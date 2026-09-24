"""Bounded text-evidence storage with durable, locked provenance records."""
import hashlib
import os
from pathlib import Path
import re
import tempfile
import time
from .errors import CecError
from .ledger import AtomicLedger

MAX_EVIDENCE_BYTES = 1024 * 1024
_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SENSITIVE_PATTERNS = [
    ("email-address", re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("card-number", re.compile(rb"\b(?:\d[ -]?){13,19}\b")),
    ("ssn-like", re.compile(rb"\b\d{3}-\d{2}-\d{4}\b")),
    ("customer-record-marker", re.compile(rb"(?i)customer_(id|name|email|address)")),
    ("credential-marker", re.compile(rb"(?i)(?:password|passwd|api[_-]?key|secret|token)\s*[:=]")),
    ("private-key-marker", re.compile(rb"BEGIN [A-Z ]*PRIVATE KEY")),
]

def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def screen_for_sensitive_data(data: bytes) -> list[str]:
    if type(data) is not bytes or len(data) > MAX_EVIDENCE_BYTES:
        raise CecError("evidence must be bytes within the 1 MiB limit")
    return [name for name, rx in _SENSITIVE_PATTERNS if rx.search(data)]

def _label(value):
    return type(value) is str and _TYPE.fullmatch(value) is not None

def _source(value):
    if type(value) is not str or not value or len(value) > 2048:
        raise CecError("source must be a nonempty bounded label")
    try:
        data = value.encode("utf-8")
    except UnicodeError:
        raise CecError("source must be valid UTF-8") from None
    if any(ord(c) < 32 for c in value) or any(c in value for c in "?@#") or screen_for_sensitive_data(data):
        raise CecError("source must not contain sensitive metadata or URI credentials/query")

class EvidenceLedger:
    """Local prototype ledger; protect its directory with OS access controls.

    Version 2 uses sequence/Merkle envelopes. Existing unframed ledgers fail
    closed and require an explicitly reviewed offline migration.
    """
    def __init__(self, root):
        self.root = os.path.realpath(root)
        self.objects = Path(self.root) / "objects"
        self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.objects.is_symlink():
            raise CecError("object directory must not be a symlink")
        self.index_path = os.path.join(self.root, "ledger.jsonl")
        if Path(self.index_path).is_symlink():
            raise CecError("ledger must not be a symlink")
        self._ledger = AtomicLedger(self.index_path)

    def _validate_record(self, rec):
        common = {"action", "evidence_type", "source", "ts"}
        action = rec.get("action")
        if not isinstance(action, str):
            raise CecError("invalid evidence action")
        extra = {
            "HARVESTED": {"digest", "bytes"},
            "REFUSED_SENSITIVE": {"reason", "detectors"},
            "REFUSED_OUT_OF_SCOPE": {"reason"},
            "REFUSED_FORMAT": {"reason"},
        }.get(action)
        if extra is None or set(rec) != common | extra or not _label(rec["evidence_type"]):
            raise CecError("invalid evidence record schema")
        _source(rec["source"])
        if type(rec["ts"]) not in (float, int) or not 0 <= rec["ts"] <= 10**12:
            raise CecError("invalid evidence timestamp")
        if action == "HARVESTED":
            if (type(rec["digest"]) is not str or not _DIGEST.fullmatch(rec["digest"])
                    or type(rec["bytes"]) is not int or not 0 <= rec["bytes"] <= MAX_EVIDENCE_BYTES):
                raise CecError("invalid evidence digest or length")
        else:
            if type(rec["reason"]) is not str or not rec["reason"]:
                raise CecError("invalid refusal reason")
            if action == "REFUSED_SENSITIVE" and (
                    type(rec["detectors"]) is not list or not rec["detectors"]
                    or not all(isinstance(v, str) and v in {n for n, _ in _SENSITIVE_PATTERNS} for v in rec["detectors"])):
                raise CecError("invalid refusal detectors")

    def harvest(self, data, *, evidence_type, source, allowed_types):
        if type(data) is not bytes or len(data) > MAX_EVIDENCE_BYTES:
            raise CecError("evidence must be bytes within the 1 MiB limit")
        if not _label(evidence_type) or type(allowed_types) not in (set, frozenset) or not all(_label(v) for v in allowed_types):
            raise CecError("invalid evidence type or allowed-type set")
        _source(source)
        rec = {"evidence_type": evidence_type, "source": source, "ts": time.time()}
        with self._ledger.transaction():
            for previous in self._ledger.entries():
                self._validate_record(previous)
            if evidence_type not in allowed_types:
                rec.update(action="REFUSED_OUT_OF_SCOPE", reason="evidence type outside caller-declared scope")
            else:
                try:
                    decoded = data.decode("utf-8")
                    if any(ord(c) < 32 and c not in "\t\r\n" for c in decoded):
                        raise ValueError("binary control")
                except (UnicodeError, ValueError):
                    rec.update(action="REFUSED_FORMAT", reason="only UTF-8 text evidence is supported")
                else:
                    hits = screen_for_sensitive_data(data)
                    if hits:
                        rec.update(action="REFUSED_SENSITIVE", detectors=hits, reason="sensitive-data pattern detected")
                    else:
                        digest = sha256(data)
                        obj = self.objects / digest[7:]
                        if obj.is_symlink():
                            raise CecError("evidence object must not be a symlink")
                        # Replace using a unique, private temporary file under the
                        # same directory; serialize all cooperating harvesters.
                        fd, tmp = tempfile.mkstemp(dir=self.objects, suffix=".tmp")
                        try:
                            with os.fdopen(fd, "wb") as fh:
                                fh.write(data)
                                fh.flush()
                                os.fsync(fh.fileno())
                            os.replace(tmp, obj)
                        finally:
                            if os.path.exists(tmp):
                                os.unlink(tmp)
                        rec.update(action="HARVESTED", digest=digest, bytes=len(data))
            self._ledger.settle(rec)
        return rec.copy()

    def entries(self):
        with self._ledger.transaction():
            records = self._ledger.entries()
            for rec in records:
                self._validate_record(rec)
                if rec["action"] == "HARVESTED":
                    obj = self.objects / rec["digest"][7:]
                    if obj.is_symlink():
                        raise CecError("evidence object must not be a symlink")
                    try:
                        with obj.open("rb") as fh:
                            data = fh.read(MAX_EVIDENCE_BYTES + 1)
                    except OSError:
                        raise CecError("evidence object is unavailable") from None
                    if len(data) != rec["bytes"] or sha256(data) != rec["digest"]:
                        raise CecError("evidence object integrity failure")
            return records
