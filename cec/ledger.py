"""Local, locked Merkle ledger; protect its directory from untrusted writers."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
import threading
from .codec import canonical_bytes
from .errors import CecError


class LedgerIntegrityError(CecError):
    pass


def _root(leaves):
    level = list(leaves)
    if not level:
        return hashlib.sha256(b"").digest()
    while len(level) > 1:
        level = [hashlib.sha256(level[i]+level[i+1]).digest()
                 for i in range(0,len(level)-1,2)] + (level[-1:] if len(level)%2 else [])
    return level[0]


def _strict_loads(data):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key]=value
        return result
    def invalid(value):
        raise ValueError("non-finite JSON number")
    return json.loads(data,object_pairs_hook=pairs,parse_constant=invalid)


@contextmanager
def _file_lock(path):
    with open(path,"a+b") as fh:
        fh.seek(0,os.SEEK_END)
        if fh.tell()==0:
            fh.write(b"0")
            fh.flush()
        fh.seek(0)
        if os.name=="nt":
            import msvcrt
            msvcrt.locking(fh.fileno(),msvcrt.LK_LOCK,1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(),fcntl.LOCK_EX)
        try:
            yield
        finally:
            fh.seek(0)
            if os.name=="nt":
                msvcrt.locking(fh.fileno(),msvcrt.LK_UNLCK,1)
            else:
                fcntl.flock(fh.fileno(),fcntl.LOCK_UN)


class AtomicLedger:
    def __init__(self,path):
        self.path=os.path.realpath(path)
        os.makedirs(os.path.dirname(os.path.abspath(path)),mode=0o700,exist_ok=True)
        self._lock=threading.RLock()
        self._local=threading.local()
        self._records,self._leaves=[],[]
        with self.transaction():
            pass

    @contextmanager
    def transaction(self):
        with self._lock:
            if getattr(self._local,"active",False):
                yield
                return
            with _file_lock(self.path+".lock"):
                self._local.active=True
                try:
                    self._reload()
                    yield
                finally:
                    self._local.active=False

    def _reload(self):
        if not os.path.exists(self.path):
            self._records,self._leaves=[],[]
            return
        with open(self.path,"rb") as fh:
            data=fh.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise LedgerIntegrityError("ledger exceeds the 32 MiB limit")
        records,leaves=[],[]
        offset,truncate_at=0,None
        lines=data.splitlines(keepends=True)
        if len(lines) > 10000:
            raise LedgerIntegrityError("ledger exceeds the 10000-row limit")
        for i,line in enumerate(lines):
            try:
                rec=_strict_loads(line)
            except json.JSONDecodeError as exc:
                if i==len(lines)-1 and not line.endswith(b"\n"):
                    truncate_at=offset
                    break
                raise LedgerIntegrityError("malformed complete ledger row") from exc
            except (ValueError,UnicodeError,RecursionError) as exc:
                raise LedgerIntegrityError("ambiguous ledger JSON") from exc
            try:
                if not isinstance(rec,dict) or set(rec)!={"entry","seq","merkle_root"}:
                    raise LedgerIntegrityError("invalid ledger row fields")
                if not isinstance(rec["entry"],dict) or type(rec["seq"]) is not int or rec["seq"]!=len(leaves)+1:
                    raise LedgerIntegrityError("invalid ledger entry or sequence")
                leaves.append(hashlib.sha256(canonical_bytes(rec["entry"])).digest())
                if rec["merkle_root"]!=_root(leaves).hex():
                    raise LedgerIntegrityError("ledger Merkle root mismatch")
            except (ValueError,TypeError) as exc:
                raise LedgerIntegrityError("invalid ledger content") from exc
            records.append(rec)
            offset+=len(line)
        if truncate_at is not None or (data and not data.endswith(b"\n")):
            with open(self.path,"r+b") as fh:
                if truncate_at is not None:
                    fh.truncate(truncate_at)
                else:
                    fh.seek(0,os.SEEK_END)
                    fh.write(b"\n")
                fh.flush()
                os.fsync(fh.fileno())
        self._records,self._leaves=records,leaves

    def settle(self,entry):
        entry=_strict_loads(canonical_bytes(entry))
        if not isinstance(entry,dict):
            raise ValueError("ledger entries must be objects")
        with self.transaction():
            if len(self._records) >= 10000:
                raise LedgerIntegrityError("ledger exceeds the 10000-row limit")
            leaves=self._leaves+[hashlib.sha256(canonical_bytes(entry)).digest()]
            rec={"entry":entry,"seq":len(leaves),"merkle_root":_root(leaves).hex()}
            encoded=canonical_bytes(rec)+b"\n"
            with open(self.path,"a+b") as fh:
                fh.seek(0,os.SEEK_END)
                start=fh.tell()
                if start+len(encoded)>32*1024*1024:
                    raise LedgerIntegrityError("ledger exceeds the 32 MiB limit")
                try:
                    fh.write(encoded)
                    fh.flush()
                    os.fsync(fh.fileno())
                except OSError:
                    fh.seek(start)
                    fh.truncate()
                    fh.flush()
                    raise
            self._records.append(rec)
            self._leaves=leaves
            return copy.deepcopy(rec)

    def entries(self):
        with self.transaction():
            return [copy.deepcopy(r["entry"]) for r in self._records]

    def verify(self):
        try:
            with self.transaction():
                pass
            return True
        except LedgerIntegrityError:
            return False
