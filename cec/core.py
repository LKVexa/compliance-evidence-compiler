"""Compliance Evidence Compiler & Interpreter — deterministic core
(JY-S004-P001 partial candidate).

Implements slices of COMP-01 (policy parser), COMP-03 (applicability
rule engine), COMP-05 (evidence ledger), PAPER-CAP-01..06 and
PAPER-GRD-01..04, with source guardrails enforced structurally:

- GRD-01: evidence files are screened by a deterministic sensitive-data
  detector; a file that trips it is REFUSED into the ledger and the
  refusal recorded. Pattern screening does not detect all sensitive data.
- GRD-02: reports carry no attestation. The compiled report's
  `attestation` field is present only when a separate human Approval
  record is supplied, and it then cites that record — the compiler
  itself never attests.
- GRD-03: there is no production-change API anywhere in the package.
- GRD-04: only evidence types declared by an applicable control may be
  harvested; anything else is refused as out of scope.
- Unspecified thresholds/policies are never invented: controls that
  reference an unresolved decision produce NEEDS_DECISION naming the
  blocking DEC item.

Applicability rules use the eval()-free condition evaluator retrieved
from the amplifier-collection-recipes Junkyard donor (MIT, vendored) —
a proven chop-shop fit — over declared scoping facts, with the reasoning
recorded per judgment (PAPER-CAP-03).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time

from .vendor.condition_evaluator import ExpressionError, evaluate_condition

VERSION = "0.1.2a1"


from .errors import CecError
from .codec import canonical_bytes
from .evidence import EvidenceLedger, screen_for_sensitive_data


def sha256(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


# ------------------------- COMP-01: policy parser ------------------------
_CONTROL_FIELDS = {"control_id", "title", "evidence_types",
                   "applicability", "not_applicable_when"}


def parse_policy_corpus(corpus: dict) -> list[dict]:
    """Parse a policy set (JSON object with a 'controls' list) into
    control records with evidence types and applicability rules.
    Unknown/missing fields are errors, never guesses."""
    if not isinstance(corpus, dict) or set(corpus) != {"controls"}:
        raise CecError("policy corpus must be an object with a 'controls' list")
    if not isinstance(corpus["controls"], list):
        raise CecError("policy corpus 'controls' must be a list")
    if len(corpus["controls"]) > 1000:
        raise CecError("too many controls")
    controls = []
    seen = set()
    for i, raw in enumerate(corpus["controls"]):
        if not isinstance(raw, dict):
            raise CecError(f"controls[{i}] must be an object, got {type(raw).__name__}")
        if not all(isinstance(key, str) for key in raw):
            raise CecError("control field names must be strings")
        missing = {"control_id", "title", "evidence_types", "applicability"} - set(raw)
        if missing:
            raise CecError(f"controls[{i}] missing fields: {sorted(missing)}")
        unknown = set(raw) - _CONTROL_FIELDS - {"needs_decision"}
        if unknown:
            raise CecError(f"controls[{i}] unknown fields: {sorted(unknown)}")
        if not isinstance(raw["evidence_types"], list) or not raw["evidence_types"] \
                or not all(isinstance(t, str) for t in raw["evidence_types"]):
            raise CecError(f"controls[{i}] evidence_types must be a non-empty list of strings")
        for k in ("control_id", "title", "applicability"):
            if not isinstance(raw[k], str) or not raw[k].strip() or len(raw[k]) > 4096:
                raise CecError(f"controls[{i}] {k} must be a nonempty bounded string")
        if raw["control_id"] in seen:
            raise CecError("duplicate control identifier")
        seen.add(raw["control_id"])
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", et) for et in raw["evidence_types"]) or len(set(raw["evidence_types"])) != len(raw["evidence_types"]):
            raise CecError("invalid or duplicate evidence type")
        if "needs_decision" in raw and (not isinstance(raw["needs_decision"], str) or not raw["needs_decision"].strip() or len(raw["needs_decision"]) > 4096):
            raise CecError("needs_decision must be a nonempty bounded string")
        if "not_applicable_when" in raw and (not isinstance(raw["not_applicable_when"], str) or not raw["not_applicable_when"].strip() or len(raw["not_applicable_when"]) > 4096):
            raise CecError(f"controls[{i}] not_applicable_when must be a string")
        try:
            canonical_bytes(raw)
        except (ValueError, UnicodeError, TypeError):
            raise CecError("policy must contain valid JSON/Unicode") from None
        # F4: deep copy so later mutation of the caller's corpus cannot
        # alias into parsed control records.
        controls.append(copy.deepcopy(raw))
    return controls


# ------------------- COMP-03: applicability rule engine ------------------
def judge_applicability(controls: list[dict], scoping_facts: dict) -> list[dict]:
    """PAPER-CAP-02/03: judge each control against minimal scoping facts,
    recording the rule, the facts consulted, and the reasoning."""
    if not isinstance(scoping_facts, dict) or not all(isinstance(k, str) for k in scoping_facts):
        raise CecError("scoping facts must be a JSON object")
    try:
        if len(canonical_bytes(scoping_facts)) > 1024 * 1024:
            raise CecError("scoping facts exceed size limit")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise CecError("invalid or oversized scoping facts") from None
    if not isinstance(controls, list) or len(controls) > 1000:
        raise CecError("controls must be a bounded list")
    judgments = []
    for c in controls:
        if not isinstance(c, dict) or not {"control_id", "applicability"} <= set(c):
            raise CecError("invalid control record")
        rule = c["applicability"]
        try:
            applicable = evaluate_condition(rule, scoping_facts)
            reason = f"rule {rule!r} evaluated {applicable} against declared scoping facts"
            status = "APPLICABLE" if applicable else "NOT_APPLICABLE"
            excl = c.get("not_applicable_when")
            if applicable and excl:
                excluded = evaluate_condition(excl, scoping_facts)
                if excluded:
                    status, applicable = "NOT_APPLICABLE", False
                    reason += f"; exclusion {excl!r} evaluated True"
        except ExpressionError as exc:
            status = "NEEDS_EVIDENCE"
            reason = f"scoping fact missing or rule invalid: {exc}"
        judgments.append({
            "control_id": c["control_id"],
            "status": status,
            "rule": rule,
            "facts_consulted": sorted(set(re.findall(r"\{\{(\w+(?:\.\w+)*)\}\}",
                str(rule) + " " + str(c.get("not_applicable_when", ""))))),
            "reasoning": reason,
            "control_digest": sha256(canonical_bytes(c)),
        })
    return judgments


# ------------------- PAPER-CAP-05: report compilation ---------------------
def compile_report(controls, judgments, ledger: EvidenceLedger,
                   human_approval: dict | None = None) -> dict:
    """Compile the per-control compliance report: evidence references,
    timestamps, explicit gaps, NEEDS_DECISION blockers; attestation only
    via a supplied human Approval record (GRD-02)."""
    controls = parse_policy_corpus({"controls": controls})
    if not isinstance(judgments, list) or len(judgments) != len(controls):
        raise CecError("one applicability judgment is required per control")
    jmap = {}
    for judgment in judgments:
        if not isinstance(judgment, dict) or not {"control_id", "status", "reasoning", "control_digest"} <= set(judgment):
            raise CecError("invalid judgment")
        ident = judgment["control_id"]
        if not isinstance(ident, str) or ident in jmap:
            raise CecError("invalid or duplicate judgment identifier")
        if judgment["status"] not in ("APPLICABLE", "NOT_APPLICABLE", "NEEDS_EVIDENCE") or not isinstance(judgment["reasoning"], str):
            raise CecError("invalid judgment status or reasoning")
        jmap[ident] = judgment
    for control in controls:
        judgment = jmap.get(control["control_id"])
        if judgment is None or judgment["control_digest"] != sha256(canonical_bytes(control)):
            raise CecError("judgment does not match the current control")
    harvested = [e for e in ledger.entries() if e["action"] == "HARVESTED"]
    by_type = {}
    for e in harvested:
        by_type.setdefault(e["evidence_type"], []).append(e)
    rows, gaps, needs_decision = [], [], []
    for c in controls:
        j = jmap[c["control_id"]]
        row = {"control_id": c["control_id"], "title": c["title"],
               "applicability": j["status"], "reasoning": j["reasoning"],
               "evidence": [], "gaps": []}
        if c.get("needs_decision"):
            row["status"] = "NEEDS_DECISION"
            row["blocking_decision"] = c["needs_decision"]
            needs_decision.append(c["control_id"])
        elif j["status"] == "APPLICABLE":
            for et in c["evidence_types"]:
                found = by_type.get(et, [])
                if found:
                    row["evidence"] += [{"evidence_type": et, "digest": e["digest"],
                                         "source": e["source"], "ts": e["ts"]}
                                        for e in found]
                else:
                    row["gaps"].append(et)
                    gaps.append({"control_id": c["control_id"], "missing": et})
            row["status"] = ("NEEDS_EVIDENCE" if row["gaps"] else "EVIDENCE_COMPILED")
        else:
            row["status"] = j["status"]
        rows.append(row)
    report = {
        "schema": "cec/report/v1", "compiler_version": VERSION,
        "generated_at": time.time(),
        "controls": rows, "gaps": gaps, "needs_decision": needs_decision,
        "human_input_required": bool(gaps or needs_decision or
                                    any(r["status"] == "NEEDS_EVIDENCE" for r in rows)),
        "provenance_note": "deterministic compilation only; no model inference",
    }
    digest_body = {k: v for k, v in report.items() if k != "generated_at"}
    report["report_digest"] = sha256(canonical_bytes(digest_body))
    if human_approval is not None:
        required = {"record_type", "role", "approves_report_of", "approver"}
        if not isinstance(human_approval, dict) \
                or human_approval.get("record_type") != "Approval" \
                or human_approval.get("role") != "human" \
                or set(human_approval) != required \
                or not isinstance(human_approval.get("approver"), str) \
                or not human_approval["approver"].strip() \
                or len(human_approval["approver"]) > 256 \
                or human_approval.get("approves_report_of") != report["report_digest"]:
            raise CecError("GRD-02: attestation requires a well-formed human Approval record")
        try:
            canonical_bytes(human_approval)
        except (ValueError, UnicodeError, TypeError):
            raise CecError("invalid approval data") from None
        report["attestation"] = {"by_human_approval": copy.deepcopy(human_approval),
                                 "identity_verified": False,
                                 "note": "caller-supplied approval reference only; human identity must be verified externally"}
    return report
