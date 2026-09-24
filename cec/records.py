"""Execution records conforming to the source package's own
schemas/execution_record.schema.json (validated with jsonschema)."""

from __future__ import annotations

import json
import copy
from importlib.resources import files
import time

import jsonschema

def load_schema() -> dict:
    return json.loads(files("cec").joinpath("schemas/execution_record.schema.json").read_text(encoding="utf-8"))


def make_execution_record(item_id: str, status: str, *, work: list,
                          artifacts: list, verification: list,
                          evidence: list, guardrail_checks: list,
                          blockers: list, parent_id: str | None = None) -> dict:
    rec = {
        "item_id": item_id, "parent_id": parent_id, "status": status,
        "scope_authority": {
            "granted_by": "JY Batch Product Factory v2.0.0 job JY-S004-P001",
            "scope": "partial-candidate build slice; no production access",
        },
        "work_performed": work, "artifacts": artifacts,
        "verification": verification, "evidence": evidence,
        "guardrail_checks": guardrail_checks, "blockers": blockers,
        "recorded_at": time.time(),
    }
    jsonschema.validate(rec, load_schema())
    # Ensure valid JSON as well as the source schema, and detach caller lists.
    json.dumps(rec, allow_nan=False).encode("utf-8")
    return copy.deepcopy(rec)
