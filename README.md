# Compliance Evidence Compiler

**0.1.2a1 — experimental partial candidate, JY-S004-P001**

A local Python library for policy applicability judgments, screened text-evidence
storage, and reports with explicit gaps and human decisions. It does not certify
compliance or authenticate human approvers.

## Install and test

Python 3.10 or newer:

~~~sh
python -m pip install -r requirements.txt
python -m pip install --no-deps .
python -m unittest discover -s tests -t .
~~~

The runtime dependency is jsonschema; requirements.txt records the tested
transitive set. CI runs on Linux Python 3.10/3.12/3.14 and Windows Python 3.12.
There are 54 tests, including 24 new security and packaging regressions.

## Example

~~~python
from cec.core import EvidenceLedger, parse_policy_corpus, judge_applicability, compile_report

controls = parse_policy_corpus({"controls": [{
    "control_id": "AC-1", "title": "Access review",
    "evidence_types": ["review-log"],
    "applicability": "{{handles_auth}} == 'true'"
}]})
judgments = judge_applicability(controls, {"handles_auth": True})
allowed = {kind for c, j in zip(controls, judgments) if j["status"] == "APPLICABLE"
           for kind in c["evidence_types"]}
ledger = EvidenceLedger("./evidence")
ledger.harvest(b"Access review procedure completed", evidence_type="review-log",
               source="ci://review/1", allowed_types=allowed)
report = compile_report(controls, judgments, ledger)
~~~

Scope is supplied by the trusted caller. Evidence labels do not prove the
underlying document satisfies a control. Missing scoping facts, missing evidence,
and unresolved decisions keep human_input_required true.

Conditions support ==, !=, and/or, quoted strings, and dotted variable references.
Boolean facts normalize to true/false. Every branch is parsed and validated.
Judgments must match the controls used to compile the report.

## Approval references

First compile without approval. After an external process authenticates a human
decision, pass its reference with record_type=Approval, role=human, a nonempty
approver, and approves_report_of equal to report_digest. This digest excludes
only generated_at, and changes when report content changes. The copied attestation
reference explicitly sets identity_verified=false: a dictionary is not proof of
human identity or authorization. The compiler makes no compliance attestation.

## Storage and limits

Only UTF-8 text up to 1 MiB is accepted. Specified email/card/SSN/customer and
credential patterns cause refusal; binary/control-byte data is also refused.
This is a limited screen, not a PII guarantee. Supply sanitized evidence only.
Source labels reject credentials, URI query/fragment data, and detected PII.

Evidence is stored by SHA-256 with private unique temporary files and fsync.
Cooperating ledger instances share a file lock. Sequence numbers and Merkle roots
are verified; reports verify referenced object bytes and digests. A malformed
unterminated final row is truncated under lock; malformed complete rows fail.
Maximum ledger size is 32 MiB / 10,000 rows. Use a protected local directory.

**Storage compatibility:** 0.1.2a1 introduces framed ledger records. Unframed
0.1.1-partial ledgers are rejected. Preserve the old directory and use a new one;
no automatic migration, archival rotation, or external checkpoint service is included.

## Scope and evidence

See [audit](docs/AUDIT.md), [test evidence](docs/CHECK_RUNS.json),
[dependency scan](docs/DEPENDENCY_AUDIT.json), and [security limits](SECURITY.md).
The schema is bundled as package data, so execution records work from the wheel.
This implements the deterministic core only; the source carrier's 200 parent
items, 1,200 nested items, live connectors, and ten human decisions remain outside
this release's completion claim.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE) and [NOTICE](NOTICE) apply to original code and
permitted modifications. The modified Microsoft condition evaluator retains MIT
terms; see [third-party notices](THIRD-PARTY-NOTICES.md).
