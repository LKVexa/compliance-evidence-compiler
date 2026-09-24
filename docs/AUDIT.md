# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S004-P001 / 0.1.1-partial / run-0001 / product.
All implementation modules, donor evaluator, schema, and inherited tests were
reviewed. The source directory remains unchanged.

## Repaired findings

- Boolean scoping facts could evade string-based applicability, quoted operators
  were split incorrectly, and short-circuiting skipped malformed expression
  tails. Reused the bounded token parser repaired in R08, retaining MIT notices.
- Duplicate/empty controls and invalid decision fields made reports ambiguous.
  The parser validates identifiers/types, and reports require exactly matching
  judgments bound to their current controls.
- Missing scoping facts produced NEEDS_EVIDENCE while human_input_required could
  be false. The stop signal now includes unresolved applicability.
- Approval references accepted unrelated targets/empty approvers and aliased the
  caller dictionary. References now bind to a stable report digest, are copied,
  and explicitly state that human identity has not been authenticated.
- The ledger silently ignored a malformed complete final row and could append
  into a torn row; concurrent writers shared a fixed temporary filename.
  Locked, sequenced Merkle envelopes, strict recovery, and unique temporary files
  now protect cooperating writers. Complete malformed records fail closed.
- Reports trusted ledger metadata without checking evidence objects. Missing,
  altered, or mismatched objects now prevent compilation.
- Arbitrary binary/oversized inputs and sensitive source metadata were accepted.
  Bounded UTF-8 evidence and source validation now narrow this surface; credential
  markers were added. Documentation removes the unsupported universal PII guarantee.
- Schema lookup assumed a source checkout; packaged schema resources now work
  from installed wheels. Execution records detach caller-owned lists.

## Release and verification

Version 0.1.1-partial -> 0.1.2a1. New ledger envelopes require a fresh evidence
directory or separately reviewed migration. The package remains experimental.
30 inherited tests passed before changes; 54 tests pass after hardening, including
24 additional security, concurrency, storage, approval, and packaging regressions.
Source and installed-wheel results are in CHECK_RUNS.json. Historical results are
retained in BASELINE_CHECK_RUNS.json. CI verifies four Linux/Windows/Python jobs.

jsonschema 4.26.0 was verified against its authoritative PyPI release page:
https://pypi.org/project/jsonschema/ . requirements.txt pins the tested transitive
set. pip-audit 2.10.1 scans that installed set; see DEPENDENCY_AUDIT.json.
Initial remote CI caught rpds-py 2026.6.3 requiring Python >=3.11. Requirements
now select rpds-py 0.30.0 for Python 3.10; that version's scan is recorded in
DEPENDENCY_AUDIT_PY310.json. The corrected matrix is rerun before publication.
This scan addresses known dependency advisories, not application correctness.

Apache 2.0 LICENSE, NOTICE, README, pinned-action CI, and dependency update
configuration were added. Microsoft MIT attribution and the original source schema
are preserved. This is a focused audit, not certification or a full roadmap build.
