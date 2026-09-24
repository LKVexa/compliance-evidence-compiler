# 0.1.2a1 — 2026-09-23

- Correct applicability parsing and missing-fact human-input signals.
- Bind approval references to report content; retain explicit unverified identity.
- Lock and validate framed evidence ledgers, verify objects, and limit text inputs.
- Bundle the execution schema; add 24 regression tests and tested dependencies.
- Add Apache 2.0 LICENSE/NOTICE naming RUSSELL PHILIP SMITHSON and preserve MIT.
- Breaking storage change: legacy unframed ledgers require reviewed migration.

# Changelog — Compliance Evidence Compiler & Interpreter (JY-S004-P001)

## 0.1.1-partial — 2026-09-14 (maintenance hardening, A005)

Baseline fingerprint: build-0001 product.zip
sha256:4ddd93408fda3d2f8200f06d96e4581e1ec0e717c52f5834e94979332fabca44
(13028 bytes), baseline version 0.1.0-partial, baseline suite 16/16 PASS.

All findings below were reproduced on the baseline with live probes
before fixing (probe transcripts in audit records).

- **A005-F1 (high)** `EvidenceLedger.entries()` crashed with a bare
  `json.JSONDecodeError` on a torn final ledger line (crash mid-append).
  Observed: unhandled JSONDecodeError; whole ledger unreadable.
  Expected: crash-tail recovery. Fixed: a torn FINAL line is ignored
  (recovered); a corrupt NON-final line now raises `CecError` as a
  ledger-integrity/tamper failure.
- **A005-F2 (high)** Condition-evaluator injection via string splicing:
  a scoping-fact value like `"a' == 'a' or 'b"` spliced into the rule
  text and flipped `{{env}} == 'prod'` to APPLICABLE. Fixed: variable
  values are substituted as opaque sentinel tokens resolved from a side
  table, never spliced into the expression grammar (vendored evaluator
  locally patched; provenance and license preserved).
- **A005-F3 (high)** GRD-02 attestation check used a proper-subset test
  (`set(approval) < required`), so an Approval record missing
  `approves_report_of` but carrying any extra key was accepted and the
  report gained an attestation. Fixed to require all required keys.
- **A005-F4 (medium)** `parse_policy_corpus` shallow-copied controls;
  mutating the caller's corpus after parse mutated parsed control
  records (e.g. appending a rogue evidence type). Fixed with deep copy.
- **A005-F5 (medium)** Error-contract leaks: a non-dict control entry
  raised bare `TypeError`; a non-string applicability rule raised bare
  `AttributeError` from the evaluator. Fixed: typed validation in
  `parse_policy_corpus` raises `CecError`; the evaluator raises
  `ExpressionError` for non-string conditions (judged NEEDS_EVIDENCE).
- **A005-F6 (medium)** Evidence object store: non-atomic object writes,
  and a pre-existing torn/tampered object at a digest path was silently
  kept while harvest recorded HARVESTED. Fixed: atomic temp+fsync+rename
  writes, and existing objects are digest-verified and repaired.

Tests: baseline 16 kept unchanged (none asserted the weaker behavior);
14 focused regression tests added (tests/test_hardening.py), 30/30 PASS.

Compatibility: repairs only; no public API changes; patch bump
0.1.0-partial -> 0.1.1-partial. Rollback: restore build-0001 product.zip
(sha256 above); ledgers written by 0.1.1 remain readable by 0.1.0 except
that 0.1.0 cannot recover a torn tail line.
