# Third-party notices — JY-S004-P001

## amplifier-collection-recipes (GitHub Junkyard donor — reused fit)
- Donor car: `D:\desktop\GitHub Junkyard\amplifier-collection-recipes`.
- License: MIT (Microsoft Corporation); full text in
  `cec/vendor/LICENSE.amplifier-collection-recipes.txt`.
- Part: `expression_evaluator.py` vendored as `cec/vendor/condition_evaluator.py`
  — the applicability rule engine's condition evaluator. Fit first proven in
  JY-S020-P001; reused in JY-S001-P001 and here.

## Source-package material
- `schemas/execution_record.schema.json` is copied unmodified from the S004
  source carrier itself (David's own package) and used as the native
  acceptance schema for execution records.

## Host libraries
- `jsonschema` (MIT) validates execution records — build-environment dependency.

## Negative retrieval results (for the ledger)
- No compliance-evidence/policy-parser donor found in the yard (searched:
  policy engine constraint evaluation, compliance evidence) —
  `build-new: policy parser, evidence ledger, sensitive-data screen, report
  compiler (searched: policy engine, compliance evidence)`.


## September 2026 modifications
The condition evaluator now tokenizes and fully parses bounded expressions.
The internal ledger implementation is shared with the R08 maintenance release
(original project modifications, Apache 2.0); it is not transplanted donor code.
The schema is also copied unchanged to cec/schemas for installed-package loading.

Installed dependencies retain their own licenses: jsonschema and
jsonschema-specifications (MIT), attrs (MIT), referencing (MIT),
rpds-py (MIT), and typing-extensions (PSF-2.0).
