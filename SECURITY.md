# Security boundaries

This is a local experimental library, not a compliance attestation service.
Policy controls, applicability judgments, allowed evidence types, and approval
identity come from a trusted caller. Report binding and input validation do not
authenticate that caller. The approval dictionary is an unverified reference.

Pattern screening misses obfuscated, encoded, Unicode, and many other forms of
personal or secret data. Only submit evidence already sanitized and authorized
for storage. Source labels and control text also need upstream data minimization.

The local directory must exclude untrusted writers with OS permissions/Windows
ACLs. Symlink checks are defense in depth, not protection against an attacker
who can race path changes or modify the running Python process. File locks only
coordinate cooperating processes; network filesystems are not validated.

Merkle envelopes detect accidental or partial modification, not an attacker who
can rewrite the entire ledger or remove a valid suffix. Independent authenticated
checkpoints are required to detect those events. Object deletion/tampering fails
report compilation. fsync does not imply directory metadata survived every power
loss; an orphan object after a failed ledger append is possible and is not evidence.

The new envelope format deliberately refuses legacy unframed ledgers. Back up
old directories and review any migration separately. Resource limits bound the
prototype, but large-ledger performance is not validated. Use an external process
boundary, resource quota and access controls for adversarial workloads.

Report defects privately to the repository owner using sanitized reproductions.
See docs/DEPENDENCY_AUDIT.json for the point-in-time dependency scan; zero known
advisories does not establish absence of vulnerabilities.
