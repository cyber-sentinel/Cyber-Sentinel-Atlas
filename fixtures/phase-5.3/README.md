# Phase 5.3.1 Fixtures

These fixtures are minimal, deterministic, sanitized, and architecture-focused.

They do not contain production Microsoft, Sysmon, MITRE, D3FEND, CAR, or DefenseOps corpora. The synthetic `4688` and `592` examples exist only to test native identifier preservation, provider/source scoping, legacy identity, cross-corpus lineage, and future search-readiness contracts.

`foundation-valid.json` is the positive reference bundle used by the permanent Phase 5.3.1 validator and tests. Negative/security cases are derived in-memory by the test suite rather than committed as duplicate fixture files.
