# Phase 5.3 Ingestion Fixtures

These fixtures are minimal, deterministic, sanitized, and architecture-focused test material for the completed Phase 5.3 ingestion control plane.

They are **not** production or redistributed Microsoft, Sysmon, MITRE, D3FEND, CAR, or DefenseOps corpora. Synthetic and realistic-synthetic examples exist only to exercise parser/normalizer behavior, native identifier preservation, provider/source scoping, legacy identity, cross-corpus lineage, inventory reconciliation, promotion controls, and later search/read-model contracts.

`foundation-valid.json` remains the positive foundation reference bundle. Negative and adversarial cases are generated in-memory where practical rather than committed as unnecessary duplicate fixtures.

Reference-export fixtures and descriptors are historical/reproducibility evidence. Current controlled production evidence, such as the promoted Sysmon 15.22 schema baseline, is kept under the governed `ingestion/` evidence/inventory paths rather than inferred from synthetic fixtures.
