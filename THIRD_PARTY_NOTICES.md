# Third-Party Notices and Redistribution Inventory

Cyber-Sentinel-Atlas integrates or references material from multiple upstream cybersecurity sources. Each upstream source retains its own copyright, license, terms and attribution requirements. Nothing in an Atlas first-party license, when one is later adopted, will relicense third-party material beyond the rights granted by its original terms.

This file is a control inventory, not a final legal opinion. Publication of a third-party target remains fail-closed until its exact source/release and redistribution status are verified.

Phase 5.10.1 release-scoped redistribution controls are maintained in:

- [`docs/releases/third-party-redistribution-closure.md`](docs/releases/third-party-redistribution-closure.md) — human-readable closure criteria and current review boundary;
- [`docs/releases/third-party-redistribution-inventory.json`](docs/releases/third-party-redistribution-inventory.json) — machine-readable source/runtime inventory and redistribution state;
- [`tools/release/validate_redistribution_inventory.py`](tools/release/validate_redistribution_inventory.py) — fail-closed baseline and strict-release validator;
- [`tools/release/generate_public_preview_notice_bundle.py`](tools/release/generate_public_preview_notice_bundle.py) — deterministic draft/release notice metadata generator; release mode fails closed until exact PPR-04 closure and package binding;
- [`third_party/license-material/manifest.json`](third_party/license-material/manifest.json) — exact upstream-revision/blob mapping for pinned third-party license material;
- [`tools/release/validate_pinned_license_material.py`](tools/release/validate_pinned_license_material.py) — byte-identity validator and SHA-256 evidence generator for pinned license material.
- [`tools/release/generate_go_license_material_evidence.py`](tools/release/generate_go_license_material_evidence.py) and [`tools/release/validate_go_license_material_evidence.py`](tools/release/validate_go_license_material_evidence.py) — preserve and byte-validate exact license/notice material for the Go modules actually linked into the Shared Core binary plus the Go toolchain; SBOM classifier labels remain non-authoritative.

PPR-04 remains **BLOCKED** until the exact Public Preview corpus and software payload are frozen, all included entries are explicitly accepted, required notices are prepared, and the evidence is bound to the exact release package SHA-256.

## Controlled upstream families

- MITRE ATT&CK — official structured source, version/release pinned by Atlas ingestion contracts.
- MITRE D3FEND — official ontology source, version/content digest pinned by Atlas ingestion contracts.
- MITRE CAR — official structured repository source, commit/content pinned by Atlas ingestion contracts.
- Microsoft Windows Security documentation/provider metadata — source-specific documentation and controlled provider-inventory authority remain distinct.
- Microsoft Sysinternals Sysmon — official Microsoft Sysinternals documentation plus controlled schema-export evidence; Atlas does not assume redistribution rights merely because a source is public.
- Cyber-Sentinel-DefenseOps — engineering provenance only; repository-level licensing remains unresolved unless separately verified for the exact material being promoted.
- LOLBAS / GTFOBins and other future sources — redistribution review is mandatory before inclusion in a public pack.

## Publication rule

Every redistributable pack/release must be able to produce a machine-readable and human-readable source/license inventory for all included third-party targets. Unknown, incompatible, missing or ambiguous licensing is a non-waivable publication failure.

Public visibility, technical ingestibility, or citation alone does not authorize redistribution. The Public Preview pack is constructed from an explicit allowlist; unresolved material is excluded or blocks publication.
