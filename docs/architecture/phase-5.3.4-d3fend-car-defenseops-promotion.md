# Phase 5.3.4 — D3FEND, CAR, DefenseOps and Final Promotion

Status: **IMPLEMENTATION IN PROGRESS**

Phase 5.3.4 closes the Source & Ingestion Core by proving three remaining source classes and the final immutable validation/review/promotion semantics. It does not implement the signed content-pack runtime.

## Source authority and pins

### MITRE D3FEND

D3FEND is a Tier-A authoritative defensive-knowledge source. Atlas treats the public D3FEND API as discovery/change-monitoring only because MITRE labels it alpha. Production ingestion must consume an immutable/version-bound ontology representation and fail closed on unexpected version, digest, or structure changes.

Initial pinned release baseline:

- D3FEND ontology version: `1.6.0`
- official release date: `2026-08-31`
- official `d3fend.ttl` SHA-256: `4909a5bb66b75d2c359624398848936fb56a6b246bcd5cfcd277977a1277753a`
- official ontology repository: `d3fend/d3fend-ontology`
- release merge commit inspected for the baseline: `6f888567acb359328ebd1e793b7e01581b6a03ed`
- official distribution URL: `https://d3fend.mitre.org/ontologies/d3fend.ttl`
- official version endpoint: `https://d3fend.mitre.org/version/`

The website version endpoint and ontology digest are release assertions. A floating ontology URL is never trusted without validating the pinned release version and digest first.

D3FEND Terms of Use permit research, development, and commercial use subject to preserving MITRE copyright designation and the D3FEND license in copies. Atlas preserves source/license provenance and does not silently strip attribution.

### MITRE CAR

CAR is a Tier-A authoritative analytic knowledge source. The structured source of record for this slice is the official `mitre-attack/car` GitHub repository, not rendered website prose.

Initial pin:

- repository: `mitre-attack/car`
- branch used for discovery: `master`
- pinned commit: `1b922fe1527d956e222a99473472e594f10f610b`
- structured content root: `analytics/`
- license: Apache License 2.0

Production acquisition uses commit-pinned raw YAML paths. Floating `master` is discovery-only. Git submodules, hooks, credential helpers, and source execution remain disabled.

### Cyber-Sentinel-DefenseOps

DefenseOps is a Tier-B primary engineering source, not an authoritative external truth source.

Initial source baseline:

- repository: `cyber-sentinel/Cyber-Sentinel-DefenseOps`
- pinned main commit: `daa879b5eede5f09651468c16ed3acc50596b2fc`
- stable release represented at that commit: `v0.1.0`

Atlas does not scrape arbitrary repository files into canonical knowledge. DefenseOps must expose or be transformed into an explicit validated export contract. The export binds at least:

- repository and commit SHA;
- content ID and content type;
- native backend / format;
- source/provenance references;
- validation and review state;
- applicability;
- telemetry requirements;
- license metadata.

A DefenseOps record may become a validated detection/hunt/engineering artifact only after Atlas ingestion validation and review. `source_class=tier-b-primary-engineering` never auto-promotes claims to `authoritative`.

## Deterministic transformation boundary

```text
Pinned Source
    ↓
RawSnapshot
    ↓
Parser → Parsed Source Representation (PSR)
    ↓
Normalizer + Mapping Profile
    ↓
Immutable Canonical Candidate Build
    ↓
Inventory / Diff
    ↓
G1–G15 Validation
    ↓
Human Review Decision
    ↓
PACK_READY Promotion Record / Manifest
```

Parsers and normalizers are deterministic, network-disabled and AI-disabled. Source content is never executed.

## D3FEND drift policy

D3FEND acquisition is fail closed if any of the following occurs without an explicit source-profile update and review:

- ontology version changes;
- pinned ontology digest changes;
- required namespace/prefix or core structural markers disappear;
- a selected defensive-technique identity becomes ambiguous;
- a native D3FEND identifier changes identity semantics;
- source/version metadata and acquired content disagree.

Absence from a newer D3FEND release does not automatically delete an existing Atlas entity or relationship.

## CAR parsing policy

CAR YAML parser output is source-native PSR. It preserves at minimum:

- CAR analytic ID;
- title;
- submission/update metadata when present;
- platforms/information domain/subtypes;
- ATT&CK coverage references;
- implementation type and data-model references;
- D3FEND mappings when explicitly present;
- unknown structured keys for drift review.

The parser does not reinterpret vendor query syntax and does not convert detections between backends. Detection IR remains outside Phase 5.3.

## DefenseOps export policy

The DefenseOps interface is an explicit export contract, not filesystem coupling. Exported content must be independently attributable to a specific DefenseOps commit. Atlas rejects exports with missing source references, missing validation state, undeclared backend/format, ambiguous content identity, or absent license metadata.

DefenseOps provenance can support engineering claims, but authoritative external facts must remain backed by their own appropriate sources.

## Final promotion gates

The existing G1–G15 gate model remains authoritative:

- G1 Acquisition
- G2 Security/Integrity
- G3 Parser
- G4 Source Structure
- G5 Normalization
- G6 Canonical Schema
- G7 Registry
- G8 Referential Integrity
- G9 Provenance
- G10 Semantic Invariants
- G11 Inventory/Completeness
- G12 Determinism/Replay
- G13 Regression
- G14 License/Redistribution
- G15 Human Review

All gates remain mandatory. A fixture may demonstrate the successful state machine with opaque synthetic reviewer references, but it must be explicitly marked fixture-only and must never be represented as a production content release or real organizational approval.

`PACK_READY` means only that a reviewed immutable build has passed the Phase 5.3 promotion contract. It does **not** mean signed, released, distributed, installed, or activated.

FAILED / QUARANTINED / REJECTED paths preserve Last Known Good and cannot be publication eligible.

## Phase boundary

Phase 5.3.4 must not:

- modify the seven-family canonical `schemas/v1` model unless a separately approved architecture issue requires it;
- implement Detection IR;
- implement deterministic search/indexing (Phase 5.4);
- implement signed pack format, key management, atomic installation or runtime rollback (Phase 5.5);
- treat D3FEND inferred mappings, CAR analytics, or DefenseOps engineering content as globally authoritative merely because of source origin.

Successful completion of this slice allows Phase 5.3 itself to be declared complete and opens the Architecture Gate for Phase 5.4.
