# Cyber-Sentinel ATLAS Documentation Hub

This directory is the human-readable documentation surface for Cyber-Sentinel ATLAS.

ATLAS is the **KNOW** layer of the Cyber-Sentinel ecosystem: a provenance-first, offline-first cyber-defense knowledge and investigation platform built around deterministic retrieval, canonical records, claim-level evidence, verified content packs, and bounded product interfaces.

## Current reviewed snapshot

- First Preview engineering readiness: **READY**
- Windows Desktop: **release-critical surface**
- Public Preview: **BLOCKED / fail-closed**
- Phase 5.10.10: **ACTIVE / CONTROLLED COVERAGE EXPANSION**
- Windows Security Log UWS benchmark: **26/422 encyclopedia-grade listed identities**, `396` remaining
- Windows Security Auditing: **20/423 encyclopedia-grade**, `403` remaining
- Current Windows Security exemplars: `4608`, `4609`, `4610`, `4611`, `4612`, `4614`, `4615`, `4616`, `4618`, `4621`, `4622`, `4624`, `4625`, `4648`, `4672`, `4688`, `4740`, `4768`, `4769`, `4771`
- Sysmon 15.22: **30/30 COMPLETE**
- Global Windows denominator: **NOT FROZEN**

The machine-readable coverage authority is `../content/encyclopedia/coverage-manifest.json`. Fresh GitHub `main` state supersedes any point-in-time prose snapshot.

## Start here

| Topic | Document |
| --- | --- |
| Current authoritative snapshot | [Current Status](current-status.md) |
| Durable project state | [Project State](project-state.md) |
| Delivery sequence and active phases | [Roadmap](roadmap.md) |
| Product family and surface dependencies | [Product Surfaces](product-surfaces.md) |
| Windows / Sysmon corpus program | [Windows & Sysmon Coverage Plan](windows-sysmon-coverage-plan.md) |
| Public Preview readiness | [Phase 5.10 Public Preview Readiness](releases/phase-5.10-public-preview-readiness.md) |
| RC functional freeze | [Public Preview RC Contract](releases/public-preview-rc-contract.md) |
| Telemetry content-depth contract | [Telemetry Record Content Contract](content/telemetry-record-content-contract.md) |
| Analyst workspace / UX | [UX Documentation](ux/) |
| Architecture decisions | [ADR Index](adr/) |
| Operational procedures | [Operations](operations/) |
| Governance | [Governance](governance/) |

## Architecture authority

The accepted production path is:

```text
Authoritative Sources
        ↓
Acquisition + Raw Snapshots
        ↓
Parsing + Normalization + Lineage
        ↓
Validation + Human Review
        ↓
Canonical AtlasRecord Model
        ↓
Deterministic Search (SQLite + FTS5)
        ↓
Verified Content Packs (.atlaspack + TUF)
        ↓
Production Shared Core (Go / atlas-core)
        ↓
Versioned Local Protocol (bounded stdio)
        ↓
Windows Desktop
```

The canonical schema contract remains `1.0.0`. Search is exact-before-lexical. Content-pack trust, anti-rollback and Last Known Good behavior remain fail-closed. Windows Desktop uses Tauri 2.x and consumes the production Shared Core over the frozen bounded child-process stdio protocol.

## Coverage rules

A telemetry identifier counts as covered only after it reaches the maintained `ENCYCLOPEDIA_GRADE` contract and passes applicable source, semantics, provenance, deterministic search, pack and acceptance checks.

A parser, provider inventory entry, source profile, fixture, UI mention, or source URL by itself is **not** counted as completed product coverage.

ATLAS intentionally does not publish an unqualified “all Windows Event IDs” completion percentage while mandatory Windows families outside the frozen Security-Auditing/Sysmon scopes do not yet have controlled denominators.

## Release-state rules

Engineering readiness, corpus depth and public-release authority are separate states.

A green CI workflow can validate that a fail-closed release gate is behaving correctly; it does not automatically mean Public Preview is authorized. Licensing, redistribution, signing, packaging, accessibility and exact-candidate evidence remain independently governed.

## Documentation maintenance

Human-readable documents are projections of repository-backed control-plane state. When a prose counter, SHA or release statement disagrees with a machine-readable ledger or fresh GitHub state, the repository evidence is authoritative and the prose must be corrected rather than the gate weakened.
