# Public Preview Release Gates

ATLAS source is publicly inspectable, but **Public Preview binary/content publication remains fail-closed** until the mandatory release gates are satisfied.

The authoritative Public Preview gate matrix is maintained in:

- `docs/releases/phase-5.10-public-preview-readiness.md`;
- `docs/releases/phase-5.10-public-preview-readiness.json`.

This document summarizes the product/MVP progression and must not override those release authorities.

## Product Foundation

- [x] Product vision defined
- [x] Product principles defined
- [x] Primary personas defined
- [x] Competitive position defined
- [x] Canonical vendor-neutral model defined
- [x] Claim-level provenance defined
- [x] Search architecture defined
- [x] AI/RAG boundaries defined
- [x] Offline-first model defined
- [x] API/CLI direction defined
- [x] Security architecture defined
- [x] Windows-first MVP scope defined

## Architecture / Governance Foundation

- [x] Project-state authority established
- [x] Canonical identifier architecture recorded
- [x] Shared-core/interface sequencing synchronized
- [x] Universal telemetry taxonomy recorded
- [x] Coverage architecture recorded
- [x] Controlled content release pipeline recorded
- [x] Legacy/current telemetry lifecycle recorded
- [x] Canonical schema v1.0.0 implemented with exactly seven AtlasRecord families
- [x] Production Go Shared Core selected and implemented
- [x] SQLite + FTS5 deterministic search selected and implemented
- [x] TUF content-pack trust/update model implemented
- [x] Tauri 2.x selected for the Windows Desktop host

## Windows First Preview Engineering Boundary

- [x] Source registry / ingestion control plane implemented
- [x] Windows/Sysmon ingestion foundation implemented
- [x] Exact and lexical search implemented
- [x] Offline Shared Core runtime implemented
- [x] Windows Desktop MVP implemented
- [x] Verified content-pack install / trust / update / rollback path implemented
- [x] Clean-Windows package smoke accepted
- [x] Pack bootstrap gap `ATLAS_PACK_NOT_READY` closed for the engineering usable-data preview
- [x] Search → Record → Graph → Provenance clean-Windows acceptance proved for Windows Security `4688` and Sysmon `1`
- [x] Engineering pack additionally contains Windows Security `4624` and Sysmon `3`
- [x] Encyclopedia-grade content exists for Windows Security `4624`, Windows Security `4688`, Sysmon `1`, and Sysmon `3`
- [x] Controlled Sysmon `15.22` / schema `4.91` reference baseline validated and promoted

The current engineering pack is **not** the complete Windows Security Corpus.

## Mandatory Windows Security Corpus Completion

Before declaring the approved Windows corpus complete:

- [ ] provider/channel/version denominators frozen for every mandatory telemetry family (Security-Auditing and Sysmon are frozen; all other mandatory families remain open);
- [ ] Sysmon encyclopedia-grade coverage reaches the frozen 30-ID target set (current: `2/30`; `28` remaining);
- [ ] Microsoft-Windows-Security-Auditing coverage reaches the controlled 423-ID provider/build target set (current encyclopedia-grade: `2/423`; `421` remaining);
- [ ] PowerShell Operational coverage accepted;
- [ ] Windows Defender coverage accepted;
- [ ] AppLocker coverage accepted;
- [ ] WMI Activity coverage accepted;
- [ ] Task Scheduler Operational coverage accepted;
- [ ] RDP / Terminal Services coverage accepted;
- [ ] Windows Firewall / Filtering Platform coverage accepted;
- [ ] DNS Client / DNS Server coverage accepted where applicable;
- [ ] Service Control Manager / service and persistence telemetry coverage accepted;
- [ ] every in-scope identifier/state is explicit with no silent omissions;
- [ ] canonical records, provenance, index, pack and coverage snapshots are consistent;
- [ ] exhaustive lookup/negative tests pass against the exact pack.

The detailed authority is `docs/windows-sysmon-coverage-plan.md`; machine-readable family state is `content/encyclopedia/coverage-manifest.json`.

## Public Preview Mandatory Closure

Current release blockers remain separate from corpus engineering:

- [ ] first-party licensing decision (PPR-03);
- [ ] exact third-party redistribution closure (PPR-04);
- [ ] production code signing / protected key custody (PPR-05);
- [ ] exact public package/distribution evidence (PPR-06);
- [ ] packaged executable accessibility review (PPR-07).

Already established supporting controls include engineering baseline, security disclosure policy, source freshness/publication policy, release governance, supply-chain evidence and trademark/attribution controls.

## Approved Post-Windows Product Surfaces

These are approved delivery scope but are **not blockers for the first Windows Public Preview**:

- ATLAS CLI — Windows / Linux / macOS;
- ATLAS Web;
- ATLAS PWA — iOS Safari;
- ATLAS Public API;
- ATLAS Desktop — Linux / macOS;
- ATLAS Native Mobile — iOS / Android.

## Stable Public Release

A later stable/GA release requires additional release-specific evidence for:

- update reliability;
- schema/data migration;
- compatibility;
- signed releases;
- source freshness monitoring;
- security maintenance policy;
- operational supportability;
- contribution/licensing governance;
- platform-specific signing/notarization/store requirements for additional product surfaces.
