# Phase 5.6 — Windows Desktop First Preview Release Closure

Status: **FIRST PREVIEW READY / POST-MERGE VERIFIED**

Closure date: 2026-09-16

## Release authority

- Repository: `cyber-sentinel/Cyber-Sentinel-Atlas`
- Release authority: `main`
- PR: `#39` — merged
- PR head: `bae4b2d87b5c227f6e332ffc3ca166d37b3fe4cd`
- Authoritative merge commit: `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- Desktop host: Tauri 2.x — ADR-0026 Accepted
- Shared Core: Go, `atlas-core/1.0.0`
- Packaging: unsigned portable Windows x64 ZIP

## Closure evidence

Phase 5.6.0 through 5.6.4 are complete. PR #39 merged to `main` and the post-merge `Phase 5.6.4 Windows First Preview Package` workflow completed successfully on the authoritative merge commit.

Post-merge package workflow:

- run: `35133827422`
- head: `70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- conclusion: `success`
- package artifact: `phase564-first-preview-package`
- clean-Windows evidence artifact: `phase564-clean-windows-evidence`

The post-merge package contains the Tauri desktop host, adjacent SHA-256-bound `atlas-core.exe`, package manifest, and First Preview instructions. Clean-Windows verification preserves the offline-first/no-default-listener security boundary and fail-closed sidecar integrity behavior.

## First Preview boundary

The First Preview provides:

- Offline Global Search;
- Canonical Record / Entity Detail;
- bounded relationship and graph navigation;
- claim/source provenance;
- Windows Event / Sysmon investigation context present in the active pack;
- verified pack status, update and safe rollback;
- diagnostics and recovery visibility;
- UTC, system-local and Tehran/Jalali presentation;
- operational dark UI with accessibility/high-contrast controls.

The selected host exposes only the seven explicit application commands defined by the Phase 5.6 contract. CSP `connect-src 'none'`, no generic application network API, no generic frontend-controlled Shared Core method bridge, and no Tauri plugin expansion remain enforced boundaries.

## Deferred release-readiness work

First Preview readiness is not Public Preview readiness. Production Authenticode signing, installer/distribution hardening, third-party licensing/redistribution closure, broader accessibility review, contributor/release workflow hardening, source freshness policy and launch criteria remain Phase 5.10 work. Binary auto-update is not part of this First Preview.

## Governance

Future product work branches from the authoritative `main` baseline. Frozen Phase 5.5 contracts and accepted ADRs remain release constraints. No security or architecture gate is weakened by this closure record.
