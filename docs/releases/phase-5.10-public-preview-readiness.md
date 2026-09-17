# Phase 5.10 — Public Preview Readiness

Status: **ACTIVE**

Current slice: **Phase 5.10.0 — Public Preview Readiness Baseline**

First Preview engineering readiness is already **READY**. Public Preview remains **BLOCKED** until every mandatory release-readiness gate is closed with reviewable evidence.

## Purpose

Phase 5.10 converts the First Preview engineering baseline into a release process suitable for public distribution. It does not redefine the frozen Phase 5.5 Shared Core or the accepted Phase 5.6 desktop architecture.

The phase exists to close the difference between:

- an engineering-verified preview artifact;
- a publicly distributed security product;
- an environment-specific production deployment decision.

Those states are deliberately not treated as equivalent.

## Release authorities

- Current control-plane baseline: `main@d839bb366dbbd10282f6b6da70000d2fa4aaf826`
- First Preview package baseline: `main@70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- First Preview post-merge package run: `35133827422` — **SUCCESS**
- Public Preview authority: future explicit release gate; not yet granted

## Mandatory gate matrix

| Gate | Requirement | State | Current evidence / blocker |
| --- | --- | --- | --- |
| PPR-01 | First Preview engineering baseline | **PASS** | Phase 5.6 complete, merged and post-merge verified |
| PPR-02 | Security disclosure and supported-release policy | **PASS** | `SECURITY.md` |
| PPR-03 | First-party licensing decision | **BLOCKED** | No project `LICENSE`; requires explicit legal/business approval |
| PPR-04 | Third-party redistribution closure | **BLOCKED** | `THIRD_PARTY_NOTICES.md` is fail-closed; public-pack inventory not yet closed |
| PPR-05 | Production code signing and protected key custody | **BLOCKED** | First Preview is unsigned; provider/certificate/key-custody design not yet accepted |
| PPR-06 | Public packaging and distribution hardening | **BLOCKED** | Verified portable ZIP exists; signed installer/public distribution channel remains open |
| PPR-07 | Accessibility release review | **PARTIAL** | UI has accessibility/high-contrast controls; broader release review remains open |
| PPR-08 | Source freshness and public-pack publication policy | **BLOCKED** | Provenance/versioning exists; freshness SLA and public publication criteria remain open |
| PPR-09 | Release governance and launch criteria | **PARTIAL** | PR/CI/post-merge discipline exists; formal Public Preview launch/rollback authority remains open |
| PPR-10 | Supply-chain evidence | **PASS** | Reproducible build, SBOM, linked-module/license validation and vulnerability scanning |
| PPR-11 | Trademark and attribution controls | **PASS** | `TRADEMARKS.md`, `CITATION.cff`, `THIRD_PARTY_NOTICES.md` |

The machine-readable authority for this matrix is `docs/releases/phase-5.10-public-preview-readiness.json`.

## Gate semantics

- **PASS** — the defined gate is closed with inspectable evidence.
- **PARTIAL** — meaningful controls exist, but the complete Public Preview acceptance contract is not closed.
- **BLOCKED** — a mandatory release decision or control is absent; Public Preview must not be declared ready.
- **DEFERRED** — allowed only for non-mandatory work outside the Public Preview acceptance boundary.

No mandatory `BLOCKED` or `PARTIAL` gate may be re-labelled merely to obtain a release.

## CI behavior

`tools/release/validate_phase510_readiness.py` supports two modes:

- baseline mode validates schema, required policy files, evidence consistency and truthful blocker representation;
- `--release` mode fails unless every mandatory gate is `PASS` and concrete file/evidence requirements are satisfied.

Normal development CI uses baseline mode. A future Public Preview release authority must invoke strict release mode.

## Explicit decisions not made by this baseline

This baseline does **not**:

- choose an open-source or commercial first-party license;
- choose a certificate authority, signing provider, HSM/KMS or key-custody vendor;
- authorize a public installer or distribution channel;
- waive third-party redistribution review;
- convert First Preview engineering readiness into GA or universal production readiness.

Those decisions require their own accepted evidence and, where applicable, legal/business approval.

## Immediate Phase 5.10 sequence

```text
5.10.0 Readiness baseline + machine gate                 ACTIVE
        ↓
5.10.1 Licensing / redistribution closure               BLOCKED
        ↓
5.10.2 Signing / key custody / artifact attestation     BLOCKED
        ↓
5.10.3 Public packaging / distribution hardening        BLOCKED
        ↓
5.10.4 Accessibility / freshness / launch governance    PARTIAL
        ↓
Strict Public Preview readiness gate                    BLOCKED
        ↓
PUBLIC PREVIEW READY
```

The sequence may be parallelized, but `PUBLIC PREVIEW READY` requires every mandatory gate to pass.
