# Phase 5.10 — Public Preview Readiness

Status: **ACTIVE**

Current workstream: **Phase 5.10 — release-candidate decisions and evidence closure**

First Preview engineering readiness is already **READY**. Public Preview remains **BLOCKED** until every mandatory release-readiness gate is closed with reviewable evidence.

## Purpose

Phase 5.10 converts the First Preview engineering baseline into a release process suitable for public distribution. It does not redefine the frozen Phase 5.5 Shared Core or the accepted Phase 5.6 desktop architecture.

The phase exists to close the difference between:

- an engineering-verified preview artifact;
- a publicly distributed security product;
- an environment-specific production deployment decision.

Those states are deliberately not treated as equivalent.

## Release authorities

- Latest verified control-plane baseline: `main@d1efb549c1b651b58052a616bba82a3b146c0d6e` — PPR-03 through PPR-07 control planes integrated; post-merge validators green
- Usable Data Preview post-merge baseline: `main@4d64b2fb402b280d00c01783f7990538a3b67484`, run `35305516189` — **SUCCESS**
- PPR-04 Tauri/Rust preflight merged baseline: `main@734e20dbb36083d9c5770a22e9c69e844903158f`; PR #54 exact-head run `35309913398` — **SUCCESS**; artifact `10533096533` / `sha256:ead00ebd410b7a5e715f1488847c7c066ec31dbed7196c1796c221f3dc75535d`
- First Preview package baseline: `main@70afc6fdb9e5ce88afdb0dd4de139aa659606f1e`
- First Preview post-merge package run: `35133827422` — **SUCCESS**
- Public Preview authority: future explicit release gate; not yet granted

## Mandatory gate matrix

| Gate | Requirement | State | Current evidence / blocker |
| --- | --- | --- | --- |
| PPR-01 | First Preview engineering baseline | **PASS** | Phase 5.6 complete, merged and post-merge verified |
| PPR-02 | Security disclosure and supported-release policy | **PASS** | `SECURITY.md` |
| PPR-03 | First-party licensing decision | **BLOCKED** | Fail-closed license decision state/validator are integrated; no project `LICENSE` is published and explicit maintainer/legal-business approval remains required |
| PPR-04 | Third-party redistribution closure | **BLOCKED** | Exact inventory/validator plus Windows-target Rust/Tauri preflight are integrated; exact-head run `35309913398` verified 258 third-party crates and 3 frontend assets. Microsoft Learn source text is excluded and pinned ATT&CK/CAR/D3FEND/Sysmon rights are classified; final corpus/software freeze, final notices and exact package binding remain open |
| PPR-05 | Production code signing and protected key custody | **BLOCKED** | Provider-neutral non-exportable/hardware-backed signing contract and validator are integrated; provider/certificate/key custody and exact signed-candidate evidence remain unselected |
| PPR-06 | Public packaging and distribution hardening | **BLOCKED** | Packaging/distribution contract and validator are integrated; final signed format/channel and exact published-package evidence remain unselected |
| PPR-07 | Accessibility release review | **PARTIAL** | Machine-readable accessibility state and strict validator are integrated; executable Windows keyboard/Narrator/high-contrast/scaling review remains open on the exact final candidate |
| PPR-08 | Source freshness and public-pack publication policy | **PASS** | `docs/releases/source-freshness-and-publication-policy.md` |
| PPR-09 | Release governance and launch criteria | **PASS** | `docs/releases/public-preview-launch-governance.md` |
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
5.10.0 Readiness baseline + machine gate                 COMPLETE
        ↓
5.10.1 Licensing / redistribution control planes       COMPLETE — PPR-03/PPR-04 remain BLOCKED on release decisions/evidence
        ↓
5.10.2 Signing / key custody control plane              COMPLETE — PPR-05 remains BLOCKED on provider/certificate/custody
        ↓
5.10.3 Packaging / distribution control plane          COMPLETE — PPR-06 remains BLOCKED on final format/channel/evidence
        ↓
5.10.4 Accessibility / freshness / launch controls     CONTROL PLANE COMPLETE
        ├─ PPR-08 freshness/publication policy          PASS
        ├─ PPR-09 launch/rollback governance            PASS
        └─ PPR-07 packaged accessibility review         PARTIAL
        ↓
Strict Public Preview readiness gate                    BLOCKED
        ↓
PUBLIC PREVIEW READY
```

The sequence is intentionally parallelizable. Closing PPR-08 and PPR-09 does not waive PPR-03 through PPR-07. `PUBLIC PREVIEW READY` requires every mandatory gate to pass against the exact release-authority commit.
