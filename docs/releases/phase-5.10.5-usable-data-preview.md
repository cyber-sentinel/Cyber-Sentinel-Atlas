# Phase 5.10.5 — Usable Data Preview

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Date: 2026-09-17

## Purpose

Phase 5.10.5 proves that the packaged Windows desktop can start from clean-machine conditions with a verified engineering knowledge pack and deliver an actually usable analyst flow rather than only UI/process liveness.

This slice is an engineering usability/evidence milestone. It does **not** grant Public Preview release authority and it does not change any mandatory PPR gate state.

## Verified exact-head authority

- Branch: `phase-5.10.5-usable-data-preview`
- Exact head: `e5f76ef8f9bc8dad83b12387a7e7b9edfc6dd8a4`
- Workflow: `Phase 5.10.5 Usable Data Preview`
- Run: `35253441607` — **SUCCESS**

Both jobs passed:

1. `build exact-head usable data preview`
2. `clean Windows first-run Search Record Graph`

## Verified post-merge authority

- Merge vehicle: PR #45 — **MERGED**
- CI resilience closure: PR #49 — **MERGED**
- Verified post-merge engineering baseline: `main@4d64b2fb402b280d00c01783f7990538a3b67484`
- Workflow: `Phase 5.10.5 Usable Data Preview`
- Run: `35305516189` — **SUCCESS**
- `build exact-head usable data preview`: **PASS**
- `clean Windows first-run Search Record Graph`: **PASS**

Post-merge artifacts:

- `phase5105-usable-data-preview`
  - artifact ID: `10530884223`
  - digest: `sha256:174009a03ca99c5df83f3ab4489319f88ab9ff02a1c94343cecd066ac8b9f435`
- `phase5105-clean-windows-evidence`
  - artifact ID: `10532105635`
  - digest: `sha256:efea2fd75a83f6300d7463217a7412c96324a5428e8eaf2ae08ac548039ee438`

The later Public Preview control-plane integration baseline `main@d1efb549c1b651b58052a616bba82a3b146c0d6e` changes release-control documentation/validators rather than the Phase 5.10.5 build-relevant product tree; all PPR control-plane, Foundation, Governance and Phase 5.3.4 canary workflows passed post-merge on that baseline.

## Acceptance evidence

The clean-Windows acceptance path verified all of the following from the packaged bytes:

- package integrity and relocation to a path containing spaces;
- every security-significant payload binding;
- selected Tauri desktop host bootstrap against the packaged Shared Core;
- a verified first-run knowledge-pack bootstrap;
- exact Windows Security Event ID `4688` retrieval;
- Sysmon Event ID `1` retrieval;
- canonical Record resolution;
- bounded Graph expansion;
- claim/source provenance availability;
- TUF target tampering rejection with fail-closed behavior.

The tamper acceptance probe intentionally modifies a signed target and requires TUF verification to reject it. The final path-safe harness confirms that the expected non-zero tamper result is treated as successful security evidence rather than as a workflow failure.

## Artifacts

- `phase5105-usable-data-preview`
  - artifact ID: `10512162655`
  - digest: `sha256:65bc9987b9673c0c711e049813b8562b978f30192799f11397cff1113d450f62`
- `phase5105-clean-windows-evidence`
  - artifact ID: `10511033598`
  - digest: `sha256:7c7569437f6139a27cee3743e1e0e426a64f03f0dc20044526165c3068bcc60e`

Artifacts are retained by GitHub Actions according to repository retention policy. The digests above are the immutable evidence identifiers for the successful exact-head run.

## Security interpretation

Phase 5.10.5 closes the previously observed usability gap where the desktop shell and IPC could be healthy while search returned `ATLAS_PACK_NOT_READY`. The verified package now proves an end-to-end analyst path with usable Windows/Sysmon knowledge and fail-closed pack tamper handling.

The following boundaries remain unchanged:

- Phase 5.5 Shared Core contracts remain frozen;
- canonical schema v1 remains unchanged;
- TUF verification, trusted-time, anti-rollback and Last Known Good behavior remain authoritative;
- no generic frontend-controlled Shared Core bridge is introduced;
- no default application network listener is introduced;
- the engineering package is not a signed Public Preview release.

## Merge and post-merge closure

The required merge and post-merge conditions are closed:

1. PR exact-head CI succeeded;
2. PR #45 merged the reviewed implementation to `main`;
3. PR #49 hardened the pinned Windows dependency download path without relaxing SHA-256 or Cargo.lock controls;
4. post-merge run `35305516189` succeeded on `main@4d64b2fb402b280d00c01783f7990538a3b67484`;
5. clean Windows acceptance again proved exact 4688/Sysmon retrieval, Record/Graph/Provenance, security-significant payload binding, and TUF tamper rejection.

Public Preview remains governed independently by `docs/releases/phase-5.10-public-preview-readiness.md` and its machine-readable manifest.
