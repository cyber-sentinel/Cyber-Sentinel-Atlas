# Phase 5.6.1 Desktop Candidate Hosts

These hosts exist only to produce executable Windows evidence for ADR-0026. They do not select a Desktop framework by themselves.

All candidates must consume the same exact-head production `atlas-core.exe` through the frozen ADR-0025 child-process stdio protocol. Candidate code may locate and integrity-check the adjacent sidecar, perform the exact `atlas-core` protocol `1.0.0` handshake, call `core.status`, render returned data, and collect host/IPC/packaging evidence. It must not duplicate canonical validation, search/index semantics, graph behavior, pack trust, durable state, update, or rollback logic.

The executable comparison currently covers:

- Tauri 2.11.5;
- Electron 44.3.0;
- .NET 10 Windows Desktop / WPF.

Every candidate fails closed when the adjacent sidecar or its SHA-256 manifest is missing or mismatched. The CI evidence summarizer additionally requires the packaged candidates to carry an identical `atlas-core.exe`, report one exact core commit, preserve `network_listener: false` and `offline_capable: true`, and leave `schemas/v1/` unchanged.

Phase 5.6.1 does not authorize selection. G-D1 through G-D9 remain fail-closed and ADR-0026 may be accepted only after Phase 5.6.2 completes security-surface, capability, installer/portable, footprint and weighted evidence review.
