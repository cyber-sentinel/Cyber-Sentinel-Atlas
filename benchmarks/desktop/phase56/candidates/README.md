# Phase 5.6 Desktop Candidate Hosts

These hosts exist to produce executable Windows evidence for ADR-0026. They do not select a Desktop framework by themselves.

All candidates must consume the same exact-head production `atlas-core.exe` through the frozen ADR-0025 child-process stdio protocol. Candidate code may locate and integrity-check the adjacent sidecar, perform the exact `atlas-core` protocol `1.0.0` handshake, call `core.status`, render returned data, and collect host/IPC/packaging evidence. It must not duplicate canonical validation, search/index semantics, graph behavior, pack trust, durable state, update, or rollback logic.

The executable comparison currently covers:

- Tauri 2.11.5;
- Electron 44.3.0;
- .NET 10 Windows Desktop / WPF.

Every candidate fails closed when the adjacent sidecar or its SHA-256 manifest is missing or mismatched. The CI evidence summarizer additionally requires the packaged candidates to carry an identical `atlas-core.exe`, report one exact core commit, preserve `network_listener: false` and `offline_capable: true`, and leave `schemas/v1/` unchanged.

## Dependency reproducibility

Electron uses its committed `package-lock.json` with `npm ci`.

Tauri now uses a committed `Cargo.lock`. Candidate CI:

- requires the lockfile to exist;
- verifies the approved SHA-256 before build;
- builds with `cargo build --locked` or `cargo xwin build --locked`;
- resolves evidence metadata with `cargo metadata --locked`;
- fails if the committed lockfile changes during the job.

The workflow must not regenerate Tauri dependency resolution with `cargo generate-lockfile`. Dependency drift is a hard failure rather than an implicit update.

## Phase 5.6.2 hard-gate evidence

G-D7 Desktop Security Surface is implemented as candidate-specific, machine-enforced policy evidence. It validates the intended security boundary for Electron, Tauri and native .NET/WPF before the candidate summary can pass.

G-D8 Installer/Portable feasibility is also implemented as executable evidence. Each staged candidate is relocated to a different directory whose path contains spaces and must successfully execute its real probe from that location while preserving the adjacent `atlas-core.exe` and SHA-256 manifest boundary. Packaging/runtime prerequisites, installer options, signing boundary and disabled binary auto-update posture are recorded as evidence.

G-D8 feasibility evidence does **not** replace real installer construction, release signing, or clean-machine installer smoke testing. Those remain Phase 5.6.4 requirements.

G-D9 remains partially open. The common external Windows harness currently captures first post-build launch, repeated measured launch/IPC timing, process-tree peak working set, process count, package size and TCP/UDP endpoint observations. Any remaining measurement closure must be completed before weighted selection.

Phase 5.6.1 completion does not authorize selection. G-D1 through G-D9 remain fail-closed, and ADR-0026 may be accepted only after Phase 5.6.2 closes every mandatory gate and completes the weighted evidence review.
