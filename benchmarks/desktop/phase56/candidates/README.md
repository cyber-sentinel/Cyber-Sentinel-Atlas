# Phase 5.6 Desktop Candidate Hosts

These hosts were created to produce executable Windows evidence for ADR-0026. Candidate comparison is now **closed**; ADR-0026 is accepted and **Tauri 2.x is the selected Windows First Preview host**.

All candidates consumed the same exact-head production `atlas-core.exe` through the frozen ADR-0025 child-process stdio protocol. Candidate code was permitted to locate and integrity-check the adjacent sidecar, perform the `atlas-core` protocol `1.0.0` handshake, call bounded methods, render returned data and collect host/IPC/packaging evidence. Candidate code was not permitted to duplicate canonical validation, search/index semantics, graph behavior, pack trust, durable state, update or rollback logic.

The evaluated host families were:

- Tauri 2.11.5;
- Electron 44.3.0;
- .NET 10 Windows Desktop / WPF.

All three passed the mandatory Phase 5.6.2 hard gates. Build success alone was not used as the selection signal; the accepted decision is documented in `docs/adr/0026-windows-desktop-host-selection.md` and the frozen evidence-based weighted review in `benchmarks/desktop/phase56/weighted-review.json`.

## Dependency reproducibility

Electron uses its committed `package-lock.json` with `npm ci`.

Tauri uses a committed `Cargo.lock`. CI:

- requires the lockfile to exist;
- verifies the approved SHA-256 before build;
- builds with `cargo build --locked` or `cargo xwin build --locked`;
- resolves evidence metadata with `cargo metadata --locked`;
- fails if the committed lockfile changes during the job;
- never regenerates dependency resolution with `cargo generate-lockfile`.

Approved Tauri `Cargo.lock` SHA-256:

```text
dd2a97c412b0f7289f07ba16cfc28b4cca02ea9b7a5f5ed4d488b34977e37b3e
```

Because the lock is byte-hash guarded, `.gitattributes` forces `benchmarks/desktop/phase56/candidates/tauri/Cargo.lock` to LF to prevent false Windows CRLF drift.

## Closed Phase 5.6.2 evidence

Exact-head Candidate Evidence run `35090304056` completed successfully and closed G-D1 through G-D9.

The evidence enforces:

- identical production Shared Core binary across candidates;
- exact core commit binding;
- `network_listener=false` and `offline_capable=true`;
- full process-tree TCP/UDP observation;
- sidecar SHA-256 identity/integrity;
- signed-pack Active Generation read model;
- verified pack update and safe rollback;
- candidate-specific Desktop security surfaces;
- relocated portable execution from paths containing spaces;
- comparable startup/IPC/process/memory/package measurements;
- canonical schema v1 drift protection.

G-D8 in Phase 5.6.2 proved **packaging/portable feasibility**. Final First Preview package construction and clean-machine consumption are separately enforced by Phase 5.6.4.

## Selected Tauri First Preview boundary

The selected Tauri host has exactly one main-window capability and seven allowlisted application commands:

- `core_status`;
- `search_records`;
- `get_record`;
- `expand_graph`;
- `pack_status`;
- `pack_update`;
- `pack_rollback`.

Security regression evidence requires CSP `connect-src 'none'`, no Tauri plugins, disabled asset protocol, no generic frontend-controlled Shared Core method bridge and no generic frontend/Rust network API.

Candidate directories remain in the repository as reproducible decision evidence and regression fixtures; they no longer represent an open framework-selection decision.
