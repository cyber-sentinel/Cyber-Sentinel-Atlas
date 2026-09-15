# Phase 5.6 — Windows Desktop Technology Spike

**Status:** EXECUTION STARTED — 5.6.0 bootstrap
**Baseline:** `main@00a27df6b28b034fecc3905865e0aac200e5aa87`
**Decision target:** ADR-0026

## Purpose

Phase 5.6 converts the accepted offline Shared Core into the first full end-user Windows interface. The Desktop host must consume `atlas-core --serve-stdio`; it must not reimplement canonical validation, deterministic search, graph traversal, provenance, pack trust, update, activation, or rollback semantics.

This spike selects the Desktop host through executable evidence rather than preference.

## Screening candidates

The initial executable screening set is:

- **Tauri 2.x** — lightweight system-webview host with a Rust native shell;
- **Electron** — bundled Chromium/Node desktop host;
- **.NET 10 LTS Windows Desktop** — native Windows host family.

Version pins in `benchmarks/desktop/phase56/evaluation-plan.json` are screening baselines only. They do not constitute technology selection.

## Frozen Shared Core boundary

ADR-0025 remains authoritative:

```text
Windows Desktop host
        |
        | spawn
        v
atlas-core --serve-stdio
        |
        +-- 4-byte big-endian frame length
        +-- UTF-8 JSON
        +-- core.handshake first
        +-- one request at a time in protocol v1
```

The Desktop host must not:

- expose a local HTTP/TCP/WebSocket listener by default;
- pass arbitrary commands, SQL, FTS syntax, or filesystem operations through the protocol;
- bypass TUF verification or durable pack state;
- write human logs to the protocol stdout stream;
- treat UI state as canonical truth.

## Hard gates

A candidate is eligible only if it passes all gates:

1. **G-D1 Windows clean build** — reproducible build instructions on the self-hosted Windows runner.
2. **G-D2 Core IPC** — launch `atlas-core`, complete the exact v1 handshake, and call `core.status`.
3. **G-D3 Offline boundary** — no mandatory Internet dependency and no default listening network endpoint.
4. **G-D4 Sidecar control** — deterministic sidecar discovery plus executable integrity/version checks before use.
5. **G-D5 Read capability** — feasible implementation of search, record detail, graph navigation, and provenance without duplicating core logic.
6. **G-D6 Pack UX capability** — feasible verified pack state/update/rollback surfaces while mutation authority remains in the Shared Core.
7. **G-D7 Security surface** — least-privilege host APIs, no arbitrary shell bridge, no remote content execution, bounded IPC.
8. **G-D8 Packaging / portable mode** — Windows installer feasibility and explicit portable-mode evidence.
9. **G-D9 Footprint / latency** — binary/package footprint, cold start, warm start, handshake, and status IPC measurements.

Failure of any hard gate disqualifies the candidate regardless of weighted score.

## Weighted ranking

Eligible candidates are ranked using the weights frozen in the evaluation plan:

- security and isolation — 25;
- Shared Core integration — 20;
- Windows build and packaging — 15;
- footprint/startup/IPC — 15;
- maintainability and supply chain — 10;
- portable mode — 10;
- accessibility and UX — 5.

## Execution slices

### 5.6.0 — Spike contract + environment/core-boundary probe

Deliver:

- evaluation plan;
- Windows CI bootstrap;
- exact toolchain evidence;
- production `atlas-core.exe` build from the current Shared Core;
- framed `core.handshake` + `core.status` smoke test;
- evidence artifact upload.

No Desktop framework is selected in this slice.

### 5.6.1 — Executable candidate builds

Build minimal Tauri, Electron, and .NET hosts that all perform the same controlled operation:

1. locate the packaged `atlas-core` sidecar;
2. validate the expected executable/version identity;
3. spawn `atlas-core --serve-stdio`;
4. perform handshake;
5. call `core.status`;
6. render the returned status;
7. terminate cleanly.

The candidate host must contain no independent search/index/trust implementation.

### 5.6.2 — Evidence review + ADR-0026

Compare hard-gate results and weighted measurements. Accept exactly one Desktop host family. The ADR must document rejected alternatives and any residual risks.

### 5.6.3 — First Preview UI

Implement only preview-critical surfaces:

- offline exact/lexical search;
- canonical record/detail view;
- bounded relationship navigation;
- claim/source provenance;
- verified pack state/update;
- safe rollback status/action;
- failure/recovery state.

### 5.6.4 — Windows packaging / portable smoke

Produce the first Windows package, validate sidecar location/integrity, run on a clean Windows environment, and evaluate portable mode.

## Scope control

Explicitly deferred from the First Preview critical path:

- Web/PWA;
- Grounded AI or MCP;
- cloud synchronization;
- semantic/vector retrieval;
- remote/public API;
- non-Windows Desktop builds;
- decorative UI work not required for the preview workflow.

## Selection evidence sources

Screening version references checked on 2026-09-15:

- Tauri release documentation: `https://tauri.app/release/tauri/all-versions/`
- Electron releases: `https://releases.electronjs.org/`
- .NET support policy: `https://dotnet.microsoft.com/en-us/platform/support/policy`

The repository CI evidence is authoritative for actual candidate eligibility.
