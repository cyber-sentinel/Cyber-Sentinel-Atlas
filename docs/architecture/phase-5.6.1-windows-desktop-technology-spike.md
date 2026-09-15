# Phase 5.6.1 — Windows Desktop Technology Spike

Status: **EVIDENCE SPIKE AUTHORIZED / DECISION PENDING**

Issue: #37  
Decision record: ADR-0026 (Proposed until evidence closes)

## Purpose

Phase 5.6.1 selects the production Windows Desktop implementation stack from executable evidence. It is not a UI implementation phase and it must not modify Atlas canonical/search/pack semantics or the accepted Shared Core local interface to make a candidate easier to integrate.

The frozen integration boundary remains `atlas-core --serve-stdio` under ADR-0025: a child process, protocol `1.0.0`, 4-byte unsigned big-endian length prefix, UTF-8 JSON payloads, one request at a time per child process, bounded frames, protocol-only stdout, diagnostics-only stderr, and no hidden network fallback.

## Non-negotiable architecture rules

1. The Desktop is a consumer of Shared Core, not a second knowledge engine.
2. No candidate may import production Go Shared Core packages directly or use FFI to bypass ADR-0025.
3. No candidate may introduce localhost HTTP/TCP, WebSocket, named-pipe replacement, or internet fallback for the local core session.
4. Exact/lexical search, entity detail, relationships, provenance/evidence and pack state must come through the Shared Core interface.
5. Canonical schemas v1, deterministic search contracts, TUF pack trust and the existing JSON/digest profile remain frozen.
6. Candidate-specific child-process privileges must be allowlisted and minimized.
7. The accepted baseline must pin exact framework/toolchain/dependency versions; mutable `latest` references are not an acceptable production baseline.
8. The self-hosted Windows runner may be used for temporary toolchains/build state, but the spike must not leave persistent machine configuration behind.

## Candidates

### Tauri 2

Evaluate a Rust/WebView2 shell with `atlas-core` packaged as a constrained external binary/sidecar. Tauri documentation demonstrates sidecar spawn and stdin/stdout interaction and supports MSI/NSIS Windows distribution with offline or fixed WebView2 options. The spike must verify binary naming/packaging, capability allowlists, child lifecycle, CSP/isolation, offline installation and reproducible Windows CI.

References:
- https://v2.tauri.app/develop/sidecar/
- https://v2.tauri.app/distribute/windows-installer/
- https://v2.tauri.app/start/prerequisites/

### Electron

Evaluate an Electron shell in which only the trusted main process supervises `atlas-core`; renderers must not receive unrestricted Node/process execution. Electron's process model provides a Node main process and child/utility-process primitives, but the actual Chromium/Node footprint, dependency surface, sandbox/context isolation, packaging and offline behavior must be measured rather than assumed.

References:
- https://www.electronjs.org/docs/latest/tutorial/process-model
- https://www.electronjs.org/docs/latest/tutorial/application-distribution

### Wails stable

Evaluate the current stable Wails line on Windows/WebView2. Wails is attractive because the team already owns a Go production core, but that is also an architectural hazard: the Desktop must prove that it consumes the compiled `atlas-core` process exclusively through ADR-0025 and does not collapse UI and core ownership into direct Go imports. WebView2 deployment behavior and Windows packaging must be measured.

References:
- https://wails.io/docs/gettingstarted/installation/
- https://wails.io/docs/guides/windows/

### WinUI 3 / Windows App SDK

Evaluate a native Windows/.NET shell using `System.Diagnostics.Process` with redirected stdin/stdout/stderr for the frozen child protocol. Evidence must cover packaged and unpackaged/self-contained deployment, portable/folder-based feasibility, Windows App SDK runtime requirements, accessibility, DPI and enterprise deployment complexity.

References:
- https://learn.microsoft.com/windows/apps/windows-app-sdk/deploy-unpackaged-apps
- https://learn.microsoft.com/windows/apps/package-and-deploy/unpackage-winui-app

## Evidence gates

The machine-readable source of truth is `benchmarks/desktop/phase561/evaluation-plan.json`. G-DT1 through G-DT12 are mandatory evidence gates. The fast-fail subset is G-DT1, G-DT2, G-DT3, G-DT4, G-DT7, G-DT9 and G-DT10.

A fast-fail gate failure eliminates a candidate before full shell work. This keeps the spike short without weakening architecture/security criteria.

## Execution strategy

### R1 — Hard-gate micro-probes

All four candidates receive the smallest executable adapter necessary to:

- start the same `atlas-core` binary;
- complete the exact protocol handshake;
- execute the same representative core request;
- contain malformed/crashed child behavior;
- prove outbound-network-denied operation;
- expose build/dependency/lock/SBOM feasibility;
- run deterministically on `ATLAS-CI-WIN01`.

No candidate receives scoring credit for visual polish in R1.

### R2 — Full evidence finalists

At most two candidates advance. Each finalist builds a minimal but comparable Desktop shell implementing the same analyst journey:

1. launch offline;
2. handshake with `atlas-core`;
3. exact search;
4. lexical search;
5. open canonical entity detail;
6. inspect relationships;
7. inspect claim-level provenance/evidence;
8. display verified pack state;
9. terminate cleanly.

R2 also collects installer/portable evidence, cold-start/handshake/idle-memory/package-size measurements, accessibility/DPI evidence, signing compatibility, SBOM/vulnerability/license evidence and maintainability/testability scoring.

## Measurement rules

- Same `atlas-core` binary and same corpus for all candidates.
- Same Windows runner class for comparative measurements.
- One warm-up followed by at least five measured launches.
- Median is mandatory; p95 is reported where meaningful.
- Offline status must be proven with explicit outbound denial rather than inferred from lack of observed traffic.
- Critical/high vulnerabilities in executed production dependency paths are fail-closed until patched or removed; silent suppression is prohibited.
- Measurements must be emitted in machine-readable JSON as well as a human-readable report.

## Initial CI boundary

The first Phase 5.6.1 CI slice is deliberately non-invasive:

- validate this architecture contract, ADR state and evaluation plan;
- prove no changes to `schemas/v1` or `shared-core/go` are introduced by the Desktop spike;
- collect a read-only Windows runner capability inventory as evidence for toolchain planning.

Candidate toolchains are added only with pinned/reproducible setup and rollback/cleanup behavior.

## Exit criteria

Phase 5.6.1 may close only when:

- all mandatory gates have resolved evidence for the selected candidate;
- all rejected candidates have explicit evidence-based rationale;
- exact selected versions and lockfiles are recorded;
- ADR-0026 is changed from Proposed to Accepted;
- exact-head CI is green;
- architecture/security review confirms the Desktop did not redefine the Shared Core boundary;
- post-merge verification is green.

Until then, **no Windows Desktop framework is selected**.
