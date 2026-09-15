# ADR-0026 — Windows Desktop Technology Selection

**Status:** Proposed — Evidence Pending  
**Date:** 2026-09-15  
**Phase:** 5.6.1

## Context

Phase 5.5 closed the production Atlas Shared Core and froze the local Desktop-facing integration boundary in ADR-0025 as a versioned child-process stdio protocol exposed by `atlas-core --serve-stdio`.

The Windows Desktop technology is intentionally independent from the Shared Core implementation choice. Selecting Go for Shared Core does not select Wails; selecting a child-process boundary does not select Tauri, Electron, WinUI 3, or any other UI framework.

Atlas requires an offline-first, security-sensitive Windows application with deterministic access to search, entity, relationship, provenance and verified-pack capabilities. Framework choice therefore affects attack surface, supply-chain risk, packaging, process isolation, accessibility, footprint, operability and long-term maintainability.

## Decision

**Decision to be made after executable Phase 5.6.1 evidence. No production Windows Desktop framework is selected by this Proposed ADR.**

The initial executable candidate set is:

- Tauri 2;
- Electron;
- Wails stable;
- WinUI 3 / Windows App SDK.

A candidate is eligible only if it preserves all frozen Atlas contracts and resolves every mandatory gate in `benchmarks/desktop/phase561/evaluation-plan.json`.

## Mandatory invariants

The accepted solution MUST:

1. consume `atlas-core --serve-stdio` through ADR-0025 protocol `1.0.0`;
2. avoid FFI/direct Go imports and avoid a replacement localhost/network transport;
3. operate offline for all mandatory MVP journeys;
4. supervise the core process with bounded startup, crash containment, clean termination and no orphan process;
5. keep canonical/search/pack semantics in Shared Core;
6. constrain process execution and renderer/webview privileges;
7. provide deterministic Windows CI, exact dependency locks, SBOM, vulnerability and license evidence;
8. support a credible Windows installer and portable/folder-based deployment path;
9. support keyboard accessibility and Windows DPI/scaling requirements;
10. remain compatible with Authenticode/application and installer signing;
11. provide measured startup, handshake, memory and package-footprint evidence;
12. record maintainability/testability evidence rather than rely on framework preference.

## Evaluation method

The spike uses two rounds:

- **R1 — hard-gate micro-probes:** all four candidates implement the smallest comparable adapter required to prove protocol, offline, process-safety, security/supply-chain and CI viability.
- **R2 — full evidence finalists:** at most two candidates implement the same minimal analyst journey and produce packaging, resource, UX, signing and maintainability evidence.

Fast-fail gates eliminate a candidate before R2. Selection then uses the fixed weighted score in the evaluation plan, but a high weighted score cannot compensate for an unresolved or failed mandatory gate.

## Security consequence

The Desktop framework is treated as an untrusted presentation/integration layer relative to canonical knowledge semantics. Renderer/web content must never gain unrestricted shell execution or direct filesystem/core privileges merely because a framework exposes those APIs conveniently.

The Shared Core binary path and permitted arguments must be controlled by application code and packaging. The UI must not accept arbitrary executable paths or command arguments from content packs, indexed records, user-loaded web content or remote input.

## Supply-chain consequence

The accepted baseline must pin exact versions and preserve lockfiles. Production dependency vulnerabilities are fail-closed for critical/high findings in executed paths unless the dependency is patched or removed. Suppression requires a separate documented security exception; the spike itself does not grant such an exception.

## Alternatives

### Tauri 2
Potential advantages: smaller native-WebView2 model, explicit sidecar support, Rust process boundary, MSI/NSIS support. Risks to measure: Rust/tooling complexity, WebView2 deployment, plugin/capability surface and automated Windows UI testing.

### Electron
Potential advantages: mature desktop ecosystem, rapid TypeScript/React UI iteration, strong process model. Risks to measure: Chromium/Node footprint, dependency surface, renderer-to-main security boundary and packaging size.

### Wails stable
Potential advantages: Go ecosystem familiarity and WebView2-based Windows shell. Primary architectural risk: accidental erosion of the compiled Shared Core boundary through direct Go reuse/imports. This is explicitly forbidden by ADR-0025 and Phase 5.6.1.

### WinUI 3 / Windows App SDK
Potential advantages: native Windows UX/accessibility and first-party Windows platform integration. Risks to measure: Windows-only coupling, App SDK runtime/deployment complexity, packaging/portable model and development velocity.

## Acceptance

This ADR remains **Proposed — Evidence Pending** until the Phase 5.6.1 evidence is complete. Acceptance requires an exact selected framework/toolchain baseline, selected/rejected rationale, green exact-head CI, architecture/security review and post-merge verification.
