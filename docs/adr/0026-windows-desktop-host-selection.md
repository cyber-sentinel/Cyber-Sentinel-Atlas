# ADR-0026 — Windows Desktop Host Selection

**Status:** Accepted — Architecture Authority approved 2026-09-16

## Context

ADR-0025 freezes the Atlas local Desktop integration boundary as a versioned child-process stdio protocol implemented by `atlas-core --serve-stdio`. Phase 5.6 must choose exactly one Windows Desktop host without moving canonical validation, search, graph traversal, provenance, pack trust, update, activation, or rollback semantics out of the Shared Core.

The Phase 5.6 evaluation plan screened three host families:

- Tauri 2.x;
- Electron;
- .NET 10 LTS Windows Desktop / WPF.

Selection is permitted only after every mandatory hard gate G-D1 through G-D9 has passed and the frozen weighted review has been completed.

## Evidence authority

The authoritative selection evidence is the exact-head Windows workflow run:

- workflow run: `35085162486`;
- evidence head: `8fb98c22daf74bf597da0e7527ea92f5b5f14779`;
- artifact: `phase562-desktop-gate-evidence`;
- artifact SHA-256: `dc1ced987d87d339fc098964089295cdaea560e9b0f9a5ac7b945dab13e70904`.

That run closed the executable evidence chain for all three candidates:

- G-D1 Windows clean build — PASS;
- G-D2 atlas-core stdio handshake/status — PASS;
- G-D3 offline/no default network listener — PASS;
- G-D4 deterministic sidecar location/integrity/version — PASS;
- G-D5 search/record/graph/provenance capability — PASS, verified separately by the production Shared Core evidence;
- G-D6 pack status/update/rollback capability — PASS, verified separately by the production Shared Core evidence;
- G-D7 Desktop security surface — PASS;
- G-D8 installer/portable-mode feasibility — PASS_FEASIBILITY;
- G-D9 footprint/startup/IPC measurements — PASS.

No candidate was disqualified by a hard gate.

The complete scoring record is committed in `benchmarks/desktop/phase56/weighted-review.json`.

## Weighted review method

The frozen weights are:

- security and isolation — 25;
- Shared Core integration — 20;
- Windows build and packaging — 15;
- footprint/startup/IPC — 15;
- maintainability and supply chain — 10;
- portable mode — 10;
- accessibility and UX — 5.

For gate-backed criteria, a candidate receives the full criterion weight only when exact-head evidence proves the corresponding contract. All three candidates met those contracts.

Phase 5.6.2 did not collect comparative accessibility/UX evidence. That category is therefore scored `0` equally for every candidate. This is an explicit evidence boundary rather than an accessibility failure, and it cannot influence the ordering.

The G-D9 criterion is calculated from the common external Windows harness using lower-is-better ratio normalization:

`component score = component weight × best observed value / candidate value`

The 15 G-D9 points are split across:

- package size — 3;
- first post-build/staged launch — 3;
- warm process duration median — 4;
- median peak process-tree working set — 4;
- p95 process count — 1.

Candidate-internal round-trip numbers are excluded from cross-candidate scoring because the evidence labels them reference-only. Common `atlas-core` handshake/status IPC is identical across candidates and therefore does not differentiate host selection.

## Observed measurements

### Tauri 2.11.5

- package size: `28,066,386` bytes;
- first launch: `262.744 ms`;
- warm launch median: `258.971 ms`;
- median peak process-tree working set: `25,235,456` bytes;
- p95 process count: `3`;
- weighted score: `94.13 / 100` under the frozen review method.

### .NET 10 WPF

- package size: `19,923,348` bytes;
- first launch: `1365.070 ms`;
- warm launch median: `470.138 ms`;
- median peak process-tree working set: `64,786,432` bytes;
- p95 process count: `4`;
- weighted score: `88.09 / 100`.

### Electron 44.3.0

- package size: `405,004,847` bytes;
- first launch: `1080.622 ms`;
- warm launch median: `1126.594 ms`;
- median peak process-tree working set: `385,200,128` bytes;
- p95 process count: `5`;
- weighted score: `82.66 / 100`.

The common production `atlas-core.exe` remained identical across candidates with SHA-256 `83ca757c1629e37f2139161484cdaa8e9ea88c1045464b66565d7930c6cd9efd`.

## Decision

Atlas selects **Tauri 2.x** as the Windows Desktop host family for Phase 5.6.3 First Preview and the subsequent Windows packaging work.

The selected screening baseline is Tauri `2.11.5`; future patch/minor upgrades remain normal dependency maintenance and must preserve the same security, reproducibility, offline, sidecar-integrity, and Shared Core contracts.

The Desktop implementation will continue to:

- use `atlas-core --serve-stdio` as the only production application-data authority;
- perform deterministic sidecar discovery and SHA-256 verification before use;
- fail closed on protocol/version/integrity mismatch;
- expose only explicitly allowlisted Tauri commands/capabilities;
- keep CSP `connect-src 'none'` for the First Preview unless a later ADR changes the network model;
- avoid arbitrary shell/process bridges and generic frontend network APIs;
- keep binary auto-update outside the First Preview;
- preserve TUF/pack update and rollback authority inside the Shared Core.

## Why Tauri was selected

Tauri passed every mandatory security, integration, Windows build, portable-mode and measurement gate while providing the highest weighted score under the frozen evaluation plan.

Its decisive measured advantage was not a different Shared Core implementation: all candidates used the same verified `atlas-core.exe`. The advantage was the host envelope itself — substantially lower warm startup duration, lower process-tree memory, lower process count and a small package compared with Electron, while retaining a webview-based UI surface suitable for the First Preview.

## Alternatives considered

### .NET 10 WPF

WPF remains technically eligible and produced the smallest measured package. Its native Windows UI and lack of a browser bridge are favorable properties. It was not selected because the common evidence run measured materially slower first/warm process duration and higher process-tree memory than Tauri. Selecting WPF would also move the preview UI implementation to a separate native XAML surface instead of the already-proven bounded webview host model.

### Electron 44.3.0

Electron remains technically eligible and its security surface was explicitly hardened with sandboxing, context isolation, disabled Node integration, denied navigation/webviews/downloads, and a frozen IPC bridge. It was not selected because the measured package, warm startup, memory and process footprint were materially larger than the other candidates without a compensating requirement in the First Preview scope.

## Residual risks and required follow-up

1. **WebView2 runtime dependency.** Tauri on Windows relies on Microsoft Edge WebView2 Runtime. Phase 5.6.4 must make the offline/clean-machine installation behavior explicit and must not silently require Internet access.
2. **Installer/signing evidence.** G-D8 proves relocation and installer feasibility only. Production installer creation, Authenticode signing boundaries and clean-machine smoke remain mandatory Phase 5.6.4 work.
3. **Accessibility/UX evidence.** Phase 5.6.2 did not compare accessibility/UX. Phase 5.6.3 must add keyboard navigation, focus visibility, semantic labels, scalable text and usable failure/recovery surfaces before First Preview acceptance.
4. **Rust/Tauri supply chain.** The committed `Cargo.lock`, approved lock SHA-256, `--locked` builds and exact toolchain pin are mandatory reproducibility controls. They must remain machine-enforced.
5. **Cold-start interpretation.** The recorded cold value is the first post-build/staged launch on the CI runner; the OS page cache is not forcibly purged. This is sufficient for the Phase 5.6 gate but is not a laboratory cold-cache benchmark.

## Consequences

Positive:

- one Desktop host family is now authoritative;
- First Preview UI implementation can proceed without re-opening framework selection;
- the Shared Core remains replaceable independently from the UI shell;
- measured host footprint is substantially lower than Electron and lower-memory/faster than the WPF candidate in the exact-head run;
- the existing Tauri least-privilege command/capability model becomes the production Desktop security baseline.

Costs:

- Windows packaging must account for WebView2 availability;
- Rust/Tauri and frontend dependencies add a multi-toolchain maintenance surface;
- webview security configuration becomes a release-critical control and cannot be weakened for convenience;
- accessibility remains an explicit acceptance task rather than an assumption from framework selection.

## Revisit triggers

Reopen this ADR only if executable evidence shows one of the following:

- Tauri cannot satisfy clean-machine offline installation or required enterprise Windows deployment constraints;
- WebView2 policy/runtime constraints materially break the supported deployment model;
- a required accessibility capability cannot be delivered without violating the frozen security boundary;
- measured production behavior regresses beyond agreed acceptance thresholds and cannot be corrected without changing host family;
- the Shared Core transport changes through a later accepted ADR.

## Architecture Authority acceptance

Accepted on 2026-09-16 under the standing project authorization after exact-head Phase 5.6.2 hard-gate closure and the committed weighted review. Phase 5.6.3 is authorized to implement the First Preview on Tauri 2.x; Phase 5.6.4 remains responsible for final Windows packaging and clean-machine acceptance.
