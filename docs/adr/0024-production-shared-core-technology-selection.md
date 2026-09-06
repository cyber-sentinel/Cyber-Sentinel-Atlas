# ADR-0024 — Production Shared Core Technology Selection

**Status:** Accepted — Architecture Authority approved 2026-09-06

## Context

ADR-0006 requires an implementation spike before Atlas selects the production Shared Core technology. Phase 5.4 froze deterministic search semantics and selected SQLite + FTS5 for the derived production search artifact. ADR-0023 and Phase 5.5.2 froze and proved the secure content-pack trust/runtime behavior through an executable Python reference implementation.

The Windows Desktop MVP now needs a production Shared Core that can implement those contracts without becoming a second source of truth or forcing future Web/PWA, API or CLI interfaces to reimplement security/search semantics independently.

The current Python implementation remains executable semantic evidence and a conformance oracle; it is not an automatic production-language decision.

## Decision scope

This ADR selects the production implementation language/runtime and the evidenced minimum dependency baseline for:

- canonical/read model access;
- deterministic SQLite/FTS5 search;
- bounded relationship navigation;
- Atlas TUF POUF v1 pack verification;
- immutable install/activation/LKG/rollback state;
- stable interfaces consumed by Windows Desktop and later API/CLI/Web-facing adapters.

The decision does **not** select the Desktop UI framework, Desktop IPC transport/ABI, broader application storage, graph database, HSM/KMS provider, application updater, CDN/distribution topology, Detection IR, semantic/vector retrieval, or Grounded AI runtime.

## Candidates

Architecture screening covered:

- Rust;
- Go;
- Python as reference/control;
- TypeScript/Node.js;
- .NET/C#.

The executable finalist set was Rust, Go and Python control under the hard-gate rules in `docs/architecture/phase-5.5.3-shared-core-technology-spike.md`. TypeScript/Node.js and .NET/C# remained screened alternatives and were not promoted after a non-control finalist passed every mandatory gate on both target operating systems.

## Evidence binding

The decision evidence is frozen in `benchmarks/shared-core/phase553/selection-summary.json` and is bound to:

- executable evidence branch head: `8ff9e687a23b280ccb8e957ffc55555b4288199c`;
- Phase 5.5.3 workflow run: `34039331139` — success;
- Foundation Hygiene run: `34039331185` — success;
- Linux evidence artifact: `9991212307`, digest `sha256:94b6fa7c0a812ffad4c05e6467fc3d61c413ea29949713e167baaa34e3d9b596`;
- Windows evidence artifact: `9991210708`, digest `sha256:a9c2428c52a7a7a82fd93c832fe7e5c4f7becf7265b981629a8d3843a4cb2219`;
- SPC bundle digest: `sha256-61a7a9b46a070e279046230f593826d676adabd91b3384a085c8b19fa571af93`;
- cross-language serialization vector digest: `sha256-e4aa5c02c3c5c6291c09f2202cea9bcb92aa0c06900181e742af7da666633569`.

The same accepted canonical/search/pack fixtures were used as the semantic boundary. Canonical `schemas/v1/` remained unchanged in the cross-platform workflow.

## Mandatory hard-gate result

A mandatory gate failure disqualifies a candidate regardless of weighted score.

| Candidate | Linux G-SC1..G-SC8 | Windows G-SC1..G-SC8 | Eligibility |
| --- | --- | --- | --- |
| Go | all pass | all pass | **eligible** |
| Python control | all pass | all pass | **eligible** |
| Rust | G-SC5/G-SC6/G-SC7 fail | complete Windows candidate evidence not produced; hard-gate failure recorded | **ineligible** |

Rust's result is a Phase 5.5.3 evidence result, not a general judgment that Rust is unsuitable for Atlas. Its Linux search/SQLite evidence remains technically useful, but hard-gate incompleteness prevents selection under the architecture rules.

## Cross-platform measured evidence

### Go

- Go runtime/toolchain exercised: `go1.25.0`.
- TUF client baseline: `github.com/theupdateframework/go-tuf/v2 v2.4.2`.
- CGo-free SQLite baseline: `modernc.org/sqlite v1.58.0`.
- Unicode normalization/casefold dependency selected by the normalized module graph: `golang.org/x/text v0.36.0`.
- SQLite observed in the finalist: `3.53.4` on Linux and Windows; FTS5 workload passed on both.
- Linux exact P95: `0.123895 ms`; lexical P95: `0.378843 ms`.
- Windows exact P95: `1.5867 ms`; lexical P95: `1.521 ms`.
- Linux compiled binary: `19,023,793` bytes.
- Windows compiled binary: `19,431,424` bytes.
- Linux durable replacement evidence: `rename(2)+directory-fsync`.
- Windows durable replacement evidence: `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`.
- Atlas TUF adversarial fixture, local-only/offline fetch boundary, search parity, high-fanout deterministic ordering, duplicate numeric cutoff ordering, durable highest-seen state, health rollback/LKG restoration, strict SemVer, trusted-time rollback guard and crash-before-replace behavior all passed the mandatory evidence path.

The search measurements are far inside the already accepted MVP gates of exact P95 `<100 ms` and lexical P95 `<300 ms`; these numbers are evidence for this fixture/environment, not a universal throughput guarantee.

### Python control

Python remained eligible on both platforms and continues to serve as the executable semantic/conformance oracle. Its weighted score is lower because production packaging, embedding/runtime footprint and interface integration are less favorable for the intended reusable compiled Shared Core boundary. No contract exception is granted to Go relative to Python; cross-language parity is mandatory.

### Rust

Rust demonstrated a smaller native artifact and strong search performance on Linux, but it did not satisfy the full Phase 5.5.3 trust/runtime and cross-platform hard-gate envelope. It is therefore excluded before weighted ranking. Atlas did not create a custom crypto/TUF substitute merely to manufacture a passing result.

## Serialization/digest decision within this ADR

The spike compared the existing Atlas deterministic JSON bytes with RFC 8785/JCS ordering behavior and proved that the profiles are **not generally byte-equivalent**.

For Phase 5.5.3:

- retain the existing Atlas deterministic JSON profile;
- perform **no existing digest migration**;
- keep frozen cross-language serialization vectors as protocol-conformance tests;
- require a separate accepted ADR, explicit versioning/migration rules and compatibility evidence before any future migration to JCS or another canonical serialization profile.

Observed ordering contrast digests:

- Atlas profile: `sha256-86f7643502ce36621ae93769d7af762ff9c2f90e8c207fcb36f38c2cc6650c72`;
- JCS comparison: `sha256-e809e2d586f904340931323f0da13a22ddd4c10e5ead816b900f6d5c6bcd3e9f`.

## Weighted result

Only hard-gate-eligible candidates are ranked.

| Candidate | Contract/security | TUF/pack | SQLite/search | Durability | Footprint | Integration | Maintainability | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Go** | 30 | 20 | 15 | 9 | 9 | 9 | 4 | **96** |
| Python control | 30 | 18 | 15 | 9 | 3 | 6 | 4 | **85** |

The score is subordinate to hard gates and does not override contract fidelity.

## Decision

**Select Go as the production Atlas Shared Core implementation family.**

The accepted evidenced baseline is:

- Go as the production Shared Core language/runtime family;
- `go-tuf/v2 v2.4.2` as the TUF client baseline;
- `modernc.org/sqlite v1.58.0` as the CGo-free SQLite baseline;
- the normalized Go module graph, including `golang.org/x/text v0.36.0`, remains lockfile-controlled and must be reproduced by CI;
- accepted Phase 5.4 SQLite/FTS5 search semantics remain authoritative;
- accepted Phase 5.5.1/5.5.2 Atlas TUF POUF v1, archive, staging, activation, rollback and offline-security semantics remain authoritative;
- the existing Atlas deterministic JSON serialization profile remains the protocol byte/digest profile for this phase;
- Python remains the reference/control implementation during production-port conformance and may not be silently diverged from.

This is a Shared Core implementation decision, not a Desktop-stack decision. A subsequent production implementation slice must define a stable process/API/IPC boundary without assuming that Go requires or forbids Tauri, Electron, .NET, React, or another UI stack.

## Why Go is selected

Go is the only non-control finalist that passed all eight mandatory gates on both target operating systems and then ranked first among eligible candidates. It preserves the frozen canonical, search, pack-trust, offline and durable rollback semantics while providing a compiled cross-platform artifact and a CGo-free SQLite path suitable for a reusable local core.

The selection is based on measured Atlas-specific evidence, not on a general language preference. Rust's smaller binary and fast search do not compensate for failed mandatory trust/runtime gates. Python's semantic fidelity is retained as the control, but its production packaging and integration characteristics score lower for the intended reusable Shared Core role.

## Consequences

- production Shared Core implementation work may begin in a new implementation slice/branch after this ADR is merged;
- Go production code must pass the same cross-language semantic, search, TUF, archive/offline and durable-state conformance fixtures before replacing any Python reference path;
- dependency locks, SBOM/vulnerability review and reproducible clean builds become release gates for the production Go core;
- Windows filesystem behavior must continue to test replacement/durability and fail closed under state-write or activation failure;
- the Go binary footprint is acceptable at current MVP evidence scale but remains monitored;
- canonical `schemas/v1/` is unchanged;
- Desktop UI framework, IPC transport, broader persistence and later AI/detection technologies remain open architecture decisions.

## Rejected / deferred alternatives

- **Python:** eligible and retained as semantic/conformance oracle; not selected for the production core because packaging, embedding/footprint and interface-integration costs scored materially worse.
- **Rust:** not selected in this phase because mandatory trust/runtime and Windows reproducibility evidence was incomplete or failed. Reconsideration is allowed if the same G-SC1..G-SC8 envelope later passes reproducibly.
- **TypeScript/Node.js:** screened but not promoted after an eligible non-control finalist passed all hard gates and ranked first; further executable work would add scope without a material decision benefit.
- **.NET/C#:** screened but not promoted for the same reason; remains a possible Desktop/UI-side technology because this ADR does not select the UI stack.

## Revisit triggers after acceptance

Reopen this technology decision if:

- a mandatory security/conformance property cannot be maintained in the Go production implementation;
- required TUF features exceed the selected `go-tuf` profile;
- Windows Desktop embedding, portable mode or stable interface exposure becomes materially infeasible;
- corpus or pack scale invalidates measured performance/footprint assumptions;
- future API/CLI/Web reuse requires a boundary the selected core cannot expose safely;
- a selected dependency becomes unmaintained or suffers a security issue that cannot be mitigated within the selected stack.

## Architecture Authority acceptance

Accepted by Architecture Authority on 2026-09-06 under the standing project authorization. Go is frozen as the Phase 5.5 production Shared Core implementation family subject to the documented revisit triggers. Any future technology change requires a new ADR and reproducible evidence.
