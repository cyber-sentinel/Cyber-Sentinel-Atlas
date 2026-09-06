# Phase 5.5.4 — Production Go Shared Core

Status: **ARCHITECTURE ACCEPTED / IMPLEMENTATION AUTHORIZED**

Baseline main: `94f3136687f8e9765c0343b938a1049436878783`

Authoritative decisions:

- ADR-0006 — Shared Core and Interface Sequencing
- ADR-0022 — SQLite + FTS5 Search Engine Selection
- ADR-0023 — Secure Content Pack Trust and Update Model
- ADR-0024 — Go Production Shared Core Selection
- ADR-0025 — Shared Core Local Interface Boundary

## Purpose

Phase 5.5.4 converts the Phase 5.5.3 executable Go finalist into production Shared Core code. Benchmark/spike code remains evidence and is not itself promoted into the product runtime.

The production core must implement the already-accepted Atlas semantics without redefining them for Go convenience.

## Production source boundary

Production code will live under:

```text
shared-core/go/
```

The intended package boundary is:

```text
shared-core/go/
├── go.mod
├── go.sum
├── cmd/
│   └── atlas-core/
├── internal/
│   ├── canonical/
│   ├── protocol/
│   ├── search/
│   ├── graph/
│   ├── pack/
│   ├── state/
│   └── app/
└── testdata/   # only Atlas-owned non-secret fixtures where appropriate
```

Production packages must not import `benchmarks/shared-core/phase553` as a runtime dependency. Spike code may be copied/refactored only after production tests bind the resulting behavior to the same canonical/search/pack fixtures.

## Core responsibilities

### Canonical/read model

- read and validate the existing seven AtlasRecord families;
- preserve canonical/native identifier, lifecycle, provenance and relationship semantics;
- reproduce frozen Atlas deterministic JSON vectors where protocol digests depend on exact bytes;
- reject an unknown eighth family or invalid canonical identifier state;
- never mutate `schemas/v1/` merely to fit Go types.

### Deterministic search

- SQLite + FTS5 remains the derived disposable search artifact;
- exact canonical/native/scoped/alias resolution precedes lexical retrieval;
- lexical retrieval keeps safe internal FTS expression construction and bound SQL parameters;
- malformed Unicode/surrogates fail closed;
- maximum query size remains 512 Unicode scalars and maximum lexical term count remains 32;
- high-fanout ties and duplicate numeric Event-ID cutoffs retain deterministic total ordering;
- provider/source/lifecycle catalogs and bounded graph pivots preserve Phase 5.4 contracts;
- no vector/semantic fallback is hidden inside search.

### Pack trust and runtime

- TUF/Atlas POUF v1 verification remains mandatory before publication-grade pack activation;
- `.atlaspack` strict archive validation occurs before extraction;
- executable content from packs remains prohibited;
- verified artifact bytes, Pack Manifest, Source-License Inventory and projection/index bindings remain exact;
- immutable generations, durable highest-seen version state, trusted-time rollback protection, atomic active/LKG transitions and health rollback remain mandatory;
- network access is absent from installed-pack search/read paths;
- production code may not invent a weaker custom cryptographic verifier as a substitute for the accepted TUF path.

## Local interface

`cmd/atlas-core` implements ADR-0025 as a child-process stdio server.

Protocol v1 invariants include:

- 4-byte big-endian length-prefixed UTF-8 JSON frames;
- request <= 1 MiB, response <= 8 MiB;
- strict duplicate-key/unknown-envelope-field/UTF-8/BOM/trailing-value/depth validation;
- mandatory `core.handshake` before operational requests;
- exact `atlas-core` protocol `1.0.0` support initially;
- one request at a time per child process;
- compiled method allowlist only;
- stdout reserved for protocol frames and stderr for logs;
- no default listener or hidden network fallback.

Initial production method closure:

1. `core.handshake`
2. `core.status`
3. `search.query`
4. `record.get`
5. `catalog.list`
6. `graph.expand`
7. `pack.status`

Pack mutation methods are added only after the production pack/state implementation passes the Phase 5.5.2 adversarial envelope. They are not enabled through generic dynamic dispatch.

## Stable error model

Protocol errors use stable machine-readable codes. Initial families:

- `ATLAS_PROTOCOL_INVALID_FRAME`
- `ATLAS_PROTOCOL_UNSUPPORTED_VERSION`
- `ATLAS_PROTOCOL_HANDSHAKE_REQUIRED`
- `ATLAS_PROTOCOL_INVALID_REQUEST`
- `ATLAS_METHOD_NOT_FOUND`
- `ATLAS_QUERY_INVALID`
- `ATLAS_RECORD_NOT_FOUND`
- `ATLAS_AMBIGUOUS_IDENTIFIER`
- `ATLAS_PACK_NOT_READY`
- `ATLAS_PACK_TRUST_FAILURE`
- `ATLAS_STATE_FAILURE`
- `ATLAS_INTERNAL_FAILURE`

Error messages are bounded diagnostics and may not disclose stack traces, secrets, private-key material, environment dumps, or arbitrary local paths.

## Implementation slices

Phase 5.5.4 may be implemented incrementally, but all slices remain within this accepted architecture:

### 5.5.4A — Core skeleton + protocol

- Go module and dependency locks;
- typed protocol framing/parser/handshake/error envelope;
- `core.status`;
- Linux/Windows protocol adversarial tests;
- deterministic build metadata.

### 5.5.4B — Canonical + search + graph

- canonical/read-model loader and deterministic serialization vectors;
- production SQLite/FTS5 resolver/search/catalog/graph packages;
- cross-language result parity against Python control;
- performance regression gates.

### 5.5.4C — Pack trust + durable state

- go-tuf POUF v1 verification;
- strict archive/manifest/source-license validation;
- immutable install generations;
- highest-seen/trusted-time state;
- activation/LKG/health rollback;
- Linux/Windows filesystem adversarial tests.

### 5.5.4D — Supply-chain / closure

- clean reproducible Linux/Windows builds from locked Go definitions;
- SBOM generation;
- `govulncheck`/Go vulnerability evidence;
- dependency/license inventory review;
- full Python-oracle conformance suite;
- binary footprint and startup/IPC measurements;
- closure documentation and status sync.

Sub-slice labels are execution structure only and do not create new canonical schemas or reopen ADR-0024/0025 unless a documented revisit trigger fires.

## Dependency policy

The initial production baseline inherited from ADR-0024 is:

- `github.com/theupdateframework/go-tuf/v2 v2.4.2`;
- `modernc.org/sqlite v1.58.0`;
- normalized graph including `golang.org/x/text v0.36.0`.

`go.mod` and `go.sum` are authoritative dependency locks for the Go module. CI must verify the actual build module graph rather than trusting documentation text.

New production dependencies require explicit justification, license review and reproducible CI evidence. Runtime plugins and dynamic code loading are out of scope.

## Supply-chain evidence

Before Phase 5.5.4 closes:

- the Go module graph is archived as machine-readable evidence;
- a CycloneDX-compatible SBOM is generated from the locked module/build graph;
- Go vulnerability scanning runs against the production packages;
- security results distinguish reachable/code-called findings where the tooling supports it;
- a vulnerability finding cannot be waived silently; a documented risk decision or remediation is required;
- release builds record Go/toolchain version, target OS/architecture and module build information.

Networked vulnerability database access is allowed in CI/release validation; the installed Atlas Shared Core itself remains offline-capable and does not contact the vulnerability service at runtime.

## CI gates

At minimum:

- Ubuntu x86-64 clean build/test;
- Windows x86-64 clean build/test;
- `go test ./...`;
- race/static analysis where supported without weakening cross-platform reproducibility;
- protocol fuzz/adversarial fixture tests;
- canonical/search cross-language conformance;
- TUF/archive/state adversarial conformance;
- canonical `schemas/v1/` unchanged;
- no secrets/private keys committed;
- dependency lock drift detected;
- SBOM and vulnerability evidence emitted as CI artifacts.

## Failure and rollback philosophy

Search index state is disposable and deterministically rebuildable from verified projection data. Installed pack generations and trust/highest-seen state are not disposable and remain protected by ADR-0023 semantics.

A crash, malformed protocol frame, failed pack verification, write failure, AV/filesystem interference, or failed post-activation health check must not expose a partially active generation as healthy.

## Explicit non-goals

Phase 5.5.4 does not select or implement:

- Windows Desktop UI framework;
- browser/Web/PWA runtime;
- remote HTTP API;
- public multi-user daemon;
- graph database;
- HSM/KMS/signing ceremony;
- application binary updater/CDN;
- Detection IR;
- semantic/vector search;
- Grounded AI runtime.

## Exit criteria

Phase 5.5.4 closes only when:

- ADR-0025 and this architecture boundary are merged;
- production Go code exists outside benchmark directories;
- the stdio protocol is versioned and adversarially tested;
- canonical/search/graph behavior matches accepted contracts and Python control;
- pack/TUF/archive/state/LKG behavior matches Phase 5.5.1/5.5.2;
- Linux and Windows production CI is green;
- SBOM/vulnerability/dependency evidence is produced;
- no canonical schema drift exists;
- Windows Desktop can begin without reimplementing Shared Core logic or depending on Go FFI internals.
