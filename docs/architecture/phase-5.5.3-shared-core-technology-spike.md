# Phase 5.5.3 — Production Shared Core Technology Spike

Status: **ARCHITECTURE GATE / SPIKE AUTHORIZED**

Baseline main: `d2c837b0740b52aeca9dd579c32911e01c8c6ecc`

## Why this slice exists

Phase 5.5.1 froze the content-pack trust contracts and ADR-0023. Phase 5.5.2 proved the verified pack runtime, secure extraction, TUF verification, deterministic SQLite/FTS5 rebuild, durable rollback state and Last Known Good activation using the repository's Python reference/runtime implementation.

The remaining Phase 5.5 material decision is **which production Shared Core implementation/runtime should own those already-accepted contracts for the Windows Desktop MVP and later interfaces**.

This slice creates reproducible evidence before selecting that technology. It does not treat the current Python implementation, or historical Tauri/Rust/React/TypeScript candidates, as an implicit production decision.

## Authoritative inherited requirements

The candidate implementation must preserve, not reinterpret:

- the seven-family canonical model under `schemas/v1/`;
- canonical IDs and provider/namespace-scoped native identifier semantics;
- Phase 5.4 exact-before-lexical resolution and deterministic ambiguity behavior;
- ADR-0022 SQLite + FTS5 deterministic search behavior;
- Phase 5.4 bounded query/filter/graph contracts and deterministic total ordering;
- ADR-0023 / Atlas TUF POUF v1 trust and update semantics;
- exact Pack Manifest / Source-License Inventory / artifact byte bindings;
- offline operation with no hidden network fallback;
- immutable generation staging, durable highest-seen state, trusted-time rollback guard, atomic activation, health checks and Last Known Good recovery;
- shared contracts consumable by Windows Desktop, Web/PWA, API and the official `atlas` CLI.

No candidate may gain points by changing a frozen contract.

## Candidate screening set

The architecture screen evaluates five implementation families:

1. **Rust**
   - strong native/embedded and Windows Desktop affinity;
   - mature SQLite bindings and straightforward bundled SQLite deployment;
   - direct future compatibility with Tauri remains a possible advantage, not an assumed Desktop decision;
   - TUF-library maturity/completeness must be proven rather than assumed.

2. **Go**
   - cross-platform single-binary deployment and strong CLI/API ergonomics;
   - official `go-tuf/v2` client implementation exists;
   - CGo-free SQLite/FTS5 options exist and must be pinned/tested;
   - Desktop embedding/IPC cost must be measured rather than hand-waved.

3. **Python** — control/reference candidate
   - current Atlas reference implementation and `python-tuf` path are already executable and cross-platform tested;
   - provides the semantic/control baseline for parity testing;
   - packaging, native embedding, startup/runtime footprint and dependency surface must be measured like every other candidate.

4. **TypeScript / Node.js**
   - official `tuf-js` implementation and strong Web/UI ecosystem alignment;
   - native filesystem durability, SQLite/FTS5 packaging, runtime footprint and Desktop trust-boundary suitability require explicit evidence.

5. **.NET / C#**
   - strong Windows integration and cross-platform runtime options;
   - SQLite/native filesystem primitives are available;
   - TUF client/conformance maturity and reuse across future non-Desktop interfaces require explicit evidence.

The first executable spike targets **Rust, Go, and Python as the control** unless bootstrap feasibility proves one of them incapable of the mandatory contract. TypeScript/Node.js and .NET/C# remain screened alternatives and can be promoted into the executable set if evidence invalidates a finalist or exposes a material architectural advantage.

This finalist set is a spike-scope decision, not the production-language decision.

## Upstream evidence seed

The spike must pin exact versions/commits and preserve links to official upstream evidence. Initial authoritative upstream families include:

- TUF Specification — `theupdateframework/specification`;
- Python TUF — `theupdateframework/python-tuf`;
- Go TUF — `theupdateframework/go-tuf`;
- Rust TUF — `theupdateframework/rust-tuf`;
- AWS `tough` where evaluated as a Rust client alternative;
- TUF JS — `theupdateframework/tuf-js`;
- `rusqlite` / bundled SQLite for Rust;
- `modernc.org/sqlite` or another explicitly pinned CGo-free SQLite/FTS5 implementation for Go.

No dependency is accepted because it merely exists. Version, security status, feature completeness, license, build behavior and supported operating systems must be recorded in the evidence bundle.

## Hard pass/fail gates

A candidate is **ineligible regardless of aggregate score** if any mandatory gate fails.

### G-SC1 — Canonical contract fidelity

- reads the existing Atlas canonical and search projection fixtures without schema changes;
- canonical IDs/native IDs/lifecycle/provenance remain unchanged;
- no eighth AtlasRecord family;
- invalid or unknown required contract states fail closed.

### G-SC2 — Cross-language byte/digest interoperability

The candidate must reproduce all frozen digests that are already protocol identity, or the spike must demonstrate exactly where the existing Python serialization behavior is language-specific.

The spike must compare the current Atlas deterministic JSON profile with a standards-based canonical JSON option such as RFC 8785/JCS. **No serialization/hashing migration occurs in Phase 5.5.3 without a separate accepted architecture decision and explicit migration evidence.**

A candidate cannot silently recalculate protocol digests with a different byte representation.

### G-SC3 — Search semantic parity

Using the same SPC and acceptance corpus, the candidate must preserve:

```text
Exact Canonical/Native Identifier
        ↓
Scoped Identifier / Scoped Alias
        ↓
Alias
        ↓
Lexical
```

It must reproduce deterministic ambiguity sets, legacy searchability, bounded filters, high-fanout tie ordering, provider-scoped numeric browse and the accepted query suite. No semantic/vector fallback is permitted.

### G-SC4 — SQLite + FTS5 parity

- FTS5 availability is asserted at build/runtime;
- SQLite version/build options are recorded;
- user input is bound/escaped through typed APIs and is never concatenated into raw SQL or exposed directly as backend DSL;
- the derived index remains disposable and reproducible from verified SPC;
- corruption/staleness fails closed or triggers only the accepted deterministic rebuild path.

### G-SC5 — TUF / POUF v1 interoperability

The candidate must pass an Atlas-owned signed fixture corpus that includes:

- valid root/bootstrap path;
- wrong root;
- target byte tamper;
- signature tamper;
- expired metadata;
- timestamp/snapshot/targets rollback;
- consistent-snapshot target retrieval;
- undeclared signed target rejection;
- offline/no-network enforcement;
- exact Atlas Pack Manifest and source-license binding after TUF verification.

Passing a generic TUF example is insufficient.

### G-SC6 — Durable filesystem and rollback semantics

Linux and Windows tests must prove:

- exclusive install lock behavior;
- durable temp-write + flush/fsync-equivalent + atomic replacement semantics;
- immutable generation identity;
- active/LKG state transition correctness;
- post-activation health rollback;
- pack-version highest-seen preservation;
- trusted wall-clock rollback/state-loss behavior;
- crash/interruption recovery without partial activation.

### G-SC7 — Offline security boundary

- search and installed-pack reads require no network;
- TUF fixture verification can run through a local-only fetch abstraction;
- no dynamic code execution from pack contents;
- malformed path/Unicode/archive input does not escape the trust boundary;
- no unsafe parser repair is accepted silently.

### G-SC8 — Cross-platform build/reproducibility

At minimum:

- `windows-latest` / x86-64;
- `ubuntu-latest` / x86-64;
- clean CI bootstrap from a pinned toolchain/dependency definition;
- recorded binary/runtime footprint;
- reproducible machine-readable benchmark result schema.

## Scored decision dimensions

Only candidates passing all mandatory gates are ranked.

| Dimension | Weight |
| --- | ---: |
| Contract/security fidelity beyond minimum gate | 30 |
| TUF/pack trust implementation maturity and fit | 20 |
| SQLite/FTS5 deterministic performance and operational fit | 15 |
| Windows/Linux durability and portability | 10 |
| Binary/runtime/dependency footprint | 10 |
| Desktop + API + CLI integration fit | 10 |
| Maintainability, ecosystem and supply-chain surface | 5 |
| **Total** | **100** |

Scores require executable evidence or cited upstream facts. Unsupported preference receives no score.

## Required executable workloads

### Search workload

Reuse the Phase 5.4 production acceptance corpus and query semantics, including at least:

- `4688`;
- `Event ID 4688`;
- `windows 4688`;
- `sysmon 1`;
- bare `1` ambiguity behavior;
- `592` legacy lookup;
- `T1059` and `T1059.001`;
- `CreateAccessKey`;
- `EXECVE`;
- `exec_start`;
- `kubectl exec`;
- `FileAccessed`;
- high-cardinality deterministic lexical tie case;
- duplicate numeric Event-ID cutoff ordering.

Performance gates remain the accepted MVP targets unless a later ADR explicitly changes them:

- exact P95 < 100 ms;
- lexical P95 < 300 ms.

### Pack workload

Reuse or generate from the same Atlas 5.5.2 signed fixture corpus. The production candidate must consume the same logical `.atlaspack` / POUF v1 semantics without changing Pack Manifest v1.

### State workload

Run state-transition fixtures across:

```text
install A
activate A -> LKG A
install B
activate B -> LKG B
replay A -> reject
same-version/different-manifest -> reject
activate C -> health fail -> restore LKG B
clock rollback -> reject
trust-state loss with durable state present -> administrative recovery
```

## Benchmark outputs

Each candidate produces a machine-readable evidence artifact containing:

- candidate name;
- exact compiler/runtime/toolchain versions;
- dependency lockfile digest;
- target OS/architecture;
- SQLite version and compile options relevant to FTS5;
- TUF implementation/library identity and version/commit;
- corpus/SPC/fixture digests;
- correctness matrix;
- deterministic repeated-result matrix;
- exact and lexical latency distributions;
- index build time and artifact size;
- compiled binary/runtime footprint;
- pack verification time;
- activation/rollback test results;
- known limitations;
- build/log evidence identifiers.

Raw results remain evidence; a separate selection summary may aggregate them but may not replace them.

## Architecture decision process

`ADR-0024 — Production Shared Core Technology Selection` remains **Proposed** until:

1. candidate screening evidence is committed;
2. executable finalist spikes pass Linux + Windows CI;
3. Atlas cross-language digest/serialization behavior is resolved explicitly;
4. the same search and pack fixture corpus is used for all finalists;
5. security/adversarial failures are fixed or recorded as disqualifying;
6. the weighted decision table is generated from reproducible evidence;
7. architecture review confirms the winner does not implicitly freeze Desktop/Web technology beyond the Shared Core boundary.

Only then may ADR-0024 become Accepted and authorize production Shared Core implementation.

## Explicit non-goals

Phase 5.5.3 does not itself select:

- Tauri, Electron, .NET desktop UI, React or another UI framework;
- a graph database;
- broader application persistence beyond the already accepted SQLite search artifact;
- HSM/KMS/provider or production signing ceremony;
- application binary updater;
- remote CDN/distribution topology;
- Detection IR;
- semantic/vector retrieval;
- Grounded AI runtime.

## Exit criteria

Phase 5.5.3 closes only when:

- the architecture gate is merged;
- executable finalists are implemented under isolated spike directories;
- Linux/Windows CI is green;
- all hard gates have evidence;
- ADR-0024 is Accepted with a named winner and explicit rejected-alternative rationale;
- the selected Shared Core contract boundary is documented;
- canonical `schemas/v1/` remains unchanged;
- a subsequent production implementation slice can start without reopening the technology-selection question unless an ADR revisit trigger occurs.
