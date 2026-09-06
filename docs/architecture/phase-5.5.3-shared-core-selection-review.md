# Phase 5.5.3 — Shared Core Selection Review

Status: **EVIDENCE COMPLETE / PROPOSED DECISION — GO / ARCHITECTURE AUTHORITY PENDING**

This review closes the executable evidence portion of Phase 5.5.3. It does not itself accept ADR-0024 or authorize merge to `main`.

## Evidence boundary

The executable evidence is bound to branch head `8ff9e687a23b280ccb8e957ffc55555b4288199c` and GitHub Actions run `34039331139`.

- Linux and Windows finalist jobs both completed successfully at the workflow level.
- Go passed G-SC1 through G-SC8 on both Linux and Windows.
- Python control passed G-SC1 through G-SC8 on both Linux and Windows and remains the semantic oracle.
- Rust is hard-gate ineligible: Linux did not prove G-SC5/G-SC6/G-SC7; the Windows path did not produce complete runnable candidate evidence and is recorded as ineligible.
- Canonical `schemas/v1/` remained unchanged.

Evidence artifacts:

| OS | Artifact ID | Artifact digest |
| --- | ---: | --- |
| Linux | `9991212307` | `sha256:94b6fa7c0a812ffad4c05e6467fc3d61c413ea29949713e167baaa34e3d9b596` |
| Windows | `9991210708` | `sha256:a9c2428c52a7a7a82fd93c832fe7e5c4f7becf7265b981629a8d3843a4cb2219` |

Machine-readable aggregation is committed at `benchmarks/shared-core/phase553/selection-summary.json`.

## Decision review

### Eligible candidates

| Candidate | Linux | Windows | Weighted total | Review result |
| --- | --- | --- | ---: | --- |
| Go | G-SC1..G-SC8 pass | G-SC1..G-SC8 pass | **96** | **proposed winner** |
| Python control | G-SC1..G-SC8 pass | G-SC1..G-SC8 pass | 85 | retain as semantic/control oracle |
| Rust | mandatory trust/runtime gates incomplete | complete runnable candidate evidence absent | not ranked | disqualified by hard-gate policy |

### Go production baseline demonstrated by the spike

- `go1.25.0` toolchain in the evidence run;
- `github.com/theupdateframework/go-tuf/v2 v2.4.2`;
- `modernc.org/sqlite v1.58.0`;
- normalized module graph using `golang.org/x/text v0.36.0`;
- SQLite `3.53.4` with successful FTS5 workload on Linux and Windows;
- no CGo dependency for the selected SQLite path;
- deterministic exact-before-lexical resolver parity;
- safe bounded query parsing, NFKC + full casefold behavior, parameterized SQL and bounded FTS expression construction;
- high-fanout deterministic lexical ordering and duplicate numeric cutoff ordering;
- local-only TUF verification against Atlas-owned adversarial fixtures;
- durable highest-seen state and trusted-time guards;
- Last Known Good rollback after post-activation health failure;
- Linux durable replacement with `rename(2)+directory-fsync`;
- Windows durable replacement with `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`.

Measured search latency remained far within existing MVP gates:

| OS | Exact P95 | Lexical P95 | Compiled Go artifact |
| --- | ---: | ---: | ---: |
| Linux | `0.123895 ms` | `0.378843 ms` | `19,023,793` bytes |
| Windows | `1.5867 ms` | `1.521 ms` | `19,431,424` bytes |

These figures characterize the controlled Phase 5.5.3 fixture and CI environment; they are not universal throughput guarantees.

## Serialization review

The existing Atlas deterministic JSON protocol profile is not generally byte-equivalent to RFC 8785/JCS. Therefore Phase 5.5.3 proposes **no digest migration**.

- Atlas ordering contrast digest: `sha256-86f7643502ce36621ae93769d7af762ff9c2f90e8c207fcb36f38c2cc6650c72`.
- JCS ordering contrast digest: `sha256-e809e2d586f904340931323f0da13a22ddd4c10e5ead816b900f6d5c6bcd3e9f`.

The existing Atlas serialization vectors remain the protocol conformance boundary. Any future serialization migration requires its own accepted ADR and compatibility/migration evidence.

## Proposed Shared Core boundary

If ADR-0024 is accepted, Go owns the production implementation of the **Shared Core**, while accepted contracts remain authoritative and language-neutral.

```text
Verified Atlas Pack / Canonical + SPC
              |
              v
     +---------------------+
     |  Go Shared Core     |
     |---------------------|
     | canonical read      |
     | exact/FTS5 search   |
     | bounded graph read  |
     | TUF verification    |
     | install/state/LKG   |
     | offline safeguards  |
     +---------------------+
              |
       stable local boundary
              |
    +---------+----------+----------------+
    |                    |                |
Windows Desktop       atlas CLI       later API/Web adapters
```

The stable local boundary is intentionally **not** frozen here as a language ABI, FFI mechanism, IPC transport or UI framework. The production implementation slice must define that interface with versioning and fail-closed error semantics. This avoids coupling the Desktop choice to Go internals and preserves later CLI/API/Web reuse.

## Non-decisions

Selecting Go for the Shared Core does not choose:

- Tauri, Electron, .NET desktop UI, React or another UI framework;
- a graph database or broader application persistence;
- HSM/KMS/signing provider or signing ceremony;
- application updater or remote distribution/CDN design;
- Detection IR;
- semantic/vector retrieval;
- Grounded AI runtime.

## Production risks carried forward

1. The Go binary is materially larger than the Linux Rust spike binary. Current size is acceptable for the MVP, but footprint remains a measured release attribute.
2. `modernc.org/sqlite` and CPython's SQLite build are not assumed byte/build-equivalent. Cross-language contract fixtures, not implementation details, remain the authority.
3. `go-tuf` and the SQLite dependency graph create a supply-chain surface that requires committed locks, SBOM generation, vulnerability review and clean-build verification in production CI.
4. Atlas deterministic JSON is a custom frozen protocol profile. Its implementation must be centralized and guarded by fixed vectors to prevent cross-language digest drift.
5. Windows durable replacement must continue to be tested against real application state directories and fail closed on filesystem/AV/portable-media interference.
6. The Desktop integration boundary remains open. The next slice must avoid a fragile language-ABI dependency when a stable local process/API contract provides safer reuse and versioning.

## Revisit triggers

Reopen the Shared Core technology ADR if a mandatory conformance property cannot be preserved, the selected TUF profile becomes insufficient, Windows integration becomes materially infeasible, measured scale invalidates assumptions, future interfaces cannot reuse the boundary safely, or a critical dependency becomes unmaintained/unmitigable.

## Architecture review conclusion

The evidence supports **Go** as the Phase 5.5.3 proposed production Shared Core winner. The proposal is evidence-driven: Go is the only non-control executable finalist that passed every mandatory gate on both target operating systems and it ranked first among eligible candidates.

ADR-0024 remains **Proposed** until explicit Architecture Authority approval. Merge to `main` remains a separate material action and must use the normal Merge Commit governance path.
