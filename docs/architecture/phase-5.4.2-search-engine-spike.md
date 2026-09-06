# Phase 5.4.2 — Search Engine Spike + Selection ADR

Status: **ACTIVE — BENCHMARK EVIDENCE REQUIRED BEFORE ENGINE FREEZE**

Baseline main SHA: `863b54d39cbe09c0f0c14de72856613e3480d092`

Phase 5.4.1 established the engine-neutral Search Projection Corpus, bounded query contract, exact/scoped resolver, deterministic disambiguation, alias stage, numeric browse projection, and permanent acceptance/security tests. Phase 5.4.2 compares the two mandatory embedded search candidates under equivalent declared conditions.

## Candidates

### SQLite + FTS5

Evaluation profile:

- embedded/in-process;
- single-file persistence candidate;
- B-tree exact/filter indexes plus FTS5 lexical index;
- no daemon/service lifecycle;
- future pack/runtime compatibility must consider atomic database replacement and schema migration.

### Tantivy

Evaluation profile:

- embedded/in-process Rust search library;
- dedicated index directory;
- BM25/full-text and fast-field capabilities;
- no daemon/service lifecycle;
- future pack/runtime compatibility must consider directory-level atomic replacement and index-format/version binding.

The spike harness uses the pinned Python Tantivy binding only for reproducible cross-platform benchmark evidence in the current Python-heavy repository. That binding is not a commitment to the final Shared Core language or API.

## Mandatory comparison dimensions

The selection record must compare:

1. exact resolver integration;
2. lexical correctness and deterministic tie handling;
3. structured provider/scope filtering;
4. numeric Event ID browse support;
5. index build time;
6. process-warm P50/P95/P99 latency;
7. index footprint;
8. offline/read-only operation;
9. Windows portability;
10. rebuild/corruption recovery model;
11. Phase 5.5 atomic replacement/rollback compatibility;
12. migration/version binding;
13. runtime/library footprint;
14. licensing;
15. integration risk with future Shared Core/Desktop candidates.

## Benchmark corpus

The benchmark starts with the Phase 5.4.1 acceptance projection and appends deterministic fixture-only scale records to reach the declared scale. Synthetic records never introduce additional native identifiers, so they cannot change exact-resolution acceptance semantics.

To avoid basing lexical/footprint conclusions on a nearly identical repeated-noise corpus, the scale records contain deterministic varied high-cardinality lexical material. A dedicated `benchmarkfanout` term is present on every fifth synthetic document. At the default 20,000-document scale this produces thousands of equal-score matches and forces each adapter to prove the Atlas total-order Top-K contract.

Default CI evidence:

- document count: 20,000;
- iterations per query case: 40;
- operating systems: Ubuntu latest and Windows latest GitHub-hosted runners;
- cache claim: process-warm repeated queries; OS page cache not flushed;
- output: immutable workflow artifact JSON with corpus/query/engine versions and result digest.

The 20,000-document corpus is an MVP-scale selection workload. It is not a guarantee for every future Atlas expansion domain. Material corpus-growth, ranking or footprint changes require renewed benchmark evidence before revisiting the accepted engine through a later ADR.

## Deterministic Top-K requirement

A backend may not return an arbitrary subset when more than `TOP_K` candidates share the cutoff relevance score.

The benchmark therefore requires:

- identical ordered output across repeated executions of every case;
- a high-fanout equal-score lexical case with an exact expected ordered result;
- canonical target ID as the final total-order tie breaker after relevance;
- fail-closed evidence if an adapter cannot establish deterministic candidate selection.

SQLite can express the total order directly in its query plan. The Tantivy spike adapter must not rely on `search(..., TOP_K)` followed by sorting only that backend-selected subset. The reference spike may use a bounded full-candidate collection to prove semantics; Phase 5.4.3 may replace it with a more efficient collector only if the deterministic result contract remains identical.

## Query safety

Both candidates are exercised through adapter operations rather than arbitrary backend query strings.

- caller text containing non-scalar Unicode surrogates is rejected;
- input is bounded to the accepted 512 Unicode scalar-value search limit before backend execution;
- lexical text is NFKC-normalized in the search layer only;
- at most 32 lexical terms are generated;
- SQLite uses bound SQL parameters and a generated FTS expression from tokenized terms;
- Tantivy uses programmatic `Query` objects and does not use its user-facing query parser;
- exact/filter values remain parameters/typed terms;
- benchmark code does not expose regex/wildcard/fuzzy syntax.

The dedicated Phase 5.4.2 workflow runs these permanent contract/security tests on both Linux and Windows before producing benchmark evidence.

## Selection rule

Performance is necessary but not sufficient. Architecture Authority should prefer the candidate that satisfies the deterministic/offline product contract with the lower combined deployment, migration, rollback, and integration risk.

A candidate is not selected merely because one CI runner reports the lowest latency. The final selection requires ADR-0022 to cite the benchmark runs/artifacts and explain trade-offs.

Index footprint must be interpreted as the complete artifact produced by each candidate adapter for the measured operations. SQLite includes the relational rows/indexes used for exact/filter/numeric operations as well as FTS5; Tantivy persists its dedicated stored/indexed search representation. This is therefore an operational artifact-footprint comparison, not a claim that the internal index structures are byte-for-byte equivalent.

## Boundaries

Phase 5.4.2 must not:

- change `schemas/v1/`;
- redefine Phase 5.4.1 identity/disambiguation semantics;
- implement semantic/vector search;
- implement Grounded AI;
- freeze the Windows Desktop stack;
- implement signed pack runtime or key management;
- implement Detection IR.

Successful completion produces an accepted engine-selection ADR and opens Phase 5.4.3 production exact/lexical core implementation.
