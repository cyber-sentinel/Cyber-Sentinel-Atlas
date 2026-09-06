# ADR-0022 — Deterministic Search Engine Selection

**Status:** Accepted — Architecture Authority approved 2026-09-06
**Decision scope:** Phase 5.4.2 → Phase 5.4.3
**Evidence run:** `34018323174`
**Evidence head:** `b7e110567f6345c70cbd455b97dba64481f84894`

## Context

Phase 5.4.1 froze the engine-neutral Search Projection Corpus, bounded query contract, exact/scoped identifier resolver, deterministic collision disambiguation, alias precedence and numeric browse semantics. Phase 5.4.2 must select an embedded deterministic/lexical search engine before the production Phase 5.4.3 implementation.

The accepted architecture requires at least SQLite + FTS5 and Tantivy to be evaluated on Linux and Windows. Raw user queries may not be passed to backend query parsers or interpolated into backend DSLs. Atlas also requires a deterministic total order whenever more candidates share a lexical score or numeric browse key than fit inside `TOP_K`.

## Candidates

### SQLite + FTS5

- embedded/in-process;
- exact/filter/catalog data can share relational B-tree indexes with lexical FTS5 indexes;
- single database-file deployment model is compatible with local/offline operation;
- no daemon lifecycle;
- SQLite core is public domain according to SQLite's official documentation;
- FTS5 is part of SQLite's official full-text search functionality.

Official references:

- https://sqlite.org/fts5.html
- https://sqlite.org/about.html
- https://sqlite.org/copyright.html

### Tantivy

- embedded/in-process Rust search library;
- dedicated full-text index with BM25 and fast fields;
- no daemon lifecycle;
- materially smaller benchmark search artifact;
- MIT licensed according to the official Tantivy repository;
- introduces a separate persisted/index format if Atlas later uses relational storage for catalog/filter/graph-adjacent state.

Official references:

- https://github.com/quickwit-oss/tantivy
- https://tantivy-py.readthedocs.io/en/stable/

The Python binding used in the spike is evidence tooling only and is not a commitment to the eventual Shared Core language.

## Hardened Reproducible Evidence

Evidence summary is committed at:

`benchmarks/search/phase542/evidence/selection-summary.json`

The hardened benchmark used:

- 20,000 documents;
- Phase 5.4.1 acceptance projection plus deterministic fixture-only scale records;
- varied high-cardinality synthetic lexical material rather than nearly identical repeated noise;
- a dedicated high-fanout equal-score case matching every fifth synthetic document;
- 40 iterations per query case;
- Linux and Windows GitHub-hosted runners;
- process-warm queries; OS page cache not explicitly flushed;
- exact lookup, lexical retrieval, provider filtering, numeric Event ID browse and deterministic high-fanout Top-K;
- permanent Unicode/query-bound/security tests before benchmark execution;
- explicit permanent tests proving deterministic numeric browse at a duplicate-value Top-K cutoff.

Benchmark corpus digest:

`sha256-5cb1431b21eb9519f5e590ee5e7f2eb0720cb662fc70b6b2baf54996f0bc8f04`

Query-suite version/digest:

`1.1.0` / `sha256-45a0f9b5837dce8803000072ba3e628f8229c6c83d5d2433ead2592c8a3355ae`

Cross-platform evidence run: `34018323174`.

- Linux artifact `9984630110`, digest `sha256:e5d8609f64728348ae91f9a38728921071e1bb223f1a8686b38e5268cd9c40f6`;
- Windows artifact `9984633555`, digest `sha256:e6b027575862dd2dfb0405133892d1c64392bdca6b6b47aa44f7585b10050cc9`.

Both candidates passed correctness, repeated-order determinism, lexical cutoff-tie behavior, numeric browse cutoff-tie behavior and the permanent Phase 5.4.2 security tests on both operating systems.

### Linux evidence

| Dimension | SQLite + FTS5 | Tantivy |
|---|---:|---:|
| Build time | 0.472286 s | 0.268639 s |
| Search artifact size | 18,739,200 B | 2,745,183 B |
| Exact 4688 P95 | 0.0196 ms | 0.0158 ms |
| PowerShell lexical P95 | 0.0939 ms | 0.0477 ms |
| Process-creation lexical P95 | 0.0918 ms | 0.0691 ms |
| Provider-filtered lexical P95 | 0.0746 ms | 0.0622 ms |
| High-fanout deterministic Top-K P95 | 12.3888 ms | 28.2506 ms |
| Numeric Event-ID browse P95 | 0.0138 ms | 0.1700 ms |

### Windows evidence

| Dimension | SQLite + FTS5 | Tantivy |
|---|---:|---:|
| Build time | 0.599467 s | 0.623498 s |
| Search artifact size | 18,739,200 B | 2,892,936 B |
| Exact 4688 P95 | 0.0314 ms | 0.0267 ms |
| PowerShell lexical P95 | 0.1120 ms | 0.0248 ms |
| Process-creation lexical P95 | 0.1137 ms | 0.0624 ms |
| Provider-filtered lexical P95 | 0.1090 ms | 0.0429 ms |
| High-fanout deterministic Top-K P95 | 15.8578 ms | 34.8627 ms |
| Numeric Event-ID browse P95 | 0.0592 ms | 0.1964 ms |

Both candidates remain comfortably inside Atlas MVP targets of <100 ms for exact local resolution and <300 ms for normal local lexical search at the tested scale.

Tantivy remains faster on most sparse lexical cases and produces a search artifact approximately 6.5–6.8x smaller. SQLite is faster for provider-scoped numeric browsing and, under the reference implementation that proves Atlas' total-order semantics, faster for the high-fanout equal-score case on both operating systems.

The high-fanout Tantivy number must be interpreted correctly: the spike intentionally collects the bounded candidate set before applying the final Atlas tie-break rather than trusting a backend-selected Top-K subset. Phase 5.4.3 could implement a more efficient Tantivy collector if Tantivy were selected, but it would still need to prove identical deterministic output.

Likewise, the Tantivy numeric-browse reference path collects the bounded matching set before applying `(numeric_event_id, target_id)` ordering so duplicate numeric values cannot produce an arbitrary cutoff subset. This is a correctness reference implementation, not a claim that a production Tantivy collector could not be optimized.

## Architecture Evaluation

### Exact resolver integration

**Equivalent on correctness; SQLite advantage in integration simplicity.**

Exact identifier resolution remains governed by the Phase 5.4.1 resolver contract. SQLite can implement exact identifiers, scope filters and deterministic ordering directly through B-tree indexes in the same embedded search database used by FTS5. Tantivy supports exact term queries, but those operations remain part of a dedicated search-index model.

### Lexical search

**Tantivy advantage for sparse lexical latency and footprint; no MVP blocker for SQLite.**

Tantivy is generally faster on sparse lexical cases and its measured artifact is materially smaller. SQLite FTS5 nevertheless remains orders of magnitude inside the product latency budget at the declared MVP scale.

The footprint result is an operational artifact comparison, not a byte-for-byte internal-index comparison. SQLite's measured file contains relational rows/indexes required for exact/filter/numeric operations plus FTS5, while Tantivy persists its dedicated stored/indexed search representation.

### Deterministic Top-K under broad equal-score matches

**SQLite advantage in the current deterministic contract.**

The earlier spike could have accepted an arbitrary backend-selected Tantivy subset when more than `TOP_K` documents shared the cutoff score. The hardened spike removes that ambiguity and adds an exact expected result for thousands of equal-score matches.

SQLite expresses relevance plus canonical target-ID tie ordering directly in one query. The Tantivy reference adapter can prove the same semantics, but the straightforward bounded implementation requires a larger candidate collection before final truncation. This remains inside the MVP budget but adds implementation complexity that SQLite does not need.

### Structured filters and numeric catalog browse

**SQLite advantage.**

Atlas requires deterministic provider catalogs, filters, lifecycle/version browsing and numeric Event-ID ordering. These are relational/indexed-data operations naturally supported by SQLite without a second query/index model. The hardened benchmark again showed lower numeric browse latency for SQLite on both operating systems.

The final spike additionally proves that duplicate numeric values at the `TOP_K` cutoff use canonical target ID as the deterministic secondary key. SQLite expresses this directly with `ORDER BY numeric_event_id, target_id`; the Tantivy reference adapter requires explicit candidate collection and Atlas-side ordering to prove equivalent semantics.

### Offline deployment and Windows portability

**Both pass; SQLite operationally simpler.**

Both candidates passed Linux and Windows evidence and are in-process. SQLite has a single-file operational model. Tantivy requires a dedicated index directory and Rust library/binding integration in the eventual runtime.

### Phase 5.5 atomic replacement / rollback

**SQLite advantage, but not exclusive capability.**

A version-bound immutable SQLite search database can be built off-line, verified and activated as one artifact, mapping naturally to Last Known Good and atomic replacement. Tantivy can also be packaged and replaced at a directory/package boundary; this is viable but carries more persisted files and explicit index-format compatibility handling.

### Corruption recovery and rebuild

**Equivalent in principle because the Search Projection Corpus remains authoritative derived input.**

Neither search artifact is canonical truth. The Phase 5.4.3 implementation must fail closed on stale/corrupt metadata and rebuild from a verified Search Projection Corpus. SQLite's single-file boundary simplifies quarantine/replacement; Tantivy's directory index is likewise rebuildable.

### Schema evolution and migration

**SQLite advantage for current scope.**

SQLite supports explicit relational schema/version migrations for exact/filter/catalog structures and FTS schema evolution inside one derived database boundary. Tantivy index-format/schema changes are also manageable, but require a dedicated index compatibility path in addition to any future relational/graph state store.

### Shared Core / Desktop integration risk

**SQLite advantage for the current product sequence.**

Atlas still has an open broader embedded-storage decision. Its Shared Core/Desktop requirements nevertheless include portable local storage, structured filtering, catalog browsing, graph-adjacent projections and offline replacement. Selecting SQLite + FTS5 for Phase 5.4.3 avoids committing Atlas to a second dedicated persisted search format before broader Shared Core storage architecture is frozen.

This ADR does **not** freeze the final canonical-content database, graph persistence model, Desktop framework or implementation language.

## Decision

**Select SQLite + FTS5 as the Phase 5.4 production deterministic/lexical search engine.**

Use:

- B-tree indexes for exact identifiers, scope/filter facets, lifecycle/version filters and numeric Event-ID catalog ordering;
- FTS5 for bounded lexical retrieval over derived SearchDocument fields;
- deterministic Atlas tie-break logic with canonical target ID as the final total-order key;
- explicit `(numeric_event_id, target_id)` ordering for numeric browse;
- an immutable/version-bound derived search database that can always be rebuilt from the Search Projection Corpus;
- fail-closed index/corpus metadata validation before activation.

Retain Tantivy as a documented alternative if future corpus scale, ranking requirements, index footprint or benchmark evidence shows that SQLite FTS5 no longer satisfies product constraints.

## Why SQLite Is Selected Despite Tantivy's Sparse-Lexical and Footprint Advantages

The measured Tantivy advantages are real and must not be discarded: it is generally faster for sparse lexical search and materially smaller on disk.

However, the evidence does not show a performance requirement that SQLite fails. SQLite remains comfortably within MVP latency targets while materially simplifying the operations Atlas must perform together: exact resolution, structured filters, provider catalogs, numeric browsing, deterministic ties, local/offline packaging and rollback.

Selecting Tantivy now would introduce a separate search persistence model primarily to obtain performance headroom that Atlas does not currently need. That trade is not justified at the Phase 5.4 MVP boundary.

## Revisit Triggers

The engine decision must be reopened through a new ADR with reproducible evidence if any of the following occurs:

- declared production corpus scale materially exceeds the validated MVP profile and SQLite approaches the latency budget;
- the search artifact becomes a material content-pack size or distribution constraint;
- ranking/query features required by the product cannot be expressed safely or efficiently through FTS5;
- incremental/rebuild cost becomes operationally significant;
- final Shared Core architecture makes a native Tantivy integration materially simpler than maintaining SQLite;
- measured concurrency or read-pattern requirements exceed the selected SQLite profile.

No silent engine drift is permitted.

## Security Requirements Preserved

The implementation following this ADR must:

- reject malformed/non-scalar Unicode search input;
- enforce the accepted 512-scalar query bound and 32-term lexical bound before backend execution;
- never concatenate raw user text into SQL;
- never pass raw user text to an FTS query parser;
- tokenize and bound lexical terms before FTS expression construction;
- pass generated FTS expressions as bound parameters;
- bind all structured filter values as SQL parameters;
- preserve exact/scoped resolution before lexical retrieval;
- guarantee deterministic Top-K selection under relevance-score ties;
- guarantee deterministic numeric browse under duplicate numeric values and cutoff ties;
- keep semantic/vector retrieval outside this decision;
- treat the search database as disposable derived state, never canonical truth.

## Consequences

- Phase 5.4.3 implements the production exact/filter/numeric/FTS5 core against the Phase 5.4.1 contracts;
- SQLite search schema/version becomes an explicit derived-index compatibility contract;
- deterministic rebuild/corruption recovery tests become mandatory;
- Phase 5.5 can package/replace a single derived search database artifact;
- Tantivy remains benchmarked but non-production;
- `schemas/v1/` remains unchanged;
- the Search Projection Corpus remains engine-neutral and can support another adapter later.

## Decision Gate

Accepted by Architecture Authority on 2026-09-06. SQLite + FTS5 is frozen for the Phase 5.4.3 production search implementation. Any future engine change requires a new ADR and reproducible benchmark evidence under the documented revisit triggers.
