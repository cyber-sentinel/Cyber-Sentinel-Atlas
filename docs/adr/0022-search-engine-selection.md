# ADR-0022 — Deterministic Search Engine Selection

**Status:** Proposed — Architecture Authority decision required
**Decision scope:** Phase 5.4.2 → Phase 5.4.3
**Evidence run:** `34013740514`
**Evidence head:** `1ff6f0b32d9500523c01d0da7e97859995a48f96`

## Context

Phase 5.4.1 froze the engine-neutral Search Projection Corpus, bounded query contract, exact/scoped identifier resolver, deterministic collision disambiguation, alias precedence and numeric browse semantics. Phase 5.4.2 must select an embedded deterministic/lexical search engine before the production Phase 5.4.3 implementation.

The accepted architecture requires at least SQLite + FTS5 and Tantivy to be evaluated on Linux and Windows. Raw user queries may not be passed to backend query parsers or interpolated into backend DSLs.

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
- substantially smaller benchmark index in the Phase 5.4.2 evidence;
- MIT licensed according to the official Tantivy repository;
- introduces a second persisted/index format if Atlas later uses a relational/graph store for non-search state.

Official references:

- https://github.com/quickwit-oss/tantivy
- https://tantivy-py.readthedocs.io/en/stable/

The Python binding used in the spike is evidence tooling only and is not a commitment to the eventual Shared Core language.

## Reproducible Evidence

Evidence summary is committed at:

`benchmarks/search/phase542/evidence/selection-summary.json`

The benchmark used:

- 20,000 documents;
- Phase 5.4.1 acceptance projection plus deterministic fixture-only scale records;
- 40 iterations per query case;
- Linux and Windows GitHub-hosted runners;
- process-warm queries; OS page cache not explicitly flushed;
- exact lookup, lexical retrieval, provider filtering and numeric Event ID browse.

The benchmark corpus digest was:

`sha256-bf2e69c262b94b0ddecd71e4c5b041a6b83e33aa2fd9e437e1d87475646d8f08`

Query-suite digest:

`sha256-0b21343d840f8dd0cfec4e3add58e732f6dddb29a3f4ccac365b9bfbabe75167`

### Linux evidence

| Dimension | SQLite + FTS5 | Tantivy |
|---|---:|---:|
| Build time | 0.212216 s | 0.289738 s |
| Index size | 14,041,088 B | 1,824,178 B |
| Exact 4688 P95 | 0.0274 ms | 0.0261 ms |
| PowerShell lexical P95 | 0.0927 ms | 0.0370 ms |
| Process-creation lexical P95 | 0.1416 ms | 0.0961 ms |
| Provider-filtered lexical P95 | 0.1010 ms | 0.0984 ms |
| Numeric Event-ID browse P95 | 0.0203 ms | 0.2993 ms |

### Windows evidence

| Dimension | SQLite + FTS5 | Tantivy |
|---|---:|---:|
| Build time | 0.736707 s | 0.460229 s |
| Index size | 14,041,088 B | 1,911,052 B |
| Exact 4688 P95 | 0.0369 ms | 0.0177 ms |
| PowerShell lexical P95 | 0.0870 ms | 0.0412 ms |
| Process-creation lexical P95 | 0.0771 ms | 0.0519 ms |
| Provider-filtered lexical P95 | 0.1019 ms | 0.0546 ms |
| Numeric Event-ID browse P95 | 0.0336 ms | 0.1547 ms |

Both candidates passed the golden-result correctness suite on both operating systems and are far below Atlas MVP latency targets of <100 ms for exact local resolution and <300 ms for normal local lexical search.

Tantivy is generally faster for lexical retrieval and produced an index roughly 7x smaller in this benchmark. SQLite is substantially faster for the provider-scoped numeric browse case and was faster to build on the Linux runner. Neither candidate has a performance blocker at the tested MVP scale.

## Architecture Evaluation

### Exact resolver integration

**Equivalent / SQLite advantage in operational simplicity.**

Exact identifier resolution remains governed by the Phase 5.4.1 resolver contract. SQLite can implement exact identifiers, scope filters and deterministic ordering directly through B-tree indexes in the same embedded database used by FTS5. Tantivy also supports exact term queries, but those operations remain part of a dedicated search index.

### Lexical search

**Tantivy performance advantage.**

Tantivy was consistently faster on the measured lexical cases and has a materially smaller search index. SQLite FTS5 nevertheless remained multiple orders of magnitude inside the product latency budget.

### Structured filters and numeric catalog browse

**SQLite advantage.**

The product requires deterministic provider catalogs, filters, lifecycle/version browsing and numeric Event-ID ordering. These are relational/indexed-data operations naturally supported by SQLite without a second query/index model. The benchmark also showed lower numeric browse latency for SQLite on both operating systems.

### Offline deployment and Windows portability

**Equivalent at the functional gate.**

Both candidates passed on Linux and Windows and are in-process. SQLite has the simpler single-file operational model and is already widely available as an embedded library. Tantivy requires a dedicated index directory and Rust library/binding integration in the eventual runtime.

### Phase 5.5 atomic replacement / rollback

**SQLite advantage.**

A version-bound, immutable search database can be built off-line and activated by replacing a single validated database artifact. This maps cleanly to the Phase 5.5 Last Known Good / atomic-install / rollback model. Tantivy can also be replaced atomically at a directory/package boundary, but introduces more files and explicit index-format compatibility management.

### Shared Core / Desktop integration risk

**SQLite advantage for the current product sequence.**

Atlas still has an open embedded-database decision, but its Desktop/Shared Core requirements include portable local storage, structured filtering, catalog browsing, graph-adjacent projections and offline replacement. Selecting SQLite + FTS5 for Phase 5.4.3 avoids committing Atlas to a separate dedicated full-text persistence layer before the broader Shared Core storage decision is made.

This ADR does **not** freeze the final canonical-content database or Desktop technology stack. It selects the Phase 5.4 production search/index implementation only.

## Proposed Decision

**Select SQLite + FTS5 as the Phase 5.4 production deterministic/lexical search engine.**

Use:

- B-tree indexes for exact identifiers, scope/filter facets, lifecycle/version filters and numeric Event-ID catalog ordering;
- FTS5 for bounded lexical retrieval over derived SearchDocument fields;
- deterministic Atlas tie-break logic outside backend-dependent score ordering;
- an immutable/version-bound derived search database that can always be rebuilt from the Search Projection Corpus.

Retain Tantivy as a documented alternative if future corpus scale, ranking requirements, index footprint or benchmark evidence shows that SQLite FTS5 no longer meets Atlas performance/footprint requirements.

## Why Tantivy Is Not Proposed Despite Better Lexical Numbers

The benchmark does not show a performance need for Tantivy at the declared MVP scale. Choosing Tantivy now would add a separate search-index format/runtime integration before Atlas has frozen its Shared Core storage architecture. The observed lexical advantage therefore does not currently outweigh deployment, migration, rollback and cross-feature integration simplicity.

The selection should be revisited only through a new ADR with reproducible evidence; it must not drift silently.

## Security Requirements Preserved

The implementation following this ADR must:

- never concatenate raw user text into SQL;
- never pass raw user text to an FTS query parser;
- tokenize and bound lexical terms before FTS expression construction;
- pass generated FTS expressions as bound parameters;
- bind all structured filter values as SQL parameters;
- enforce query-size/filter/depth limits before backend execution;
- preserve exact/scoped resolution before lexical retrieval;
- keep semantic/vector retrieval outside this decision;
- treat the search database as disposable derived state, never canonical truth.

## Consequences If Accepted

- Phase 5.4.3 implements the production exact/filter/numeric/FTS5 core against the Phase 5.4.1 contracts;
- SQLite search schema/version becomes an explicit derived-index compatibility contract;
- deterministic rebuild/corruption recovery tests become mandatory;
- Phase 5.5 can package/replace a single derived search database artifact;
- Tantivy remains benchmarked but non-production;
- `schemas/v1/` remains unchanged;
- the Search Projection Corpus remains engine-neutral and can support another adapter later.

## Decision Gate

This ADR remains **Proposed** until Architecture Authority explicitly accepts the engine selection. No Phase 5.4.3 production engine implementation may treat SQLite + FTS5 as frozen while this ADR remains Proposed.
