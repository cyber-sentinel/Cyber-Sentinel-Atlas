# Phase 5.4.3 — Production Exact + Lexical Search Core

Status: **IMPLEMENTATION SLICE — ADR-0022 ACCEPTED**

Architecture baseline:

- `docs/architecture/phase-5.4-deterministic-search-core.md`;
- ADR-0021 — Search Projection and Exact Resolver Contract;
- ADR-0022 — SQLite + FTS5 selected for production deterministic/lexical search.

## Purpose

Phase 5.4.3 replaces the Phase 5.4.1 reference lexical containment path with the selected embedded production search engine while preserving the already-frozen identity semantics.

The SQLite database created in this slice is **derived, disposable search state**. It is not a Canonical `AtlasRecord`, does not modify `schemas/v1/`, and can always be rebuilt from a verified Search Projection Corpus (SPC).

## Production index boundary

The production index is a single SQLite database file using:

- B-tree-backed relational tables for exact identifiers, aliases, facets, lifecycle/scope data, and numeric identifiers;
- FTS5 for bounded lexical retrieval;
- immutable/version-bound metadata binding the index to its source SPC and projection inputs.

Index schema version: `1.0.0`.

Adapter identity:

- `index_adapter_id = sqlite-fts5`;
- `index_adapter_version = 1.0.0`.

The persisted metadata binds at minimum to:

- search-contract version;
- SPC bundle digest;
- canonical corpus ID/digest;
- canonical schema version;
- registry bundle version/digest;
- projection profile version/digest;
- adapter ID/version;
- SQLite build version;
- projected document/identifier/alias/filter counts;
- deterministic manifest digest.

No wall-clock build timestamp is part of the logical manifest, so equivalent inputs produce equivalent logical bindings.

## Build and activation model

`tools/search/sqlite_search.py` implements the production index builder and verified read-only runtime.

Build behavior:

1. validate the SPC bundle and every `SearchDocument` projection digest;
2. reject duplicate/missing projection targets or incomplete build binding;
3. build into a unique sibling temporary file;
4. use `journal_mode=DELETE`, `synchronous=FULL`, and foreign-key enforcement while building;
5. run SQLite `quick_check` before publication;
6. fsync the completed file;
7. publish with `os.replace()` only after successful validation;
8. clean temporary state on failure.

A failed rebuild must not replace the previous good index.

Runtime activation:

1. require the index path to exist;
2. open with SQLite URI `mode=ro&immutable=1`;
3. enable `query_only`;
4. run `quick_check`;
5. verify required tables;
6. verify index schema/adapter/search-contract versions;
7. verify the manifest digest;
8. when an expected SPC is supplied, verify every source-binding field before serving queries.

Any corruption, stale binding, wrong adapter/version, or incomplete schema fails closed.

## Retrieval precedence

The production runtime preserves the accepted stage order:

```text
Exact Canonical Identifier
    ↓
Exact Native Identifier
    ↓
Scoped Native Identifier
    ↓
Exact Scoped Alias
    ↓
SQLite FTS5 Lexical Retrieval
```

Exact identity resolution remains registry-aware and is never delegated to FTS5.

Bare scoped identifier collisions continue to return deterministic disambiguation; SQLite/FTS ranking never chooses an identity winner.

## Structured filtering

Structured filters and natural scope hints are compiled into fixed SQL templates using the derived facet table.

- facet keys originate only from the bounded typed query parser;
- facet values are normalized in the search layer and always passed as SQL parameters;
- raw caller input is never interpolated into a SQL identifier or SQL literal;
- unavailable facet values simply produce no candidates rather than silently broadening the query.

This design keeps provider/platform/product/channel/type/lifecycle and future projected facets engine-local without adding search-only fields to canonical records.

## FTS5 safety boundary

Raw caller text is never passed directly to `MATCH`.

The lexical path:

1. executes the accepted bounded query parser;
2. removes structured filters from lexical text;
3. NFKC-normalizes search-layer text;
4. tokenizes with a restricted Unicode word-token regex;
5. enforces the 32-token lexical bound independently of parsed-term count;
6. quotes/escapes only those generated tokens;
7. passes the generated FTS expression as a bound parameter.

Wildcard, operator, quote, and FTS syntax supplied by a caller therefore remain data and cannot become backend query syntax.

## Deterministic ranking

FTS5 lexical results use:

1. FTS5 BM25 relevance;
2. exact normalized-title equality as the next deterministic boost;
3. normalized title;
4. canonical target ID as the final total-order tie breaker.

The SQL total order is applied before `LIMIT`, so equal-score cutoff ties do not permit an arbitrary backend-selected subset.

Raw floating-point BM25 values are not exposed as a cross-engine public contract.

Exact/disambiguation result ordering continues to mirror the accepted Phase 5.4.1 stable key using Python NFKC/casefold normalization rather than SQLite locale/collation behavior.

## Numeric identifiers

The production schema persists derived numeric values only from SPC `IdentifierProjection` rows that explicitly declare numeric semantics.

Numeric browse uses:

```text
derived_numeric_value ASC,
canonical target ID ASC
```

This method is available to the core in 5.4.3; provider/source catalog product behavior is completed in Phase 5.4.4.

## Search result contract

The existing `schemas/search/v1/search-result.schema.json` remains search-contract version `1.0.0` and gains the additive production `lexical` match stage while retaining `lexical_reference` for the Phase 5.4.1 reference implementation.

No canonical schema changes are authorized by this slice.

## Permanent validation

Phase 5.4.3 adds:

- `tools/search/validate_phase543.py`;
- `tests/phase54/test_phase543_sqlite_search.py`;
- `.github/workflows/phase543-production-search-core.yml`.

Validation covers:

- exact/scoped/native/alias equivalence with the frozen reference resolver;
- production FTS5 lexical retrieval;
- structured filter behavior;
- case-sensitive native identifiers without identity collapse;
- query/term/result-limit bounds;
- injection-like caller text treated as data;
- read-only/query-only runtime behavior;
- SPC and SearchDocument digest enforcement;
- stale metadata rejection;
- corrupt database rejection;
- failed rebuild preservation of the Last Known Good file;
- deterministic logical rebuild behavior;
- numeric Event ID ordering;
- SearchResult JSON Schema validation;
- Linux and Windows CI execution.

The CI workflow also builds a fixture-only SQLite index and uploads the index manifest/query evidence so cross-platform activation remains inspectable.

## Explicit non-goals

Phase 5.4.3 does **not**:

- change canonical `schemas/v1/`;
- add vector/semantic retrieval;
- add Grounded AI;
- select a graph database;
- implement graph expansion;
- implement signed content packs, pack installation, signing, or rollback orchestration;
- freeze the Desktop/Web framework or Shared Core implementation language;
- implement Detection IR;
- make the fixture-only acceptance corpus a completeness claim.

## Exit criteria

Phase 5.4.3 is complete when:

- the production SQLite index builder/runtime is merged;
- exact resolution remains behaviorally equivalent to Phase 5.4.1;
- lexical retrieval is FTS5-backed and bounded;
- stale/corrupt/misbound indexes fail closed;
- failed rebuilds preserve the previous good index;
- permanent Linux/Windows CI is green;
- no canonical schema changes occur.

Completion opens Phase 5.4.4 — Catalog, Graph Pivots, Benchmarks and Phase 5.4 closure.
