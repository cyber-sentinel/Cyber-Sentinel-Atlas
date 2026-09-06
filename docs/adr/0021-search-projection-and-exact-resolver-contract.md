# ADR-0021 — Search Projection and Exact Resolver Contract

**Status:** Accepted
**Decision:** 2026-09-06 — approved by Atlas Architecture Authority

## Context

Phase 5.3 completed the Source & Ingestion Core and preserved the canonical identifiers, native identifiers, scoped context, aliases, lifecycle, applicability, source-backed claims, provenance, and relationship data required for deterministic retrieval.

ADR-0020 already requires exact identifier resolution, provider/namespace scoping, legacy discoverability, and numeric browse semantics while explicitly deferring search projection/index implementation to Phase 5.4.

Phase 5.4 therefore needs an engine-neutral contract that converts immutable canonical corpus data into a rebuildable search corpus without changing canonical identity semantics or prematurely selecting a storage/search engine.

## Decision

Atlas will introduce a **Search Projection Corpus (SPC)** as a derived, non-canonical corpus for Phase 5.4.

The SPC is rebuilt from a pinned canonical corpus and pinned registries. Search-specific values such as normalized tokens, exact lookup keys, scoped lookup keys, numeric sort values, lexical fields, filter facets, graph adjacency projections, and stage-local ranking features are projections only. They do not become new `AtlasRecord` families and do not modify `schemas/v1/`.

### Exact resolver precedence

The deterministic search pipeline uses this stage order:

```text
Exact Canonical / Native Identifier
    > Scoped Identifier
    > Exact Scoped Alias
    > Lexical Match
    > Bounded Graph Expansion
    > Semantic Retrieval (future, optional)
```

Semantic retrieval may never outrank a clear exact identifier match.

### Identifier scope and ambiguity

A native identifier is not globally unique unless its registry/scope proves uniqueness.

For a bare identifier such as `4688`:

- if exactly one registered identity exists in the active corpus, Atlas may resolve it directly;
- if multiple valid scoped identities exist, Atlas returns a deterministic disambiguation set;
- Atlas never selects an arbitrary winner based on recency, popularity, ingestion order, lexical score, or source rank.

Natural scoped forms such as `sysmon 1`, `windows 4688`, and `event id 4688` are first-class resolver inputs.

Exact resolution never uses fuzzy matching.

### Deterministic disambiguation

Ambiguous results use a stable total order:

1. platform;
2. product;
3. provider;
4. telemetry source/channel;
5. identifier type;
6. native value;
7. lifecycle;
8. canonical ID as final tie breaker.

The displayed result must include sufficient scope information for the analyst to distinguish candidates.

### Search projection contract

The projection build must bind to at least:

- `search_contract_version`;
- canonical corpus/build identifier;
- canonical corpus digest;
- canonical schema version;
- registry bundle version/digest;
- projection-profile version/digest;
- index adapter identifier/version when an engine-backed index is built.

The initial Phase 5.4 projection objects are:

- `SearchDocument`;
- `IdentifierProjection`;
- `AliasProjection`;
- `FilterProjection`;
- `EdgeProjection`.

These objects are non-canonical and rebuildable.

### Numeric browse

Numeric Event ID ordering is a derived search projection only when the identifier registry declares numeric semantics. The lossless native identifier remains a string in canonical data.

No `numeric_sort_value` or equivalent search-only field is added to canonical records.

### Query safety boundary

The public/core search interface accepts a typed internal query/request model. Raw user text is parsed and bounded before backend execution.

User-controlled text must never be concatenated directly into an engine query language, FTS expression, SQL fragment, regex, or backend DSL.

Initial Phase 5.4 safety bounds are:

- maximum query length: 512 Unicode scalar values;
- maximum parsed terms: 32;
- maximum structured filters: 16;
- default graph expansion depth: 1;
- hard graph expansion depth: 2.

These limits are runtime search controls and are not canonical model constraints.

### Engine neutrality

This ADR does **not** select a search/storage engine.

Phase 5.4.1 remains engine-neutral. A later implementation spike must compare at least:

1. SQLite + FTS5;
2. Tantivy.

The winning engine requires a separate Architecture Decision Record after benchmark evidence is reviewed.

## Acceptance requirements

Permanent acceptance coverage must include at minimum:

- `4688`;
- `Event ID 4688`;
- `windows 4688`;
- `sysmon 1`;
- ambiguous bare `1` across multiple providers;
- legacy `592`;
- `T1059`;
- `T1059.001`;
- `CreateAccessKey`;
- `EXECVE`;
- `exec_start`;
- `kubectl exec`;
- `FileAccessed`.

Synthetic collision fixtures are mandatory so ambiguity behavior is tested even when a current production-like corpus happens to contain only one matching native identifier.

## Consequences

- deterministic identity lookup is independent of search-engine scoring;
- canonical identity and lifecycle semantics remain owned by the Canonical Knowledge Model;
- search indexes can be rebuilt, migrated, replaced, or rolled back without mutating canonical truth;
- exact lookup and ambiguity behavior can be tested before selecting the production lexical engine;
- numeric browsing remains provider/source scoped;
- legacy telemetry remains first-class in search;
- engine-specific query syntax is kept behind adapters;
- Phase 5.4.1 can proceed without freezing the embedded database or Desktop stack;
- final search-engine selection remains a separate material architecture decision.

## Non-goals

This ADR does not authorize:

- modifying canonical `schemas/v1/` for search convenience;
- vector/semantic retrieval as an identity-resolution dependency;
- Grounded AI;
- signed content-pack runtime or key management;
- a daemon/service requirement for core offline search;
- Detection IR implementation;
- production search-engine selection.
