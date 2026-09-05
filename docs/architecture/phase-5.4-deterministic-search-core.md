# Phase 5.4 — Deterministic Search Core

Status: **PROPOSED — ARCHITECTURE GATE**

Baseline main SHA: `dc1062718951034fdf4ef6c6adc152eb10ed5445`

Phase 5.4 turns the canonical knowledge corpus and the lossless identifier/context metadata preserved by Phase 5.3 into a deterministic, offline-first search capability. It must return the correct entity before attempting a clever answer.

This phase does **not** select or implement semantic/vector retrieval, Grounded AI, the signed content-pack runtime, or a final Desktop/Web stack.

## 1. Architectural invariants

The following rules are mandatory:

1. Exact identifier resolution precedes alias, lexical, graph-expansion, and future semantic retrieval.
2. A native identifier is never globally unique unless its registry/scope proves that it is.
3. A bare identifier with multiple valid scoped matches returns a deterministic disambiguation set; Atlas never chooses an arbitrary winner.
4. Search projections are derived/rebuildable artifacts and are not new Canonical `AtlasRecord` families.
5. Canonical `schemas/v1/` remains unchanged by Phase 5.4 unless a separately approved architecture issue requires a model change.
6. Legacy, deprecated, superseded, and retired telemetry remains searchable and browseable.
7. Numeric sorting is a search projection only and is generated only when the identifier registry declares numeric semantics.
8. Raw user search text is never passed directly into an engine-specific query parser or query DSL.
9. Core search remains fully usable offline.
10. Search-engine selection remains open until the Phase 5.4 engine spike produces benchmark evidence and a dedicated ADR.

## 2. Retrieval pipeline

```text
User Query
    ↓
Bounded Query Intake
    ↓
Query Normalization + Scope Parsing
    ↓
Exact Resolver
    ├── Canonical ID
    ├── Native Identifier
    └── Scoped Native Identifier
    ↓
Deterministic Disambiguation
    ↓
Scoped Alias Resolver
    ↓
Lexical Retrieval
    ↓
Structured Filters / Catalog Constraints
    ↓
Bounded Graph Expansion
    ↓
Deterministic Result Composition
```

Future semantic retrieval may be appended after lexical/graph stages, but it may never outrank a clear exact match.

## 3. Search Projection Corpus

Phase 5.4 introduces a **Search Projection Corpus (SPC)** as a derived, non-canonical corpus.

The SPC is rebuilt from an immutable canonical corpus and pinned registries. It is invalid if its source corpus or projection contract changes.

Minimum build binding:

- `search_contract_version`;
- canonical corpus/build identifier;
- canonical corpus digest;
- canonical schema version;
- registry bundle version/digest;
- projection-profile version/digest;
- index adapter identifier/version when an engine-backed index is built.

The projection may contain derived values that do not belong in canonical records, including:

- normalized search tokens;
- exact-lookup keys;
- scoped-lookup keys;
- alias keys;
- numeric sort values;
- lexical fields;
- filter facets;
- graph adjacency projections;
- stage-local ranking features.

All such values are rebuildable and must never become the authority for canonical identity or lifecycle.

## 4. Projection objects

Phase 5.4.1 should define versioned search-contract schemas for the following non-canonical objects.

### SearchDocument

One searchable canonical subject with derived retrieval fields.

Minimum fields:

- canonical record/entity ID;
- record/entity type;
- title;
- platform/product/provider/source/channel scope where applicable;
- lifecycle and applicability summary;
- source-backed description/claim text selected under an explicit projection rule;
- projection digest.

### IdentifierProjection

Minimum fields:

- canonical target ID;
- identifier type;
- lossless native value;
- namespace;
- structured context/scope;
- case-sensitivity policy;
- registry-defined normalization policy;
- numeric semantics flag and derived numeric value when permitted;
- primary/non-primary flag.

### AliasProjection

Minimum fields:

- canonical target ID;
- alias value;
- alias scope;
- normalization policy;
- provenance/derivation reference where applicable.

### FilterProjection

Typed filter facets derived from canonical/source-backed attributes, such as:

- platform;
- product;
- provider;
- channel/source;
- record/entity type;
- lifecycle;
- version/applicability;
- validation maturity;
- ATT&CK/D3FEND/CAR relationship pivots where source-backed.

### EdgeProjection

A compact, derived adjacency view for bounded graph expansion. It does not replace canonical `RelationshipRecord` semantics.

## 5. Query normalization

Search normalization must be conservative.

- Preserve the original query for audit/debug display.
- Trim leading/trailing whitespace and collapse repeated separator whitespace for parsing.
- Do not globally lowercase identifier values.
- Identifier matching follows the identifier registry's case-sensitivity and normalization rules.
- Scope vocabulary such as `sysmon`, `windows`, provider labels, and filter keys may be case-insensitive.
- Unicode normalization may be used only in the search projection/query layer and must not modify canonical/native stored identity.
- Query length, token count, filter count, and graph-expansion depth must be bounded.

Initial Phase 5.4.1 safety profile:

- maximum query length: 512 Unicode scalar values;
- maximum parsed terms: 32;
- maximum structured filters: 16;
- default graph expansion depth: 1;
- hard graph expansion depth limit: 2.

These are search-runtime safety bounds, not canonical data-model constraints.

## 6. Exact resolver contract

The Exact Resolver is authoritative for deterministic identity lookup.

Resolution stages:

1. exact canonical ID, when supplied;
2. exact native identifier using registry-aware normalization;
3. exact native identifier constrained by parsed scope;
4. deterministic ambiguity handling.

Natural scoped forms must be supported without requiring users to know Atlas canonical IDs, including:

- `sysmon 1`;
- `windows 4688`;
- `event id 4688`;
- provider/product qualified forms defined by the scope registry.

A bare numeric query such as `4688` is not globally assigned to Windows Security. Atlas first looks for exact registered identifier matches. If exactly one identity exists in the active corpus, it may resolve directly. If multiple scoped identities exist, the response is a disambiguation set.

Exact resolution never uses fuzzy matching.

## 7. Deterministic disambiguation

Disambiguation results use a stable ordering independent of ingestion order.

Stable sort key:

1. platform;
2. product;
3. provider;
4. telemetry source/channel;
5. identifier type;
6. native value;
7. lifecycle;
8. canonical ID as the final total-order tie breaker.

The user sees scope labels sufficient to distinguish the candidates. Atlas does not merge or silently prefer one identity because it is newer, more popular, or lexically higher ranked.

## 8. Alias stage

Aliases are resolved only after exact native-identifier handling.

- Aliases are scoped searchable labels, not canonical IDs.
- An alias cannot collapse distinct entities.
- Ambiguous aliases return a disambiguation set.
- Fuzzy alias matching is lexical retrieval, not exact alias resolution.

## 9. Lexical retrieval

Lexical retrieval operates over explicit projected fields and uses an engine adapter rather than raw engine syntax.

Minimum lexical fields:

- title;
- approved aliases;
- native identifier text;
- source-backed description/claim text;
- field names;
- tool/operation/activity names;
- selected relationship labels.

The query compiler produces an internal search request AST. Adapters translate that AST into engine-specific operations with parameterized/bounded inputs.

No user text may be concatenated into an engine query language.

## 10. Ranking contract

Stage precedence is fixed:

```text
Exact Native/Canonical Identifier
    > Scoped Identifier
    > Exact Scoped Alias
    > Lexical Match
    > Graph Expansion
    > Semantic Retrieval (future, optional)
```

Within lexical results, engine relevance may be used, but ordering must have deterministic tie breakers. A minimum stable ordering profile is:

1. lexical relevance score descending;
2. exact title-token match boost;
3. scope-context match boost;
4. validation/source-confidence signal where defined;
5. lifecycle/freshness signal only as a documented ranking feature, never as identity selection;
6. normalized title;
7. canonical ID as final total-order tie breaker.

Raw floating-point engine scores are not a public cross-engine contract. Golden tests assert result stage, candidate set, and stable ordering for declared engine/profile versions.

## 11. Structured filters and provider catalogs

Global search and provider catalog browse are separate product paths that can share the same projection corpus.

Supported filter dimensions should include at minimum:

- Platform;
- Product;
- Provider;
- Channel / Telemetry Source;
- Record / Entity Type;
- Lifecycle;
- Version / Applicability.

Numeric Event ID browse is scoped to a provider/source context and uses a derived numeric projection only when the identifier registry declares the identifier numeric.

Example ordering: `1, 2, 3, 10, 11, 100`, never lexical `1, 10, 100, 11, 2, 3`.

## 12. Graph expansion

Graph expansion is a bounded search enrichment stage, not a graph database selection.

- Default depth is 1; hard maximum is 2 for Phase 5.4.
- Traversal uses explicitly allowed relationship types.
- Results are deduplicated by canonical ID.
- Expansion order is deterministic.
- Relationship provenance remains available from canonical records.
- Graph expansion may boost or append related results but cannot outrank a clear exact identifier match.

## 13. Result contract

Every search result must be explainable.

Minimum response fields:

- canonical target ID;
- title;
- entity/record type;
- scope summary;
- lifecycle;
- matched query value;
- `match_stage`;
- `match_reason`;
- disambiguation state where applicable;
- stage-local rank/score metadata where useful;
- source/provenance summary reference;
- validation/freshness indicators where available.

A result must never require the user to know the canonical ID to continue searching or browsing.

## 14. Required acceptance cases

The permanent acceptance corpus must cover at least:

| Query | Required behavior |
|---|---|
| `4688` | Exact native identifier; direct only when unique, otherwise deterministic disambiguation |
| `Event ID 4688` | Same identity semantics as `4688` with recognized type hint |
| `windows 4688` | Scoped exact resolution to Windows Security context when unambiguous |
| `sysmon 1` | Scoped exact resolution to Sysmon Event ID 1 |
| `1` | Disambiguation when multiple providers expose Event ID 1 |
| `592` | Historical/legacy Windows identity remains directly discoverable |
| `T1059` | Exact ATT&CK technique identifier resolution |
| `T1059.001` | Exact ATT&CK sub-technique identifier resolution |
| `CreateAccessKey` | Exact/lexical operation lookup without vendor-ID confusion |
| `EXECVE` | Exact/lexical Linux audit action/type lookup preserving native spelling semantics |
| `exec_start` | Docker/container activity lookup without normalization-induced identity merge |
| `kubectl exec` | Lexical/tool/activity lookup and relationship pivots |
| `FileAccessed` | Lexical/activity lookup across scoped products without arbitrary collapse |

Synthetic collision fixtures are mandatory so ambiguity behavior is tested even when the current production-like corpus happens to contain only one matching identifier.

## 15. Performance and reproducibility targets

Existing MVP targets remain:

- exact local lookup: target P95 < 100 ms;
- normal local lexical search: target P95 < 300 ms;
- no network dependency for core search.

Every benchmark result must declare:

- hardware/OS profile;
- corpus size and digest;
- projection profile/version;
- engine/adapter version;
- cold/warm-cache condition;
- query set version;
- P50/P95/P99 latency;
- index size;
- index build time;
- peak memory where measurable.

Performance is never claimed without a declared benchmark scope.

## 16. Security requirements

Phase 5.4 must include negative/security tests for:

- query-parser injection;
- engine-query/FTS syntax injection;
- malformed Unicode;
- oversized query/filter input;
- pathological token counts;
- graph-expansion explosion;
- wildcard/regex denial of service where such features exist;
- stale or mismatched projection-corpus binding;
- corrupted index metadata;
- ambiguous identifier collision handling.

The core search API exposes a typed internal query AST, not an arbitrary backend query string.

## 17. Search engine spike — mandatory before selection

Phase 5.4 does not freeze the search engine at the architecture-gate stage.

The mandatory shortlist for the implementation spike is:

1. **SQLite + FTS5** — embedded/single-database candidate with B-tree exact indexes and FTS5 lexical search;
2. **Tantivy** — embedded Rust full-text index candidate with a dedicated index directory.

A third candidate may be added only if it materially improves the comparison. Daemon-first systems are not preferred for the offline/portable MVP because they add a service lifecycle and deployment boundary.

The spike must compare:

- exact resolver behavior;
- lexical relevance and deterministic ties;
- structured filters;
- numeric browse;
- graph-adjacency integration;
- index build/update cost;
- index/corpus footprint;
- read-only/offline operation;
- Windows portability;
- crash/rebuild behavior;
- atomic replacement/rollback compatibility with future Phase 5.5 packs;
- migration/version binding;
- library/runtime footprint;
- licensing;
- integration risk with future Shared Core/Desktop candidates.

The winning engine requires a dedicated accepted ADR. Until that ADR is approved, SQLite, Tantivy, and the embedded database choice remain candidates rather than product commitments.

## 18. Implementation slices

### 5.4.1 — Search Contracts + Reference Resolver

Engine-neutral foundation only:

- search projection schemas/contracts;
- projection builder over deterministic fixtures/current canonical corpus;
- query parser and typed search-request AST;
- registry-aware exact resolver;
- deterministic scoped disambiguation;
- alias stage;
- numeric browse projection contract;
- permanent acceptance/security tests.

No production lexical engine is selected in this slice.

### 5.4.2 — Search Engine Spike + Selection ADR

- implement equivalent spike adapters for SQLite FTS5 and Tantivy;
- execute declared benchmark corpus/query suite;
- compare footprint, latency, determinism, Windows/offline deployment, rebuild and rollback characteristics;
- produce engine-selection ADR for Architecture Authority approval.

### 5.4.3 — Production Exact/Lexical Search Core

After engine ADR approval:

- production index builder;
- exact lookup adapter;
- lexical adapter;
- structured filters;
- deterministic ranking/tie-breakers;
- index metadata/corpus binding;
- corruption/staleness fail-closed behavior.

### 5.4.4 — Catalog, Graph Pivots, Benchmarks and Closure

- provider/source catalog browse;
- numeric Event ID browse;
- bounded graph expansion;
- lifecycle/version browsing;
- performance regression suite;
- final Phase 5.4 acceptance corpus;
- architecture completion review.

Each slice remains branch → PR → CI → Architecture Review → explicit merge gate.

## 19. Phase boundary

Phase 5.4 must not:

- add search-only fields to canonical `schemas/v1/`;
- implement vector/semantic retrieval as an identity-resolution dependency;
- implement Grounded AI;
- implement signed pack archive/signing/install/rollback runtime;
- require a network service for core search;
- collapse scoped native identifiers;
- remove legacy telemetry from search because it is not current;
- expose arbitrary backend query syntax through the product search API.

Successful Phase 5.4 completion opens Phase 5.5 — Offline Pack Runtime / Shared Core.
