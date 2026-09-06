# Phase 5.4.4 — Catalog, Graph Pivots, Benchmarks and Closure

Status: **IMPLEMENTED — ARCHITECTURE REVIEW PENDING**

Baseline main SHA: `d6a325c349cd0ec3035c5dbe05ed69ef840323c4`

Phase 5.4.4 closes the deterministic Search Core without introducing a graph database, semantic/vector retrieval, Grounded AI, signed-pack runtime, or a Desktop/Web stack decision.

## 1. Delivered scope

- provider/source catalog browse over typed Search Projection Corpus (SPC) facets;
- lifecycle/version browse that preserves current, legacy, deprecated, superseded, retired and other projected lifecycle states;
- provider-scoped numeric Event ID browse using registry-declared numeric semantics;
- bounded graph pivots over `EdgeProjection` rows;
- deterministic graph deduplication and stable traversal ordering;
- graph depth default/maximum inherited from the accepted Phase 5.4 contract (`1` / hard maximum `2`);
- final Phase 5.4 acceptance corpus including exact identifier collisions, legacy telemetry, version facets and graph-cycle fixtures;
- production SQLite + FTS5 regression benchmark on Linux and Windows;
- explicit performance budgets and reproducible evidence artifacts.

## 2. Catalog contract

Catalog browse is a separate product path from lexical search. It reuses the same activated SQLite index and only accepts controlled facet keys from the Search Contract:

- `platform`;
- `product`;
- `provider`;
- `channel`;
- `namespace`;
- `type`;
- `lifecycle`;
- `version`.

All facet values are bound parameters. Raw caller text is never concatenated into SQL. The public catalog boundary remains limited by the Phase 5.4 maximum of 16 filters and by the same Unicode safety profile used by search.

The catalog can return deterministic facet values/counts and filtered document rows. Lifecycle/version filtering never deletes or hides legacy identities from the index; it only constrains a browse request.

## 3. Numeric Event ID browse

Numeric Event ID browse remains namespace/provider scoped and delegates to the production 5.4.3 numeric projection/index. It is enabled only where the identifier projection declares numeric semantics.

Sorting is numeric and deterministic:

```text
derived_numeric_value ASC, target_id ASC
```

No numeric sort value is added to canonical `schemas/v1/` records.

## 4. Graph pivot contract

Phase 5.4.4 **does not select a graph database**.

Graph adjacency is rebuilt from the SPC `edges` collection and held in memory by the current reference/production runtime. The canonical `RelationshipRecord` remains the semantic/provenance authority; `EdgeProjection` is a disposable adjacency view.

Safety bounds:

- maximum seeds: `20`;
- maximum graph depth: inherited hard maximum `2`;
- maximum returned graph rows: `100`;
- maximum active EdgeProjection rows in this runtime: `100,000`;
- maximum explicitly allowed relationship types per request: `32`.

Default graph relationship allowlist intentionally excludes potentially explosive structural relationships such as `HAS_FIELD`. It includes analyst-facing pivots such as `RELATED_TO`, `EQUIVALENT_SIGNAL`, `SUPERSEDES`, `SUPERSEDED_BY`, `VERSION_OF`, `MAPS_TO_ATTACK`, defensive/investigation relationships and telemetry-provider/source pivots.

Unknown relationship types, missing graph targets, duplicate edges, unsorted edge projections, oversized graphs and invalid depths fail closed.

## 5. Deterministic traversal

Traversal is bounded breadth-first search. Seeds are deduplicated and sorted. Candidate edges are sorted using relationship type, direction and stable canonical identifiers before traversal. A canonical target is emitted once, at the first deterministic shortest path encountered.

Graph results contain:

- `target_id`;
- title/entity type from the active SearchDocument;
- traversal depth;
- `via_id`;
- relationship type;
- direction.

Relationship evidence/provenance remains retrievable from the canonical relationship layer; the graph projection does not invent evidence.

## 6. Search precedence remains unchanged

Search and graph composition returns the deterministic search result separately from graph pivots:

```text
Exact Canonical/Native Identifier
    > Scoped Identifier
    > Exact Alias
    > Lexical
    > Graph Pivot
    > future Semantic Retrieval
```

Graph pivots never modify the exact/lexical `match_stage`, never replace the matched identity and never outrank a direct exact match.

## 7. Final acceptance corpus

`fixtures/phase-5.4.4/catalog-graph-corpus.json` preserves the mandatory Phase 5.4 acceptance identities and adds:

- explicit projected `version` values;
- a fixture-only legacy/current lifecycle split;
- three fixture-only graph nodes;
- a deterministic three-node cycle using registered `RELATED_TO` edges.

The graph nodes and edges are synthetic and exist only to verify traversal, cycle handling and deterministic deduplication. They are not cybersecurity claims.

The Phase 5.4.1 frozen acceptance corpus remains unchanged.

## 8. Corpus and edge binding

The 5.4.4 bundle helper starts from the accepted 5.4.1 projection contract and additively projects version facets and fixture edge seeds.

When edges are present, the canonical-corpus fixture digest is rebound to both sorted records and sorted edge seeds. The final `bundle_digest` covers documents, identifiers, aliases, filters, edges and build binding.

The production SQLite index still does not persist a graph database; its mandatory SPC `bundle_digest` binding ensures that an index built for one graph/corpus projection cannot be activated against a different SPC.

## 9. Performance regression profile

The Phase 5.4.4 benchmark synthesizes a deterministic 20,000-document corpus from the final acceptance fixture and adds a bounded 1,000-edge graph chain.

Measured paths:

- exact `4688` lookup;
- high-fanout lexical `benchmarkfanout` query;
- provider catalog browse;
- lifecycle catalog browse;
- numeric Event ID browse;
- depth-2 graph expansion.

Default iterations: `40` per path.

Budgets:

- exact P95 `< 100 ms`;
- lexical P95 `< 300 ms`;
- catalog/numeric/graph P95 `< 300 ms`.

Evidence declares OS/Python/CPU profile, document and edge counts, SPC digest, projection profile, SQLite/adapter versions, index size, projection/index build time, P50/P95/P99/mean/max and correctness assertions.

Absolute performance claims are valid only for the declared evidence environment.

## 10. Security requirements closed by this slice

Permanent tests cover:

- graph depth overflow;
- excessive/invalid relationship allowlists;
- missing graph targets;
- duplicate graph edges;
- graph-cycle deduplication;
- graph/SPC digest rebinding;
- invalid catalog facets;
- malformed Unicode in catalog filters;
- deterministic provider/source/lifecycle/version browsing;
- exact resolver collision semantics;
- search-stage precedence when graph pivots are present.

The Phase 5.4.3 injection, malformed Unicode, oversized query, corruption, stale binding and Last Known Good tests remain permanent regression tests.

## 11. Phase boundary

Phase 5.4 closes when:

1. Phase 5.4.1 through 5.4.4 permanent tests pass;
2. Linux and Windows Phase 5.4.4 benchmark/acceptance CI passes on the exact reviewed head;
3. Foundation Hygiene is green on the exact reviewed head;
4. final architecture review confirms no canonical `schemas/v1/` change and no hidden storage/graph/AI/pack-runtime freeze;
5. the reviewed PR is merged with the expected-head SHA and post-merge main validation is green.

Successful closure opens **Phase 5.5 — Offline Pack Runtime / Shared Core**.
