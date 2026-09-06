# Phase 5.4.1 — Search Contracts + Reference Resolver

Status: **IMPLEMENTATION SLICE**

Architecture baseline: ADR-0021 and `docs/architecture/phase-5.4-deterministic-search-core.md`.

## Purpose

Phase 5.4.1 freezes the engine-neutral search contracts that every later search backend must obey. It proves exact canonical/native identifier resolution, scoped resolution, deterministic ambiguity handling, exact alias handling, numeric browse projection, query bounds, and projection reproducibility before a production lexical engine is selected.

This slice deliberately does **not** select SQLite FTS5, Tantivy, or any other production search engine.

## Search schema stream

Search artifacts use a dedicated non-canonical schema stream:

```text
schemas/search/v1/
```

It is separate from:

```text
schemas/v1/             # canonical knowledge model
schemas/ingestion/v1/   # ingestion/control plane
```

The Phase 5.4.1 search-contract version is `1.0.0`.

Search schemas describe rebuildable projections and search requests/results. They do not create an eighth Canonical `AtlasRecord` family and do not authorize changes to `schemas/v1/`.

## Derived objects

The initial Search Projection Corpus contains:

- `SearchDocument` — searchable canonical subject projection;
- `IdentifierProjection` — lossless native identifier plus scoped search semantics;
- `AliasProjection` — scoped searchable alias;
- `FilterProjection` — typed derived facets;
- `EdgeProjection` — bounded graph adjacency contract, empty in the initial 5.4.1 fixture;
- immutable build binding and bundle digest.

The projection bundle binds to the canonical corpus ID/digest, canonical schema version, reference registry profile, and projection profile. A later engine-backed build will also bind to an index adapter ID/version.

## Reference resolver

`tools/search/reference_search.py` is an engine-neutral contract implementation, not the final lexical search engine.

Its stage precedence is:

```text
Exact Canonical ID
    ↓
Exact Native Identifier
    ↓
Scoped Native Identifier
    ↓
Exact Scoped Alias
    ↓
Reference Lexical Containment
```

The final lexical stage exists only to exercise the typed result contract before Phase 5.4.2. It must not be treated as the production lexical ranking implementation or used to select a backend.

## Query safety

The reference parser enforces the Phase 5.4 safety profile:

- maximum 512 Unicode scalar values;
- maximum 32 parsed terms;
- maximum 16 structured filters;
- graph depth 0–2;
- invalid Unicode surrogate rejection;
- typed filter vocabulary;
- no user-provided backend query string.

Search-layer Unicode normalization does not rewrite canonical/native identity. Identifier comparison follows projected case-sensitivity semantics.

## Deterministic ambiguity

A bare identifier that has multiple valid scoped targets returns `disambiguation`.

The acceptance corpus includes a synthetic Event ID `1` collision so this invariant cannot silently disappear if the current product corpus happens to contain a unique Event ID.

The stable ordering contract remains:

```text
platform
product
provider
channel/source
identifier type
native value
lifecycle
canonical ID
```

Input/corpus insertion order must not affect the result.

## Numeric browse

Numeric browse values exist only in `IdentifierProjection` when the seed declares numeric semantics. The canonical/native identifier remains lossless text.

The 5.4.1 acceptance corpus proves that Windows event IDs browse as `592, 4688`, not lexical text order.

## Acceptance corpus

`fixtures/phase-5.4.1/acceptance-corpus.json` is fixture-only and intentionally small. It contains representative identities for:

- Windows Security 4688;
- legacy Windows Security 592;
- Sysmon Event 1;
- synthetic colliding Event ID 1;
- ATT&CK T1059 and T1059.001;
- AWS `CreateAccessKey`;
- Linux `EXECVE`;
- Docker `exec_start`;
- Kubernetes `kubectl exec` / `create.pods.exec`;
- Microsoft 365 `FileAccessed`.

It is an acceptance fixture, not a completeness claim or released content pack.

## Permanent validation

Phase 5.4.1 adds:

```text
tools/search/validate_phase541.py
tests/phase54/test_reference_search.py
```

Validation covers:

- JSON Schema Draft 2020-12 correctness;
- search schema URI policy;
- projection determinism across reversed input order;
- exact/scoped/alias acceptance cases;
- deterministic collision behavior;
- legacy lookup;
- numeric browse;
- query bounds and malformed Unicode;
- injection-like text treated as data;
- duplicate canonical target rejection;
- non-decimal values rejected when marked numeric.

## Boundary to Phase 5.4.2

After Phase 5.4.1 is merged, Phase 5.4.2 will implement equivalent adapters/spikes for at least:

1. SQLite + FTS5;
2. Tantivy.

The spike must benchmark and compare both candidates under the accepted contract. Production search-engine selection remains a separate material ADR and is not decided by this slice.
