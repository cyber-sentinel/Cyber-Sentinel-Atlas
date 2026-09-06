# Phase 5.4.2 Search Engine Spike

This directory contains the reproducible technology-selection benchmark required by the accepted Phase 5.4 architecture gate.

Candidates:

1. SQLite + FTS5
2. Tantivy via the pinned `tantivy==0.26.0` Python binding for the spike harness

The benchmark is **not** the production search implementation. It measures equivalent adapter operations over the Phase 5.4.1 acceptance projection plus deterministic synthetic scale records.

## Operations measured

- exact target lookup;
- lexical retrieval over title/alias/native-ID/description projections;
- lexical retrieval with a provider filter;
- provider-scoped numeric Event ID browsing;
- deterministic result tie-breaking at the adapter boundary;
- a high-fanout lexical case with thousands of equal-scored candidates to prove stable Top-K behavior rather than merely backend-native Top-K selection.

No raw caller query text is passed directly into SQLite FTS or the Tantivy query parser. The harness first validates Unicode scalar input, applies the Phase 5.4 query-length bound, normalizes search-layer text, and converts it into a bounded token list. SQLite receives a generated FTS expression as a bound SQL parameter; Tantivy uses programmatic `Query` objects.

## Benchmark corpus

The corpus starts from the Phase 5.4.1 acceptance projection and adds fixture-only synthetic scale records. Synthetic records:

- do not add native identifiers;
- contain deterministic varied high-cardinality lexical material so footprint measurements are not based solely on identical repeated text;
- include a deterministic `benchmarkfanout` term on every fifth synthetic document, creating thousands of equal-score matches at the default 20,000-document scale;
- remain non-canonical and exist only for benchmark evidence.

The high-fanout case is intentionally synthetic: its purpose is to exercise deterministic Top-K/tie behavior under a broad match set. It is not a claim that this query represents analyst semantics.

## Deterministic result handling

Every benchmark case is repeated and the complete ordered result must remain identical across iterations.

SQLite applies `ORDER BY` with the canonical target ID as the total-order tie breaker after FTS relevance.

The Tantivy spike adapter does not rely on a backend-native Top-K subset followed by local sorting, because that can leave the candidate subset undefined when more than `TOP_K` documents share the cutoff score. For this bounded spike corpus, it retrieves the bounded candidate set and applies Atlas' engine-neutral relevance/`target_id` total order before truncation. Phase 5.4.3 may use a more efficient production collector, but it must preserve the same deterministic output contract.

## Reproducibility

Each result records:

- OS / Python / CPU count / available memory when discoverable;
- candidate engine version;
- Phase 5.4.1 projection digest;
- deterministic benchmark-corpus digest;
- query-suite version/digest;
- document count and iterations;
- build time;
- index footprint;
- P50/P95/P99/mean/max query latency;
- per-case deterministic-repeat status;
- candidate correctness errors;
- full result digest.

The CI benchmark intentionally describes its cache condition as **process-warm**. It does not claim an OS-cold-cache measurement because GitHub-hosted runners do not provide a controlled cache-flush primitive.

## Scope

Default CI scope:

- 20,000 documents;
- 40 repetitions per case;
- Ubuntu and Windows GitHub-hosted runners.

This is an MVP-scale technology-selection spike, not a global future-scale guarantee. Future corpus growth that materially changes footprint, latency, update cost or ranking requirements must trigger renewed benchmark evidence before changing the accepted engine decision.

## Licensing inputs

- SQLite core: public domain according to SQLite's official licensing documentation.
- Tantivy: MIT License according to the official `quickwit-oss/tantivy` repository.

License compatibility is one input to ADR-0022, not the sole selection criterion.
