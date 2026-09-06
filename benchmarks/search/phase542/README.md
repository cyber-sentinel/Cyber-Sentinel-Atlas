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
- deterministic result tie-breaking at the adapter boundary.

No raw caller query text is passed directly into SQLite FTS or the Tantivy query parser. The harness first converts lexical text into a bounded token list. SQLite receives a generated FTS expression as a bound SQL parameter; Tantivy uses programmatic `Query` objects.

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
- candidate correctness errors;
- full result digest.

The CI benchmark intentionally describes its cache condition as **process-warm**. It does not claim an OS-cold-cache measurement because GitHub-hosted runners do not provide a controlled cache-flush primitive.

## Scope

Default CI scope:

- 20,000 documents;
- 40 repetitions per case;
- Ubuntu and Windows GitHub-hosted runners.

The synthetic scale documents are fixture-only benchmark noise. They do not become canonical Atlas records and do not affect Phase 5.4.1 exact-identifier acceptance identities.

## Licensing inputs

- SQLite core: public domain according to SQLite's official licensing documentation.
- Tantivy: MIT License according to the official `quickwit-oss/tantivy` repository.

License compatibility is one input to ADR-0022, not the sole selection criterion.
