# ADR-0017 — Deterministic Acquisition, Parsing and Normalization

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Atlas must transform public authoritative sources reproducibly while preventing upstream content from becoming an execution path or an unreviewed semantic authority.

## Decision

The deterministic pipeline boundary is:

```text
SourceConnectorDefinition
→ AcquisitionRun
→ RawSnapshot + content-addressed raw blob
→ ParserRun / ParsedSourceRecord (PSR)
→ NormalizationRun / NormalizationLineage
→ Canonical Candidate Corpus
```

Public acquisition fails closed: TLS verification, HTTPS policy, host allowlisting, redirect revalidation/limits, SSRF/private-address blocking, bounded responses/decompression/archives, timeouts and safe archive extraction are mandatory. Git is data acquisition only: submodules, hooks, credential helpers, source execution and symlink traversal are disabled.

Raw bytes are SHA-256 hashed exactly as received. Snapshot identity deterministically binds retrieval/run/resource/digest. `304/not-modified` references a previous valid snapshot and never fabricates raw bytes.

Parser output is PSR, not canonical knowledge. Parsers preserve and report unknown structured fields, have no network/AI/source execution, and disable XXE/external resolution. Parser output identity is deterministic for pinned snapshot + parser/version.

The normalizer is the semantic boundary. It consumes only pinned PSR, normalizer version, mapping profile version+digest, registry bundle version+digest and canonical schema version. Identity outcomes are only `CREATE`, `MATCH`, `AMBIGUOUS`; ambiguity enters quarantine and cannot auto-publish. Normalizer core has no network and no AI.

Native identifiers remain lossless and separate from canonical IDs. Normalization lineage is build provenance and remains distinct from claim evidence.

## Consequences

- deterministic replay is possible without re-downloading upstream content;
- source content cannot execute during ingestion;
- mutable version labels alone cannot identify mappings;
- no parser sandbox implementation technology is selected in this ADR.
