# Source & Ingestion Core — Phase 5.3

Authoritative decisions: [ADR-0016](../adr/0016-source-ingestion-control-plane-boundary.md), [ADR-0017](../adr/0017-deterministic-acquisition-parsing-normalization.md), [ADR-0018](../adr/0018-authoritative-inventory-completeness-change-safety.md), [ADR-0019](../adr/0019-validation-review-pack-ready-promotion.md), and [ADR-0020](../adr/0020-encyclopedia-identifier-search-browse-data-contract.md).

## Boundary

Phase 5.3 transforms approved public authoritative sources into reviewed canonical candidate builds and stops at `PACK_READY`:

```text
SourceRecord / source control
        ↓
SourceConnectorDefinition
        ↓
AcquisitionRun
        ↓
RawSnapshot Manifest → content-addressed Raw Blob
        ↓
ParserRun → ParsedSourceRecord (PSR)
        ↓
NormalizationRun + NormalizationLineage
        ↓
Canonical Candidate Corpus
        ↓
Authoritative Inventory + three-layer InventoryDiff
        ↓
G1..G15 Build Validation
        ↓
Human ReviewDecision
        ↓
PACK_READY
```

`PACK_READY` is not signed, released or installed. Pack format, signing/key management, client installation and rollback runtime remain later concerns.

## Knowledge Plane vs Ingestion Artifact Plane

The Canonical Knowledge Corpus remains the seven Phase 5.2 `AtlasRecord` families. Ingestion artifacts are operational/reproducibility metadata and are governed by `schemas/ingestion/v1/`. They never become an eighth canonical family.

`SourceRecord` owns source identity, authority tier, licensing/redistribution and freshness/change-policy semantics. A connector owns acquisition mechanics only and derives retention/legal behavior from the source policy rather than inventing legal conclusions.

## Acquisition and Raw Snapshot Security

Public connectors are HTTPS/Git data acquisition only. Required controls include TLS verification, host/path allowlisting, redirect revalidation and limits, SSRF protections blocking loopback/private/link-local/internal destinations, response/decompression/archive/time bounds, safe archive extraction, and URI credential/signed-query rejection. Persisted transport metadata is allowlisted; authorization/cookie/secret-bearing headers are not persisted.

Git acquisition disables submodules, hooks, credential helpers, source execution and symlink traversal. Upstream repository content is data, never code to execute.

Raw blobs are SHA-256 content-addressed over exact received bytes. Snapshot identity is retrieval-specific and binds acquisition run + target/resource + raw digest. `not-modified` references prior valid content instead of creating fake raw bytes. Retention modes are `full`, `restricted`, `digest-only`, and `transient`, derived from SourceRecord policy.

## Parser / PSR

Parser responsibility ends at source-native structure. `ParsedSourceRecord` preserves native fields, native identifiers, locators and unknown structured fields. Unknown fields are **preserved + reported**. Parser core has no network/DNS/HTTP/Git, no source/JavaScript/macro execution, no AI, no XXE/external entity resolution, restricted filesystem access and resource limits.

Same snapshot + same parser/version must yield the same PSR records, IDs and representation digest. A retained RawSnapshot can be replayed with a newer parser without re-downloading upstream.

## Normalization and Lineage

Normalizer is the semantic boundary from PSR to Canonical Candidate Records. It pins PSR/parser context, normalizer version, immutable mapping-profile version+SHA-256 digest, controlled-registry bundle version+digest and Canonical Schema Version 1.0.0. It is offline and AI-free.

Identity resolution outcomes are only `CREATE`, `MATCH`, and `AMBIGUOUS`. Ambiguity quarantines the result and never auto-publishes. Native identifiers remain lossless. Material factual semantics become evidence-backed claims where required by the canonical model; semantic relationships retain supporting claims/evidence. Structural graph output still retains `NormalizationLineage`.

Claim evidence is semantic/source provenance. Normalization lineage is reproducibility/build provenance. They are complementary and not interchangeable.

## Inventory and Change Safety

Completeness is denominator-backed. `AuthoritativeInventoryDefinition` declares scope, sources, method/version, digest, expected identity count and dimensions. Documentation inventories and telemetry/provider inventories are distinct.

Diffs are represented at raw, parsed and canonical layers. `NOT_OBSERVED` never means `REMOVED`. Source-specific guardrails block unexplained shrink/explosion, collision, invalid records and structural drift. Historical telemetry is not auto-deleted because upstream content disappears.

## Validation and Review

The foundation represents G1 Acquisition, G2 Security/Integrity, G3 Parser, G4 Source Structure, G5 Normalization, G6 Canonical Schema, G7 Registry, G8 Referential Integrity, G9 Provenance, G10 Semantic Invariants, G11 Inventory/Completeness, G12 Determinism/Replay, G13 Regression, G14 License/Redistribution, and G15 Human Review.

`BuildValidationReport` is build metadata; canonical `ValidationRecord` remains unchanged. Review binds exact candidate/diff digests. Any candidate mutation invalidates prior approval. Mandatory failures cannot be waived into `PACK_READY`. High-risk policy can require four-eyes review without selecting an identity/workflow product.

## Encyclopedia Data Requirements

Phase 5.3 preserves canonical/native identifier context needed by later deterministic search. Numeric Event IDs remain strings in canonical data. Identical numeric IDs in different providers/products/sources remain separate identities. Legacy identities remain independently representable. No numeric sort/search projection, lexical index, vector index or ranking field is added to the canonical model; Phase 5.4 owns those projections.

## Slice Boundaries

- **5.3.1 — Ingestion Foundation / Contracts:** schemas, synthetic fixtures, validator/tests, security/inventory/review contracts. No live ingestion.
- **5.3.2 — MITRE ATT&CK structured-source canary:** not started; requires separate Architecture Authority authorization.
- **5.3.3 — Windows Security + Sysmon Encyclopedia pipeline:** not started; requires separate authorization.
- **5.3.4 — D3FEND/CAR + DefenseOps contract + final promotion gates:** not started; requires separate authorization.

Phase 5.3.1 does not select storage, graph/search engine, Desktop stack, Detection IR, parser sandbox technology, pack format, signing algorithm, key management, or secret-provider technology.
