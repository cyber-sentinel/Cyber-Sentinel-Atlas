# ADR-0020 — Encyclopedia Identifier Search/Browse Data Contract

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Phase 5.4 will implement deterministic search, but Phase 5.3 must preserve enough lossless data for exact identifier resolution, scope disambiguation, legacy lookup and numeric browsing.

## Decision

Canonical candidate output preserves indexable source-backed data for canonical ID, native identifier type/value/namespace/context, provider, product, platform, telemetry source/channel, title, aliases, lifecycle, applicability, version metadata, documentation status and provenance.

Native numeric Event IDs are stored losslessly as strings in the Canonical Knowledge Model. Search-specific projections, including numeric sort values, lexical tokens, vectors and ranking fields, are not added to the canonical model in Phase 5.3.1.

The same numeric native identifier may exist in multiple provider/product/source contexts and must remain separate canonical identities. For example, two scoped synthetic `4688` records are permitted and must not be merged. Legacy `592` remains an independently representable historical identity and is not collapsed into a current event alias.

Future numeric browse order is numeric within a declared scope (`1, 2, 3, 10, 11, 100`) rather than lexical. Phase 5.4 owns the projection/index implementation.

A future Windows/Sysmon Encyclopedia completeness declaration must identify authoritative denominator, provider, channel/source, product/OS version/build scope, expected native identities, missing/invalid state, lifecycle preservation, provenance, coverage snapshot and review state.

## Consequences

- exact-ID and numeric browse requirements are preserved without selecting a search engine;
- Event ID remains scoped rather than globally unique;
- historical telemetry remains discoverable;
- Phase 5.3.1 does not implement search, ranking, lexical/vector retrieval or a storage engine.
