# ADR-0014 — Claim, Evidence and Relationship Contracts

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Claim-level provenance is an accepted Atlas principle. Material semantic graph edges also require evidence without making evidence metadata part of semantic identity.

## Decision

ClaimRecord supports subject, controlled predicate, typed object, confidence, applicability and one or more evidence entries.

Claim objects support:

- canonical entity reference;
- typed literal;
- structured JSON only when a canonical entity/relationship is not the appropriate representation.

Evidence records source ID, optional source snapshot ID, source version, retrieval time, explicit locator, transformation type and reviewer status.

Claim semantic identity is deterministically derived from normalized:

`subject + predicate + object + applicability semantic scope`

Evidence source lists, review status and timestamps do not change claim identity.

RelationshipRecord is a first-class graph record. Its semantic identity is deterministically derived from:

`from + relationship_type + to + optional semantic qualifier`

Confidence, evidence, timestamps and curation state do not define relationship identity.

Material semantic relationships must be supported through claims/provenance. Pure structural edges such as RUNS_ON, HAS_TELEMETRY_PROVIDER, HAS_TELEMETRY_SOURCE, EMITS and HAS_FIELD may be validated structurally when their fixture/corpus endpoints establish the declared hierarchy.

Full SHA-256 based canonical keys are used for deterministic Claim and Relationship identities.

## Consequences

Adding a second supporting source does not duplicate a semantic claim/edge. Evidence remains inspectable, and graph identity is stable across review state changes.