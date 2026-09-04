# ADR-0014 — Claim, Evidence and Relationship Contracts

**Status:** Accepted
**Decision:** 2026-09-04

## Decision

Claims and relationships are first-class records. Claim `entity-ref` objects resolve only to EntityRecord. Evidence `source_id` resolves to SourceRecord. Material semantic relationships require supporting claims. `PRECEDES` and `FOLLOWS` are semantic temporal/ordering assertions and therefore require `supporting_claim_ids`; they are not structural exceptions.

Structural endpoint invariants are enforced for `HAS_TELEMETRY_PROVIDER`, `HAS_TELEMETRY_SOURCE`, `EMITS`, `HAS_FIELD`, and `RUNS_ON`.

### Authoritative trust

A ClaimRecord with `confidence=authoritative` requires at least one evidence entry that simultaneously references a Tier A authoritative SourceRecord, has `reviewer_status=approved`, and uses `direct-structured-import` or `normalized-fact`. An authoritative RelationshipRecord requires at least one supporting claim that satisfies the same authoritative trust invariant. Human synthesis, AI-assisted derivation, community interpretation or non-authoritative engineering judgment cannot become authoritative merely by citing a Tier A URL.
