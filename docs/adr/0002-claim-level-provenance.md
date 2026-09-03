# ADR-0002 — Claim-Level Provenance

**Status:** Accepted  
**Decision:** 2026-09-03

## Context

Page-level references are insufficient when facts have different sources, product versions, or confidence.

## Decision

Material technical claims are first-class records that can reference specific sources and applicability metadata.

## Consequences

Positive:

- inspectable evidence;
- safer AI grounding;
- version-specific facts;
- conflicting sources can coexist explicitly;
- better change review.

Negative:

- ingestion and authoring are more structured;
- content volume grows;
- provenance validation becomes mandatory.
