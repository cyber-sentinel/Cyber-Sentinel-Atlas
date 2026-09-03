# ADR-0001 — Canonical Vendor-Neutral Model

**Status:** Accepted  
**Decision:** 2026-09-03

## Context

Security concepts frequently appear in multiple SIEM, EDR, rule, and query formats.

## Decision

Atlas stores the underlying event, behavior, artifact, or technique as the canonical entity.

Engine-specific content is attached as a related representation.

## Consequences

Positive:

- no vendor becomes the domain model;
- cross-engine relationships are natural;
- API and offline data remain portable;
- query-language ambiguity is reduced.

Negative:

- normalization requires more design work;
- some vendor concepts do not map cleanly and must remain vendor-specific.
