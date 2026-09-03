# ADR-0003 — Offline-first Core

**Status:** Accepted  
**Decision:** 2026-09-03

## Context

Analysts may work in disconnected, restricted, air-gapped, or unreliable-network environments.

## Decision

Core Atlas functionality must support signed, local knowledge packs and deterministic local search.

## Consequences

Positive:

- useful in restricted environments;
- lower latency;
- stronger product differentiation;
- predictable availability.

Negative:

- update and schema migration become product concerns;
- pack signing and compatibility must be engineered early;
- storage size must be controlled.
