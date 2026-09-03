# ADR-0004 — Ecosystem Ownership: Atlas, DefenseOps and Forge

**Status:** Accepted
**Decision:** 2026-09-03

## Context

The Cyber-Sentinel ecosystem previously used Forge terminology for CLI/product concepts. Atlas now requires an unambiguous ownership boundary between the knowledge product, defensive engineering source, and any historical Forge material.

## Decision

- Cyber-Sentinel-Forge is retired as an independent Atlas architectural component and product concept.
- Historical Forge repositories/content, if present, must not be deleted automatically. Preserve or archive them with deprecation/redirect guidance where appropriate.
- Cyber-Sentinel-DefenseOps is the approved defensive engineering source for Atlas.
- DefenseOps content enters Atlas only through explicit versioned ingestion, provenance, validation, and controlled release gates.
- DefenseOps content is not automatically authoritative solely because it originates from DefenseOps.
- No independent Forge runtime or knowledge engine remains in the target architecture.
- Former Forge capabilities are classified as:
  - Atlas consumer capability → migrate to Atlas CLI/product interfaces;
  - defensive content authoring/engineering capability → belong to DefenseOps tooling.
- The official user-facing Atlas CLI command is `atlas`.

## Consequences

Positive:

- removes product/runtime ambiguity;
- preserves a clean Atlas ↔ DefenseOps boundary;
- avoids parallel knowledge engines;
- preserves historical Forge material without making it architecturally active.

Constraints:

- DefenseOps ingestion requires a future explicit contract;
- historical Forge assets require inventory before any archive/deprecation action.

## Not Decided Here

- exact DefenseOps → Atlas ingestion contract;
- Detection Intermediate Representation;
- packaging/distribution of the `atlas` CLI.
