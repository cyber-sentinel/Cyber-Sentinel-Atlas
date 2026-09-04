# ADR-0018 — Authoritative Inventory, Completeness and Change Safety

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Atlas cannot claim content completeness from crawl/page counts. Source structure may drift independently from source semantics, and disappearance upstream must not erase historical telemetry.

## Decision

Completeness is measured only against a declared `AuthoritativeInventoryDefinition` with explicit scope, source IDs, method, source/version identity, digest, expected identity count and identity dimensions.

Documentation inventory and telemetry/provider inventory are separate denominators. An emitted telemetry identity may remain in Atlas even when no dedicated documentation page exists.

For Event-ID-like telemetry the model can scope identity by provider, channel/telemetry source, native ID, product/platform and applicability/version context. Event ID is never globally unique.

Inventory diff is three-layered:

1. Raw / Acquisition Diff
2. Parsed / Source-Native Diff
3. Canonical Diff

Approved classifications are `ADDED`, `MODIFIED`, `UNCHANGED`, `NOT_OBSERVED`, `LIFECYCLE_CHANGED`, `APPLICABILITY_CHANGED`, `SOURCE_METADATA_CHANGED`, `AMBIGUOUS`, and `INVALID`.

`NOT_OBSERVED` is not `REMOVED`. Disappearance alone cannot delete or retire historical canonical telemetry. Lifecycle/removal changes require evidence and review.

Each inventory carries source-specific shrink/growth guardrails. Unexplained mass shrink, explosion, identity collision, invalid records or parser/source-structure drift blocks promotion according to policy. There is no global hard-coded percentage architecture standard.

## Consequences

- completeness claims are denominator-backed and scope/version-aware;
- parser breakage is distinguishable from genuine source-content removal;
- historical telemetry is preserved safely;
- Windows/Sysmon source-specific inventories remain for later authorized slices.
