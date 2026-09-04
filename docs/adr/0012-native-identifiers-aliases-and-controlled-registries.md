# ADR-0012 — Native Identifiers, Aliases and Controlled Registries

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Atlas canonical identity must remain stable and vendor-neutral while preserving source-native identifiers losslessly. The model also needs extensible controlled vocabularies without hard-coding every future vendor value into one monolithic JSON Schema enum.

## Decision

Native identifiers are structured objects containing at minimum `type`, `value`, `case_sensitive`, and `primary`, with optional namespace/context, components and applicability.

Aliases are structured resolver objects containing `value`, `kind`, `case_sensitive`, optional `scope`, locale and applicability. Alias kinds initially include native, display, common, historical-name, provider-qualified and legacy-canonical-id.

Aliases never replace canonical identity and never silently merge distinct entities. Ambiguous aliases require scope/context during resolution.

Controlled vocabularies are stored in versioned registries under `model/registries/`. Phase 5.2 initially defines registries for:

- entity types;
- namespaces;
- relationship types;
- native identifier types;
- claim predicates;
- alias kinds.

JSON Schema validates syntax and structure. Deterministic validators enforce registry membership.

## Consequences

- source-native case and structured components are preserved;
- registry additions can evolve without redesigning universal schemas;
- vendor-specific detail remains in native identifier components or registered extensions rather than root fields;
- canonical/native/alias identity boundaries are testable.