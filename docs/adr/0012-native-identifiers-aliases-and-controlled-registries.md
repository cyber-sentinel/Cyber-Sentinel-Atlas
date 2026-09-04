# ADR-0012 — Native Identifiers, Aliases and Controlled Registries

**Status:** Accepted
**Decision:** 2026-09-04

## Decision

Native identifiers are structured, lossless source-native identifiers and never replace Atlas canonical identity. If an entity has native identifiers, at least one must be `primary=true`; multiple primaries are valid across distinct identifier types/context/applicability domains. `primary` means preferred within source/context, not globally canonical. Exact duplicate native semantic tuples are invalid.

Aliases are structured resolution objects. Effective alias uniqueness considers normalized value/case behavior plus namespace, entity type, provider and locale. Overlapping scopes may not resolve one alias to different canonical entities; disjoint scopes may reuse an alias.

Controlled vocabularies live in versioned registries. Every registry has a unique `registry` identity, independently versioned `registry_version`, and unique values. Registry version is not required to equal schema version. Namespaced extensions use the same registered namespace vocabulary.
