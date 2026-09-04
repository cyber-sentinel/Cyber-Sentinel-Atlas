# ADR-0013 — Applicability, Versioning and Curation/Lifecycle Separation

**Status:** Accepted
**Decision:** 2026-09-04

## Context

Windows build numbers, cloud API versions, semantic versions and vendor-native labels cannot safely share one comparison model. Historical telemetry also needs lifecycle state independently from Atlas curation state.

## Decision

Lifecycle and curation are independent dimensions.

Lifecycle states remain:

- current
- legacy
- deprecated
- superseded
- retired

Curation states are:

- draft
- review
- validated
- published
- withdrawn

A reusable Applicability contract may reference platforms, products, providers, VersionRecords, version constraints, validity dates and explanatory claims.

A version constraint explicitly identifies:

- `subject_id`
- `version_scheme`
- `expression`

Supported schemes initially include semver, numeric, date, build, opaque and vendor-native.

VersionRecord is a first-class record supporting subject, version type, native label, optional normalized value, scheme, release/support dates and evidence.

Schema version, record revision, product/source version and product release version are independent concepts.

## Consequences

A telemetry entity may validly be `lifecycle=legacy` and `curation_status=published`. Atlas does not force unrelated version schemes into one comparator, and version/applicability evidence remains explicit.