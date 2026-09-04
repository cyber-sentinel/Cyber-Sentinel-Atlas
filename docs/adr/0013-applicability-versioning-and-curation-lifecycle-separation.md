# ADR-0013 — Applicability, Versioning and Curation/Lifecycle Separation

**Status:** Accepted
**Decision:** 2026-09-04

## Decision

Lifecycle (`current`, `legacy`, `deprecated`, `superseded`, `retired`) and Atlas curation (`draft`, `review`, `validated`, `published`, `withdrawn`) are independent. Applicability remains universal and version-scheme aware.

Revision 2 adds typed referential invariants: platform/product/provider applicability references resolve to matching EntityRecord types; `version_ids` resolve to VersionRecord; explanatory/lifecycle reason references resolve to ClaimRecord; version constraints target platform/product/telemetry-provider/technology entities. VersionRecord subjects are limited to EntityRecord or SourceRecord. Coverage scope subjects resolve to EntityRecord.
