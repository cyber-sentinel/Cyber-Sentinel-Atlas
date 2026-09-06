# Phase 5.5.1 — Pack Trust Contracts

Status: **IMPLEMENTATION IN REVIEW**

## Purpose

Phase 5.5.1 converts the Phase 5.3 `PACK_READY` boundary into explicit signed-pack trust and contract surfaces without yet implementing the full installer/runtime.

This slice freezes only:

- the TUF-based trust/update model in ADR-0023;
- `.atlaspack` as the offline content transport;
- Pack Manifest v1;
- Source/License Inventory v1;
- target namespace and non-executable payload rules;
- publication and path-safety invariants;
- activation prerequisites and LKG/rollback semantics at contract level.

It does not freeze the production Shared Core language, HSM/KMS vendor, application binary updater, Desktop stack, or Web/PWA packaging.

## Contract flow

```text
PACK_READY
  -> Pack Manifest v1
  -> Source/License Inventory v1
  -> TUF target metadata
  -> .atlaspack transport
  -> bounded extraction
  -> TUF verification
  -> Atlas contract validation
  -> compatibility / licensing / search validation
  -> immutable staging
  -> health check
  -> atomic activation
  -> LKG
```

Phase 5.5.1 implements and tests the bolded contract boundaries up to Atlas validation. Full archive extraction, TUF repository generation/verification, durable runtime state and atomic installation belong to Phase 5.5.2.

## Authority boundaries

Canonical Atlas records remain authoritative. SPC and SQLite search artifacts are derived/disposable. The pack manifest may describe a prebuilt search index only as `derived: true`; runtime acceptance still requires binding validation or rebuild.

No new AtlasRecord family is introduced. `schemas/v1/` remains untouched.

## Publication gate

A public/releasable pack fails closed when any included third-party source has licensing state other than `verified-redistributable`, or when required source/license evidence is missing. Reference-only sources can remain in provenance/reference metadata but cannot be represented as redistributed content.

## Security controls

Contract validation rejects unsafe target paths, active-code extensions, duplicate artifact paths, manifest/inventory identity mismatch and publication-ineligible included sources.

Phase 5.5.2 must additionally enforce ZIP-entry type/size/count/ratio bounds, TUF threshold/freshness/rollback verification and immutable activation.

## Exit criteria

Phase 5.5.1 is complete only when:

- ADR-0023 is accepted and present;
- both v1 schemas validate themselves;
- positive fixtures validate;
- negative fixtures/tests cover path traversal, Windows-reserved names, executable payloads, duplicate target paths, identity mismatch and licensing fail-closed behavior;
- Linux and Windows CI pass on the exact reviewed head;
- no `schemas/v1/` file changes;
- PR diff remains limited to Phase 5.5.1 contracts/tests/docs/CI.
