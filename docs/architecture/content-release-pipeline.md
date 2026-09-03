# Controlled Content Release Pipeline

Authoritative decision: [ADR-0009](../adr/0009-controlled-content-release-pipeline.md).

## Publication Principle

External sources never directly mutate the production/public Atlas dataset.

## Build / Publication Flow

```text
Official Source
        ↓
Raw Snapshot
        ↓
Parser
        ↓
Normalizer
        ↓
Schema Validation
        ↓
Inventory Diff
        ↓
Tests
        ↓
Human Review
        ↓
Signed Content Pack
        ↓
Release
```

## Stage Responsibilities

### Official Source

Resolve against the Atlas source authority policy.

### Raw Snapshot

Preserve source/version/retrieval metadata and an immutable or checksummed representation sufficient for reproducibility, subject to licensing constraints.

### Parser

Extract source-native structures without silently normalizing away identity.

### Normalizer

Map parsed content into Atlas canonical contracts while preserving native identifiers and provenance.

### Schema Validation

Reject structurally invalid canonical content before publication.

### Inventory Diff

Report additions, removals, lifecycle changes, source version changes, and unexpected coverage gaps against the declared inventory.

### Tests

Run deterministic validation for schema, IDs, relationships, provenance, lifecycle, coverage and source-specific invariants.

### Human Review

Mandatory review gate for release-impacting changes.

### Signed Content Pack

Package validated content with manifest, versions, checksum/signature metadata, coverage metadata and compatibility constraints.

### Release

Only reviewed/signed artifacts become installable Atlas content.

## Client Installation / Update

```text
Released Pack
        ↓
Manifest Verification
        ↓
Signature Verification
        ↓
Checksum Verification
        ↓
Schema/Compatibility Check
        ↓
Preserve Last Known Good
        ↓
Atomic Install
        ↓
Index/Migration
        ↓
Health Check
        ↓
Activation
```

If any mandatory step fails:

```text
Failure
  ↓
Rollback to Last Known Good
```

## Open Implementation Decisions

- pack-signing algorithm/format;
- code-signing integration;
- key-management and rotation;
- exact pack archive format;
- delta update implementation;
- exact health-check implementation.

Those decisions require separate architecture work and must not be inferred from this document.
