# Offline-first Architecture

## Principle

Offline is not an export feature. It is a supported operating mode and part of the shared runtime required before the Windows Desktop MVP.

Authoritative decisions:

- [ADR-0003 — Offline-first Core](../adr/0003-offline-first.md)
- [ADR-0006 — Shared Core and Interface Sequencing](../adr/0006-shared-core-and-interface-sequencing.md)
- [ADR-0009 — Controlled Content Release Pipeline](../adr/0009-controlled-content-release-pipeline.md)

## Offline Core

The MVP offline runtime should support:

- canonical entities;
- native identifiers and aliases;
- claims;
- relationships;
- lifecycle/applicability metadata;
- source metadata;
- selected source excerpts/locators where redistribution permits;
- exact search index;
- lexical search index;
- coverage metadata;
- saved analyst workspace where product design requires it;
- product schema/version metadata.

## Content Pack Model

Atlas requires independent, versioned content packs.

Candidate names currently include:

```text
atlas-core
atlas-windows
atlas-sysmon
atlas-mitre-attack
atlas-defenseops
```

Additional domain packs are expected later.

**Exact final pack naming is an open architecture decision.**

A released pack must support:

- content version;
- schema version;
- source version;
- source provenance;
- checksum;
- signature;
- compatibility;
- freshness;
- coverage;
- validation status;
- rollback.

## Controlled Publication

No source directly updates installed/production Atlas content.

See [Controlled Content Release Pipeline](content-release-pipeline.md).

## Client Update Flow

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

Failure requires rollback to Last Known Good.

## Shared Runtime Position

The approved sequence is:

```text
Deterministic Search Core
        ↓
Offline Pack Runtime / Shared Core
        ↓
Windows Desktop MVP
        ↓
Web / PWA
```

The Desktop application must not require Internet connectivity for core lookup/search/navigation over installed packs.

## Local Storage Requirement

The architecture requires portable embedded local storage and deterministic offline search.

The exact database/storage engine remains an open implementation decision.

## Windows Desktop Requirement

The first full end-user interface must support:

- fast offline lookup;
- exact identifier resolution;
- lexical search;
- local canonical dataset;
- relationship navigation;
- provenance visibility;
- signed pack updates;
- safe rollback.

Portable Windows mode remains an approved requirement candidate.

## Web / PWA

Web/PWA follows the shared core/Desktop MVP and uses the same canonical model/contracts.

It must not become a separate source of truth.
