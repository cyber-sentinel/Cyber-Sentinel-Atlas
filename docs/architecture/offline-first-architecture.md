# Offline-First Architecture

## Principle

Offline operation is not an export feature. It is a first-class supported mode for installed ATLAS content.

Authoritative decisions include:

- ADR-0003 — Offline-first Core;
- ADR-0006 — Shared Core and Interface Sequencing;
- ADR-0022 — SQLite + FTS5 deterministic search;
- ADR-0023 — Secure Content Pack Trust and Update Model;
- ADR-0024 — Go Production Shared Core;
- ADR-0025 — Bounded child-process stdio interface;
- ADR-0026 — Tauri 2.x Windows Desktop host.

## Offline Core

The installed runtime supports or carries contracts for:

- canonical records/entities;
- native identifiers and aliases;
- claims and provenance;
- relationships;
- lifecycle/applicability/version metadata;
- source metadata;
- exact resolver;
- SQLite + FTS5 lexical search;
- coverage metadata;
- pack/schema/version metadata;
- trusted pack state and Last Known Good.

## Content Pack Model

ATLAS uses independent, versioned `.atlaspack` content with TUF-based trust.

A release pack carries or binds:

- content/schema/source versions;
- provenance;
- target hashes;
- trust metadata;
- compatibility;
- freshness;
- coverage;
- validation state.

Exact public pack naming may evolve without weakening these contracts.

## Client Pack Lifecycle

```text
Candidate Pack
      ↓
TUF / target verification
      ↓
Path / extraction safety
      ↓
Schema / compatibility checks
      ↓
Immutable generation install
      ↓
Health gate
      ↓
Atomic activation
      ↓
ACTIVE
      ↓
Last Known Good / safe rollback when required
```

Trusted-time and highest-seen state prevent silent rollback to older trusted metadata after newer metadata has been accepted.

## Current Shared Runtime Position

```text
SQLite + FTS5 Search
        ↓
Verified Pack Runtime
        ↓
Go Shared Core
        ↓
Windows Desktop
        ↓
CLI / Web / API and later platform surfaces
```

The Windows Desktop must not require Internet connectivity for core lookup/search/navigation over installed verified packs.

## Local Storage

SQLite + FTS5 is the accepted deterministic search artifact under ADR-0022.

Canonical records and provenance remain authoritative; the search database is a derived deterministic artifact rather than a second source of truth.

## Approved Product Expansion

Offline/shared contracts must remain reusable by:

- Windows/Linux/macOS CLI;
- Web and iOS Safari PWA through a reviewed service boundary;
- public API;
- Linux/macOS Desktop;
- future native mobile where platform storage/runtime constraints are separately reviewed.

No future surface may weaken pack trust merely to simplify platform packaging.
