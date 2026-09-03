# ADR-0006 — Shared Core and Interface Sequencing

**Status:** Accepted
**Decision:** 2026-09-03

## Context

Atlas has explicit requirements for fast offline Windows lookup. The previous roadmap implied a Web/PWA-first sequence, which did not reflect that requirement.

## Decision

The authoritative implementation sequence is:

```text
Canonical Data Model
        ↓
Source / Ingestion Core
        ↓
Deterministic Search Core
        ↓
Offline Pack Runtime / Shared Core
        ↓
Windows Desktop MVP
        ↓
Web / PWA
        ↓
API / CLI
        ↓
Grounded AI
```

The offline pack runtime is part of the shared core required by the Desktop MVP, not a feature added afterward.

Windows Desktop requirements include:

- fast offline lookup;
- exact identifier resolution;
- lexical search;
- local canonical dataset;
- relationship navigation;
- provenance visibility;
- no mandatory Internet connection;
- signed pack updates;
- safe rollback.

Portable Windows mode remains an approved requirement candidate for evaluation.

## Technology Stack

Tauri, Rust, SQLite, React, and TypeScript remain candidates only.

Stack selection requires an implementation spike and a dedicated ADR.

The architectural requirement is:

```text
portable embedded local storage
+
shared canonical contracts
+
offline deterministic search
+
secure signed update support
```

not a specific framework or database.

## Consequences

Positive:

- satisfies the explicit offline Windows requirement;
- keeps the canonical model independent of UI technology;
- allows Desktop, Web/PWA, API, and CLI to share contracts.

Constraints:

- implementation stack remains open;
- portable packaging requires later evaluation.
