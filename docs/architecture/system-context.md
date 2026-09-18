# ATLAS System Context

## Logical Architecture

```text
                   Authoritative Sources
             vendors / MITRE / approved repos
                         │
                         ▼
             Acquisition / Raw Snapshot
                         │
                         ▼
          Parser → Normalizer → Lineage
                         │
                         ▼
        Inventory / Diff / Validation / Review
                         │
                         ▼
               Canonical Knowledge
 entities • native IDs • claims • relationships
       provenance • applicability • lifecycle
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
      SQLite + FTS5            Bounded Graph
   deterministic search       relationship view
             └───────────┬───────────┘
                         ▼
               Verified .atlaspack
           TUF trust / LKG / rollback
                         │
                         ▼
                Production Shared Core
                         │
        ┌────────────────┼─────────────────┐
        ▼                ▼                 ▼
 Windows Desktop      ATLAS CLI         Web / API
        │                                  │
        │                                  └── iOS Safari PWA
        │
        ├── future Linux/macOS Desktop
        └── future native iOS/Android through
            separately reviewed platform boundaries
```

Grounded AI is a later optional consumer of canonical/retrieval evidence and never becomes canonical truth.

## Major Subsystems

1. Source Registry
2. Raw Snapshot / Acquisition
3. Parser Layer
4. Normalization / Lineage
5. Inventory / Coverage Diff
6. Validation / Human Review / Promotion
7. Canonical Knowledge Model
8. Claim & Provenance Model
9. Lifecycle / Applicability / Versioning
10. Coverage Measurement
11. SQLite + FTS5 Deterministic Search
12. Bounded Relationship / Graph Retrieval
13. TUF Content-Pack Builder and Runtime
14. Go Production Shared Core
15. Windows Desktop
16. ATLAS CLI
17. ATLAS Web
18. iOS Safari PWA
19. Public API
20. Future Linux/macOS Desktop
21. Future Native Mobile
22. Grounded Retrieval / AI
23. Release / Supply-Chain / Accessibility Controls

## Content Trust Boundary

DefenseOps is an approved defensive engineering source, not automatic ATLAS authority.

```text
DefenseOps
    ↓
versioned ingestion
    ↓
provenance + validation
    ↓
controlled ATLAS pack release
    ↓
ATLAS Canonical Knowledge
```

## Product Surface Direction

### Windows Desktop

Current release-critical end-user surface. Offline lookup is a core requirement.

### CLI

Approved for Windows, Linux and macOS. It consumes shared canonical/search/graph/pack contracts and must not become a second knowledge implementation.

### Web

Approved browser surface using bounded, versioned service contracts.

### iOS Safari PWA

Approved installable web experience for iPhone/iPad. It is distinct from the native iOS App Store product.

### Public API

Approved versioned/authenticated/auditable service boundary. It must not expose a generic arbitrary Shared Core bridge.

### Linux / macOS Desktop

Approved future desktop surfaces with platform-specific packaging/signing/accessibility controls.

### Native iOS / Android

Approved future native surfaces requiring a dedicated mobile-core/library boundary. The Windows child-process sidecar model is not assumed to be suitable for mobile.

## Architectural Constraints

- no UI or API is the canonical source of truth;
- canonical content remains portable and machine-readable;
- exact search works without AI;
- upstream sources do not directly mutate active production content;
- product surfaces consume shared contracts rather than duplicating security/search semantics;
- platform packaging/signing requirements may vary without changing canonical truth.
