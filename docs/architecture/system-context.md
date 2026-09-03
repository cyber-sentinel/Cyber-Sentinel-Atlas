# System Context

## Logical Architecture

```text
                  ┌───────────────────────────┐
                  │      Official Sources     │
                  │ vendors / MITRE / repos   │
                  └─────────────┬─────────────┘
                                │
                                ▼
                  ┌───────────────────────────┐
                  │ Raw Snapshot / Source Reg │
                  └─────────────┬─────────────┘
                                ▼
                  ┌───────────────────────────┐
                  │ Parser → Normalizer       │
                  │ Schema / Diff / Tests     │
                  └─────────────┬─────────────┘
                                ▼
                  ┌───────────────────────────┐
                  │ Human Review / Pack Build │
                  │ sign / checksum / release │
                  └─────────────┬─────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                     Atlas Knowledge Core                     │
│ entities │ native IDs │ claims │ graph │ provenance │ lifecycle│
└───────────────┬────────────────────┬─────────────────────────┘
                │                    │
                ▼                    ▼
      ┌─────────────────┐   ┌────────────────────┐
      │ Search Indexes  │   │ Graph / Retrieval  │
      │ exact / lexical │   │ traversal / later  │
      └────────┬────────┘   └─────────┬──────────┘
               └────────────┬─────────┘
                            ▼
                ┌──────────────────────┐
                │ Offline Pack Runtime │
                │    / Shared Core     │
                └──────────┬───────────┘
                           ▼
            ┌──────────────────────────────┐
            │ Windows Desktop → Web / PWA │
            │      → API / CLI → AI       │
            └──────────────────────────────┘
```

## Major Subsystems

1. Source Registry
2. Raw Snapshot Store/Registry
3. Parser Layer
4. Normalization Layer
5. Schema/Inventory Validation
6. Human Review and Release Pipeline
7. Canonical Knowledge Model
8. Claim & Provenance Store
9. Lifecycle/Version Model
10. Coverage Measurement
11. Deterministic Search Engine
12. Relationship/Graph Service
13. Offline Pack Builder and Runtime
14. Shared Product Contracts
15. Windows Desktop
16. Web/PWA
17. API/CLI
18. Grounded Retrieval/AI
19. Validation and Release Pipeline

## Content Trust Boundary

DefenseOps is an approved defensive engineering source, not an automatic authority.

Its content follows:

```text
DefenseOps
    ↓
versioned ingestion
    ↓
provenance + validation
    ↓
controlled Atlas pack release
    ↓
Atlas Knowledge Core
```

## Deployment / Interface Direction

### Windows Desktop

First full end-user interface, with offline lookup as a core requirement.

### Web / PWA

Follows the shared runtime and canonical contracts.

### API / CLI

Consume the same contracts. Official CLI command: `atlas`.

### Offline Pack

Signed, versioned, checksummed, compatibility-aware local knowledge content.

### Self-Hosted

Potential future enterprise mode; not an MVP requirement.

## Architectural Constraints

- no UI is the source of truth;
- canonical content remains portable and machine-readable;
- exact search works without AI;
- upstream sources do not directly mutate production content;
- storage/database/framework technology is not part of the universal domain model.
