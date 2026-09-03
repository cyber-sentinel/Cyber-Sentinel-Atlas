# System Context

## Logical Architecture

```text
                 ┌───────────────────────────┐
                 │       Source Registry     │
                 │ official docs / datasets  │
                 └─────────────┬─────────────┘
                               │ ingest
                               ▼
                 ┌───────────────────────────┐
                 │ Normalization & Validation│
                 │ schema / license / claims │
                 └─────────────┬─────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Atlas Knowledge Core                     │
│ entities │ claims │ relationships │ provenance │ versions   │
└───────────────┬───────────────────┬─────────────────────────┘
                │                   │
                ▼                   ▼
      ┌────────────────┐   ┌────────────────────┐
      │ Search Indexes │   │ Retrieval / Graph  │
      │ exact/text/vec │   │ traversal / RAG    │
      └───────┬────────┘   └─────────┬──────────┘
              │                      │
              └──────────┬───────────┘
                         ▼
         ┌────────────────────────────────┐
         │ Web/PWA │ Desktop │ API │ CLI │
         └────────────────────────────────┘
```

## Major Subsystems

1. Source Registry
2. Ingestion Pipeline
3. Canonical Knowledge Model
4. Claim & Provenance Store
5. Search Engine
6. Relationship/Graph Service
7. Grounded Retrieval Layer
8. Offline Pack Builder
9. API/CLI
10. Analyst Workspace
11. Validation and Release Pipeline

## Deployment Modes

### Public Hosted

Future globally accessible Atlas service.

### Offline Pack

Signed, versioned, local knowledge bundle.

### Self-Hosted

Potential future enterprise mode.

## Architectural Constraint

The web UI must not become the source of truth. The canonical content must remain portable and machine-readable.
