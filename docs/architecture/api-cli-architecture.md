# ATLAS API & CLI Architecture

## Ownership Boundary

ATLAS owns consumer/search/investigation interfaces and the official `atlas` CLI.

DefenseOps owns defensive content engineering. DefenseOps content remains subject to ATLAS ingestion, provenance, validation and release controls before it becomes ATLAS knowledge.

## Approved Product Interfaces

- CLI: Windows / Linux / macOS;
- Web;
- iOS Safari PWA through the Web service boundary;
- Public API;
- future Linux/macOS Desktop consumers;
- future native mobile through a separately reviewed mobile boundary.

## API Principles

- stable canonical IDs;
- versioned API surface;
- authenticated/authorized operation where non-local exposure exists;
- bounded resource/method allowlists;
- explicit provenance;
- no UI-only hidden semantics;
- native identifiers preserved separately from ATLAS canonical IDs;
- deterministic retrieval remains authoritative;
- no generic arbitrary pass-through to Shared Core methods;
- auditability, input bounds and rate/resource protection appropriate to deployment mode.

## Candidate API Resources

```text
GET /v1/search
GET /v1/records/{id}
GET /v1/relationships/{id}
GET /v1/sources/{id}
GET /v1/claims/{id}
GET /v1/coverage
GET /v1/packs/status
```

Exact resources remain a Phase 5.8B implementation decision and must map to bounded product semantics rather than mirror internal methods mechanically.

## Search API

Future filters may include:

- q;
- record/entity type;
- namespace;
- native identifier type/value;
- platform;
- provider/channel;
- ATT&CK ID;
- source class;
- lifecycle/applicability;
- pack/coverage scope.

Exact identifier resolution precedes lexical/semantic augmentation.

## CLI Direction

The approved user-facing command is:

```text
atlas
```

Planned examples:

```text
atlas search 4688
atlas search "Sysmon Event 1"
atlas record atlas:event:microsoft.windows.security:4688
atlas graph atlas:event:microsoft.windows.security:4688
atlas source show <source-id>
atlas pack status
atlas pack verify
```

JSON output is an approved requirement for automation-oriented commands where applicable.

## CLI Rule

CLI must consume the same canonical/search/graph/pack contracts as other surfaces. It must not become a second implementation of canonical truth.

## Open Implementation Decisions

Still open for the future interface phases:

- exact CLI packaging/distribution per OS;
- exact Web/API framework;
- API authentication/deployment profiles;
- mobile-core/library boundary;
- broader graph service implementation;
- customer/enterprise overlay and persistence models.

SQLite + FTS5, Go Shared Core, canonical schema, TUF pack trust, Windows Tauri host and the First Preview seven-command desktop boundary are **not** open decisions.
