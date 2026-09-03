# API & CLI Architecture

## API Principles

- stable canonical IDs;
- versioned API surface;
- entity-first design;
- explicit provenance;
- no UI-only hidden semantics.

## Candidate API Resources

```text
GET /v1/entities/{id}
GET /v1/events/{id}
GET /v1/techniques/{id}
GET /v1/detections/{id}
GET /v1/hunts/{id}
GET /v1/search
GET /v1/graph/{id}
GET /v1/sources/{id}
GET /v1/claims/{id}
GET /v1/packs
```

## Search API

Should support:

- q
- entity_type
- platform
- provider
- attack_id
- engine
- validation_level
- source_class
- offline_pack

## CLI Direction

The former Sentinel Forge CLI concept becomes an Atlas interface.

Candidate commands:

```text
atlas search 4688
atlas show atlas:event:windows-security:4688
atlas related T1059.001
atlas detection DET-WIN-001
atlas export DET-WIN-001 --engine splunk-spl
atlas hunt HUNT-WIN-001 --engine microsoft-kql
atlas sources atlas:event:windows-security:4688
atlas pack list
atlas pack verify atlas-windows.pack
atlas validate
```

## CLI Rule

The CLI must consume the same canonical model/API contracts as the web application. It must not become a second knowledge implementation.
