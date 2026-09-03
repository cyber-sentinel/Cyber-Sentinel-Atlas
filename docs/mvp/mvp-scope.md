# MVP Scope

## MVP Objective

Deliver a product that is already useful to Windows/SOC analysts before expanding horizontally, while preserving a universal underlying telemetry model.

## In Scope

### Content

- Windows Security Events — prioritized security-relevant subset;
- Sysmon Events;
- PowerShell operational/security telemetry;
- Active Directory relationships;
- MITRE ATT&CK mappings;
- selected D3FEND/CAR relationships where authoritative mapping is defensible;
- DefenseOps Windows PowerShell/LOLBin detections;
- DefenseOps threat hunts;
- investigation pivots;
- source/provenance metadata.

### Shared Core

- canonical local dataset;
- exact identifier resolution;
- lexical search;
- relationship graph traversal;
- claim-level provenance;
- versioned/signed/checksummed offline packs;
- schema/compatibility verification;
- last-known-good preservation;
- atomic install and rollback-safe updates;
- shared contracts consumed by all interfaces.

### First Full End-User Interface — Windows Desktop

- fast offline lookup;
- exact identifier search;
- lexical search;
- relationship navigation;
- provenance visibility;
- no mandatory Internet connection;
- signed pack updates;
- safe rollback.

Portable Windows mode remains an approved requirement candidate and must be evaluated during Desktop design.

### Subsequent Interfaces

- Web/PWA using the same canonical model and shared contracts;
- read-only API;
- official `atlas` CLI for search/read/relationship/pack operations;
- grounded AI only after deterministic retrieval and provenance are mature.

### Quality

- schema validation;
- link/source validation where technically possible;
- duplicate canonical-ID checks;
- provenance-required checks;
- version/freshness checks;
- telemetry coverage snapshots with declared scope/version/denominator;
- detection coverage snapshots kept separate from telemetry coverage;
- CI.

## Explicitly Deferred

- full cloud content coverage;
- full Linux/macOS content coverage;
- every database;
- live SIEM integrations;
- enterprise multi-tenancy;
- production SOAR actions;
- automatic remediation;
- broad generative query conversion without validation;
- large social/community features.

Universal schema support for deferred domains does not require their ingestion during the MVP.

## MVP Success Criteria

A Windows analyst can:

1. search Event ID 4688 and land on the correct canonical entity instantly;
2. inspect meaning and important fields;
3. traverse to Sysmon/ATT&CK/detections/hunts;
4. inspect source-backed claims;
5. use the same core content offline;
6. distinguish current and historical/legacy telemetry;
7. copy a relevant validated query where available;
8. understand validation and applicability limitations;
9. update a signed local pack without risking corruption of the last-known-good dataset.
