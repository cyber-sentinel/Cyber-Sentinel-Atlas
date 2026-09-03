# Security Architecture

## Security Objectives

- protect update integrity;
- prevent malicious content ingestion;
- prevent source/provenance tampering;
- protect user workspace data;
- prevent AI prompt/context abuse from changing canonical knowledge;
- keep secrets out of source content;
- make offline packs verifiable.

## Trust Boundaries

1. external source → ingestion;
2. ingestion → canonical store;
3. canonical store → derived indexes;
4. API → client;
5. user content → workspace;
6. retrieved content → AI context;
7. update service → offline pack.

## Required Controls

### Ingestion

- source allowlisting;
- content-type limits;
- schema validation;
- size limits;
- checksum;
- parser isolation where appropriate;
- license metadata;
- provenance required before promotion.

### Canonical Knowledge

- append-aware change history;
- immutable source identifiers where possible;
- review state;
- validation state;
- auditability.

### Offline Packs

- signed manifest;
- cryptographic checksums;
- schema version;
- source/content versions;
- rollback to last known-good pack.

### API

- strict input validation;
- rate limiting for hosted mode;
- safe query construction;
- authorization for private/user workspace content;
- security headers;
- no secrets in client bundles.

### AI

Treat retrieved documents and community content as untrusted input.

The model must not be able to:

- modify canonical records;
- silently promote Draft content;
- execute arbitrary commands;
- override system security rules through retrieved text.

## Supply Chain

- pin critical build dependencies;
- generate SBOM for distributable application artifacts;
- dependency scanning;
- secret scanning;
- signed releases;
- reproducible build goals.

## Privacy

The public knowledge graph should not require user telemetry.

Private notes, saved investigations, or enterprise content must be isolated from public knowledge data.
