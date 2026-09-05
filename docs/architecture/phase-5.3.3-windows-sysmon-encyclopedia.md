# Phase 5.3.3 — Windows Security + Sysmon Encyclopedia Pipeline

Status: **IMPLEMENTATION IN PROGRESS**

Phase 5.3.3 is the first product-acceptance ingestion domain for the Atlas Encyclopedia. It must prove source-backed Windows Security and Sysmon telemetry without collapsing documentation, provider inventory, product release data, or search projections into one source.

## Authority dimensions

Windows Security uses two independent authority dimensions:

1. **Documentation authority** — Microsoft Learn event/auditing documentation provides human-readable event meaning, documented fields, version notes, audit subcategory context, and source locators.
2. **Provider inventory authority** — provider metadata exported from an explicitly declared Windows reference build provides the denominator for telemetry completeness within that provider/channel/build scope.

Sysmon also uses two independent dimensions:

1. **Documentation/release authority** — the canonical source is `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon`; Microsoft command documentation may supplement it.
2. **Schema-export authority** — a version-pinned `sysmon -s all` export may be captured on a controlled reference host and imported as an immutable artifact.

A missing Microsoft Learn page is **not** proof that a telemetry identity does not exist. A documentation page count is never the denominator for telemetry completeness.

## Controlled reference-export boundary

Atlas ingestion core MUST NOT download or execute Windows, Sysmon, or other upstream binaries to generate inventory.

Approved collection pattern:

```text
Controlled Reference Host
  -> first-party metadata/schema export
  -> immutable raw export
  -> SHA-256 + byte length
  -> ReferenceExport descriptor
  -> operator review
  -> Atlas import boundary
  -> RawSnapshot / Parser / PSR
```

The initial collection methods are:

- Windows provider metadata: `wevtutil gp <Publisher> /ge:true /f:xml` or an equivalent Windows Event Log API exporter.
- Sysmon schema metadata: `sysmon -s all`.

The commands execute outside Atlas core. The exported artifact records reference environment product/version/build, architecture, locale, collector/tool version, command shape, collection timestamp, source identity, content digest, retention mode, and an immutable content reference.

This is an **out-of-band controlled import**, not an HTTPS/git connector and not a general internal-source connector.

Official collection-method references:

- `https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil`
- `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon`
- `https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sysmon`

## Initial acceptance identities

Phase 5.3.3 must preserve enough canonical metadata for Phase 5.4 to implement deterministic identifier resolution and catalog browsing.

Required acceptance cases include:

- `4688` — Microsoft Windows Security Auditing process creation telemetry, with provider/channel/version context.
- `592` — a historical/legacy Windows telemetry identity preserved independently; any relationship to newer telemetry must be evidence-backed and is never an alias collapse.
- `sysmon 1` — scoped lookup for Sysmon Event ID 1.
- a bare numeric identifier that exists in more than one provider must remain multiple canonical entities and later produce disambiguation.
- numeric Event IDs remain lossless strings in canonical data; Phase 5.4 derives numeric sorting only for identifier types registered as numeric.

Event ID alone is never global identity.

## Completeness contract

A Windows/Sysmon completeness statement is valid only when all of the following are declared:

- platform/product;
- provider;
- channel or telemetry source;
- product/release or OS version/build;
- inventory method and method version;
- immutable inventory digest;
- expected identity denominator;
- explicit missing/invalid/quarantined accounting.

`NOT_OBSERVED != REMOVED`.

Historical telemetry is never automatically deleted because a newer source/build no longer emits or documents it. Removal, retirement, supersession, or equivalence requires explicit evidence and review.

## Documentation completeness vs telemetry completeness

Atlas tracks documentation coverage separately from telemetry inventory coverage. An event known from an authoritative provider inventory remains browsable even when documentation is missing or partial. Its documentation status may be `missing` or `partial` without changing telemetry existence.

## Phase boundary

Phase 5.3.3 prepares a validated canonical corpus with provider/product/channel/native-ID/version/applicability/lifecycle/provenance metadata sufficient for exact-ID search and numeric catalog browsing.

The search index, ranking, resolver, and catalog projection are Phase 5.4. Signed content-pack runtime, installation, and rollback are Phase 5.5.

## Fixture policy

Repository fixtures for the reference-export contract are intentionally small, sanitized, and synthetic. They test identity, hashing, provenance, and execution boundaries only. They do not establish Windows or Sysmon completeness and must never be promoted as production inventory.
