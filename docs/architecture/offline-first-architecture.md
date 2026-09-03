# Offline-first Architecture

## Principle

Offline is not an export feature. It is a supported operating mode.

## Offline Core

The MVP offline package should include:

- canonical entities;
- claims;
- relationships;
- source metadata;
- selected source excerpts/locators where redistribution permits;
- exact search index;
- lexical search index;
- saved analyst workspace;
- product schema/version metadata.

## Pack Model

```text
atlas-core.pack
atlas-windows.pack
atlas-sysmon.pack
atlas-attack.pack
atlas-defenseops.pack
```

A pack is:

- versioned;
- signed;
- checksummed;
- schema-compatible;
- independently updateable where feasible.

## Update Model

```text
Installed Pack
    ↓
Manifest Check
    ↓
Signed Update Metadata
    ↓
Delta or Full Package
    ↓
Verify Signature + Checksum
    ↓
Atomic Replace
    ↓
Index Rebuild / Migration
```

## Conflict Rule

An interrupted update must not corrupt the last known-good offline dataset.

## Local Storage

Implementation should favor a portable embedded database for the MVP.

The storage engine remains an implementation decision; domain schemas must remain portable.

## PWA

The web client should support:

- application-shell caching;
- offline navigation;
- local search;
- cached knowledge packs;
- explicit online/offline state;
- safe synchronization when connectivity returns.
