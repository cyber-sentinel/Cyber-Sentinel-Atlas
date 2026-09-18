# ATLAS Windows MVP & Approved Product Expansion

## Windows MVP Objective

Deliver an operationally useful Windows analyst product first, while preserving a universal canonical/security knowledge model that can be consumed by later CLI, Web, API, cross-platform Desktop and Mobile surfaces.

The Windows MVP implementation is engineering-ready. Public Preview release closure and corpus expansion remain active work.

## Mandatory Windows Security Corpus Scope

The approved Windows corpus is not limited to two demonstration events.

Mandatory telemetry families are:

- Microsoft-Windows-Security-Auditing / Security;
- Microsoft Sysmon;
- PowerShell Operational;
- Windows Defender native operational/security telemetry;
- AppLocker;
- WMI Activity;
- Task Scheduler Operational;
- Remote Desktop / Terminal Services;
- Windows Firewall / Windows Filtering Platform;
- DNS Client / DNS Server where applicable;
- Service Control Manager / service and process-persistence telemetry;
- additional persistence-relevant Windows providers admitted through explicit source/version/provenance review.

Additional knowledge relationships include:

- MITRE ATT&CK;
- selected D3FEND and CAR relationships where defensible;
- controlled DefenseOps detections/hunts;
- investigation and DFIR pivots;
- source/provenance metadata.

A telemetry family counts as covered only when its denominator/scope is explicit and its accepted records are canonicalized, provenance-bound, indexed, packed and tested.

## Shared Core

The frozen First Preview Shared Core provides:

- canonical local dataset contracts;
- exact identifier resolution;
- SQLite + FTS5 lexical search;
- bounded relationship graph traversal;
- claim-level provenance;
- versioned TUF-verified offline packs;
- schema/compatibility verification;
- trusted-time/highest-seen anti-rollback state;
- immutable generations;
- Last Known Good preservation;
- atomic activation and safe rollback;
- shared contracts consumed by product surfaces.

## Current End-User Surface — Windows Desktop

The selected Tauri 2.x Windows Desktop provides:

- fast offline lookup;
- exact and lexical search;
- canonical record detail;
- bounded relationship navigation;
- provenance visibility;
- verified pack state/update/rollback;
- diagnostics;
- no mandatory Internet connection for core installed-pack investigation.

The initial Public Preview release vehicle is a signed portable ZIP distributed through GitHub Releases once the mandatory PPR gates pass.

## Approved Subsequent Interfaces

The approved product family is:

```text
ATLAS
├── Desktop: Windows / Linux / macOS
├── CLI: Windows / Linux / macOS
├── Web
├── PWA: iOS Safari
├── API
└── Mobile: iOS / Android
```

Delivery sequence after Windows closure:

1. Windows Security Corpus expansion;
2. ATLAS CLI;
3. ATLAS Web + iOS Safari PWA;
4. ATLAS Public API;
5. Linux/macOS Desktop;
6. Native iOS/Android.

Desktop and Android browser use are covered by the normal Web surface and are not separate PWA product deliverables.

Grounded AI remains deferred until deterministic retrieval, provenance and release boundaries are mature.

## Quality

- schema validation;
- source/license/provenance validation;
- duplicate canonical-ID checks;
- version/freshness checks;
- machine-readable coverage snapshots with declared provider/channel/version denominator;
- detection coverage kept separate from telemetry coverage;
- exhaustive identifier and negative tests;
- exact-pack CI/release evidence.

## Explicitly Deferred From Windows Public Preview

- broad cloud corpus completion;
- broad Linux/macOS telemetry corpus completion;
- live SIEM integrations;
- enterprise multi-tenancy;
- production SOAR actions;
- automatic remediation;
- broad generative query conversion without validation;
- native mobile;
- Linux/macOS Desktop;
- public API/Web/PWA release.

Universal schema support for a domain does not imply that its corpus is already delivered.

## Windows Product Success Criteria

A Windows analyst can:

1. search a covered native identifier and resolve the correct canonical record deterministically;
2. understand provider/channel/version applicability;
3. inspect meaning, fields and security context present in the accepted corpus;
4. traverse defensible relationships without losing provenance;
5. inspect evidence behind material claims;
6. work against installed verified content without Internet access;
7. distinguish current/legacy/version-specific telemetry;
8. understand validation and applicability limitations;
9. update/rollback a trusted pack without corrupting Last Known Good;
10. distinguish an unknown/out-of-scope identifier from a broken search result.
