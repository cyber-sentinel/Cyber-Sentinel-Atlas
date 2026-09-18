# ATLAS Product Surfaces & Delivery Matrix

Status: **APPROVED PRODUCT FAMILY**

This document is the authoritative product-surface plan for Cyber-Sentinel ATLAS. The Windows Desktop is the current release-critical surface. The remaining approved surfaces are required product-family targets and are not optional ideas.

## Approved product family

```text
ATLAS
│
├── ATLAS Desktop
│    ├── Windows       ← current release-critical surface
│    ├── Linux
│    └── macOS
│
├── ATLAS CLI
│    ├── Windows
│    ├── Linux
│    └── macOS
│
├── ATLAS Web
│
├── ATLAS PWA
│    ├── Desktop
│    ├── Android
│    └── iOS Safari
│
├── ATLAS API
│
└── ATLAS Mobile
     ├── iOS
     └── Android
```

## Product-surface status

| Surface | Status | Core boundary |
| --- | --- | --- |
| Windows Desktop | **ENGINEERING READY / PUBLIC PREVIEW CLOSURE ACTIVE** | Tauri 2.x → bounded local Shared Core stdio |
| Linux Desktop | **APPROVED / FUTURE DELIVERY** | Must reuse canonical/shared contracts; platform boundary to be reviewed |
| macOS Desktop | **APPROVED / FUTURE DELIVERY** | Must reuse canonical/shared contracts; Apple signing/notarization required |
| Windows CLI | **APPROVED / PLANNED** | Official command: `atlas` |
| Linux CLI | **APPROVED / PLANNED** | Official command: `atlas` |
| macOS CLI | **APPROVED / PLANNED** | Official command: `atlas` |
| Web | **APPROVED / PHASE 5.7** | Browser-safe service boundary; no generic Shared Core bridge |
| PWA Desktop | **APPROVED / PHASE 5.7** | Same Web/PWA contract |
| PWA Android | **APPROVED / PHASE 5.7** | Installable web surface where platform permits |
| PWA iOS Safari | **APPROVED / PHASE 5.7** | Safari/PWA surface; distinct from native App Store product |
| Public API | **APPROVED / PHASE 5.8** | Versioned, authenticated, bounded read/search/graph/source/pack interfaces |
| Native iOS | **APPROVED / FUTURE DELIVERY** | Requires a reviewed mobile-core/library boundary, Apple signing and App Store controls |
| Native Android | **APPROVED / FUTURE DELIVERY** | Requires a reviewed mobile-core/library boundary and Android signing/distribution controls |

## Shared product rules

Every ATLAS surface must preserve the same knowledge and trust invariants:

- canonical schema and identifiers remain shared;
- provenance remains claim/source bound;
- deterministic retrieval remains authoritative before optional semantic/AI augmentation;
- content-pack trust and release provenance are explicit;
- no product surface may silently create a second canonical truth;
- no generic UI-to-core arbitrary method bridge is allowed;
- platform-specific transports must have explicit ACLs, input bounds and versioned contracts;
- product-specific packaging/signing does not weaken content-pack trust;
- accessibility and platform-native security requirements are release gates for the applicable surface.

## Delivery dependency order

The approved sequencing is:

```text
Windows Public Preview closure
        ↓
Windows + Sysmon knowledge coverage expansion
        ↓
ATLAS CLI
        ↓
ATLAS Web + PWA
        ↓
ATLAS Public API
        ↓
Linux Desktop / macOS Desktop
        ↓
Native iOS / Native Android
```

This sequence is a dependency order, not a calendar commitment.

## Windows knowledge coverage boundary

The current Engineering Usable Data Preview proves the runtime and packaged analyst flow, but it is **not** the complete Windows knowledge corpus.

Current packaged engineering evidence:

- `23` canonical records;
- `14` search projections;
- `3` graph edges;
- Windows Security Event ID `4688` end-to-end verified;
- Sysmon Event ID `1` end-to-end verified;
- engineering pack scope: `engineering-preview-fixture-only`;
- `public_preview_corpus=false`.

The pinned Sysmon 15.21 source profile documents 30 event IDs: `1..29` plus `255`. Current packaged acceptance guarantees Event ID `1`; full Sysmon event-ID coverage therefore still requires 29 additional documented event IDs to be represented, provenance-bound and acceptance-tested.

Windows Security/Event Log coverage does not yet have an approved exhaustive denominator. "All Windows Event IDs" spans multiple providers/channels and cannot be represented honestly by one unqualified percentage. Coverage must first be frozen by provider/channel/version and then measured through machine-readable coverage snapshots.

## Required coverage completion model

For a record to count as **covered**, it must pass all applicable stages:

```text
Authoritative source pinned
        ↓
Acquisition / immutable snapshot
        ↓
Normalization
        ↓
Canonical AtlasRecord
        ↓
Claims + provenance
        ↓
Relationships / mappings where justified
        ↓
Search projection + SQLite/FTS5 index
        ↓
Pack inclusion
        ↓
Record-level validation
        ↓
Search / Record / Graph / Provenance acceptance
        ↓
CoverageSnapshot = VERIFIED
```

A source profile, parser, or mention in documentation does not by itself count as product coverage.

## Planned Windows telemetry coverage families

The coverage program will start with security-relevant, high-value Windows telemetry families and expand under explicit provider/channel/version denominators, including:

- Microsoft-Windows-Security-Auditing / Security;
- Microsoft Sysmon;
- PowerShell Operational;
- Windows Defender / Defender for Endpoint-adjacent native telemetry where redistributable and applicable;
- Task Scheduler Operational;
- WMI Activity;
- Windows Firewall / Filtering Platform;
- AppLocker;
- Terminal Services / Remote Desktop Services;
- DNS Client/Server where applicable;
- Windows Update and service/process persistence-relevant providers;
- other Windows providers only after source, licensing, schema and security relevance are reviewed.

The goal is broad and eventually comprehensive security telemetry knowledge, without pretending that every Windows provider/version is already covered.

## Native mobile distinction

PWA on iOS/Android and native mobile applications are separate products.

The PWA may run through supported browsers and install-to-home-screen capabilities. Native iOS/Android require a separately reviewed mobile runtime boundary. The Windows child-process `atlas-core.exe` model must not be copied blindly to mobile platforms.

Native iOS release additionally requires Apple Developer identity, signing, provisioning/entitlements, privacy declarations, App Store packaging and review. Native Android requires its own signing, manifest/permission, packaging and store/distribution controls.
