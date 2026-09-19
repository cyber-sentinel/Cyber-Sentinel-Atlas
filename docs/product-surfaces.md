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
| PWA iOS Safari | **APPROVED / PHASE 5.7** | Installable Safari/PWA surface for iPhone/iPad; distinct from native App Store product |
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
ATLAS Web + iOS Safari PWA
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

- `303` canonical records (`102` entities, `106` claims, `88` relationships, `7` sources);
- `16` search projections;
- `3` graph edges;
- packaged Windows examples: Event IDs `4624` and `4688`;
- packaged Sysmon examples: Event IDs `1` and `3`;
- clean-Windows acceptance remains explicitly proven for Windows Security `4688` and Sysmon `1` on the published engineering evidence path;
- encyclopedia-grade exemplars: Windows Security `4624`, Windows Security `4688`, Sysmon `1`, Sysmon `3`;
- engineering pack scope: `engineering-preview-fixture-only`;
- `public_preview_corpus=false`.

The current controlled Sysmon baseline is `15.22` / schema `4.91`, validated on the reference host and promoted to the telemetry inventory. It contains the same 30 current Event IDs (`1..29` plus `255`) as the pinned 15.22 semantic documentation profile. Sysmon Events `1` and `3` are encyclopedia-grade; 28 Sysmon IDs remain to reach the same content depth before full Sysmon corpus coverage can be claimed.

The `Microsoft-Windows-Security-Auditing / Security` controlled provider/build scope now has a frozen 423-ID denominator for Windows Server 2025 Datacenter 24H2 build `26100.33296`, with `4624` and `4688` encyclopedia-grade. This provider/build snapshot is `2/423` (`0.47%`) and is not an all-Windows percentage. The global Windows denominator remains unfrozen because the other mandatory providers/channels/versions are not yet frozen.

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

## Approved mandatory Windows Security Corpus families

The following are approved mandatory ATLAS corpus families:

- Microsoft-Windows-Security-Auditing / Security;
- Microsoft Sysmon;
- PowerShell Operational;
- Windows Defender native operational/security telemetry and Defender for Endpoint-adjacent native Windows telemetry where authoritative and redistributable;
- AppLocker;
- WMI Activity;
- Task Scheduler Operational;
- Terminal Services / Remote Desktop Services;
- Windows Firewall / Windows Filtering Platform;
- DNS Client / DNS Server where applicable;
- Service Control Manager and service/process persistence-relevant telemetry;
- additional persistence-relevant Windows providers admitted through explicit source, licensing, schema and security-relevance review.

"Complete Windows Security Corpus" means coverage of this approved scope under frozen provider/channel/version denominators. It does not mean every Event Log provider ever shipped by Microsoft, and ATLAS will not fabricate a universal percentage across undefined providers.

Machine-readable coverage authority: `content/encyclopedia/coverage-manifest.json`.

## Native mobile distinction

The approved PWA deliverable is the **iOS Safari PWA** for iPhone/iPad. Desktop and Android are covered by the normal ATLAS Web surface and are not separate PWA product deliverables in the current roadmap.

The iOS Safari PWA may use supported install-to-home-screen capabilities. Native iOS/Android remain separate products and require a separately reviewed mobile runtime boundary. The Windows child-process `atlas-core.exe` model must not be copied blindly to mobile platforms.

Native iOS release additionally requires Apple Developer identity, signing, provisioning/entitlements, privacy declarations, App Store packaging and review. Native Android requires its own signing, manifest/permission, packaging and store/distribution controls.
