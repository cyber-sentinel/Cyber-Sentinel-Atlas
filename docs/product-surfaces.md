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

The Engineering Usable Data Preview proves the runtime and packaged analyst flow, but it is **not** the complete Windows knowledge corpus. Public Preview corpus authority remains fail-closed.

The current Phase 5.10.10 coverage control plane freezes two bounded denominators:

| Family | Frozen scope | Encyclopedia grade | Remaining |
| --- | --- | ---: | ---: |
| Windows Security Auditing | `Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296` — 423 unique Event IDs / 488 provider event-version definitions | `2/423` — Event IDs `4624`, `4688` | 421 |
| Sysmon | Sysmon `15.22`, 30 documented/current Event IDs with controlled schema `4.91` reference evidence | `15/30` — Event IDs `1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, `9`, `10`, `11`, `12`, `13`, `14`, `15` | 15 |

The authoritative machine-readable ledger is `content/encyclopedia/coverage-manifest.json`.

The global Windows denominator is deliberately **not frozen** and `global_windows_completion_percent` remains null. PowerShell Operational, Windows Defender, AppLocker, WMI Activity, Task Scheduler Operational, RDP/Terminal Services, Windows Firewall/Filtering Platform, DNS, and Service/persistence telemetry still require their own controlled provider/channel/version denominators.

ATLAS therefore does not publish an unqualified "all Windows Event IDs" completion percentage.

The engineering package remains a controlled preview surface and does not become Public Preview corpus authority merely because individual records reach `ENCYCLOPEDIA_GRADE`.

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

## Native mobile distinction

The approved PWA deliverable is the **iOS Safari PWA** for iPhone/iPad. Desktop and Android are covered by the normal ATLAS Web surface and are not separate PWA product deliverables in the current roadmap.

The iOS Safari PWA may use supported install-to-home-screen capabilities. Native iOS/Android remain separate products and require a separately reviewed mobile runtime boundary. The Windows child-process `atlas-core.exe` model must not be copied blindly to mobile platforms.

Native iOS release additionally requires Apple Developer identity, signing, provisioning/entitlements, privacy declarations, App Store packaging and review. Native Android requires its own signing, manifest/permission, packaging and store/distribution controls.
