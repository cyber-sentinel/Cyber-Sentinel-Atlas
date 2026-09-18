# ATLAS Product Vision

## Vision

Build a fast, trustworthy and operationally useful cyber-defense knowledge and investigation platform for analysts, detection engineers, incident responders, security architects and defenders worldwide.

ATLAS should let a defender move from **a raw technical signal** to **security meaning, evidence and defensive context** without opening a collection of disconnected vendor documents and rule repositories.

## Example User Journey

A user searches:

`4688`

ATLAS should resolve the correct Windows Security event and, where the accepted corpus supports it, provide:

- canonical identity;
- provider/channel/platform/version applicability;
- prerequisites / audit-policy context;
- important fields;
- security relevance;
- related Windows/Sysmon telemetry;
- ATT&CK relationships;
- D3FEND/CAR context where defensible;
- detection/hunting opportunities;
- DFIR pivots;
- false-positive/interpretation considerations;
- source-backed claims;
- version/freshness/provenance.

The product must clearly distinguish unavailable or unverified relationships rather than manufacture completeness.

## North Star

**Time-to-understanding and time-to-investigation should be materially lower than using fragmented documentation and disconnected defensive content, while preserving evidence and uncertainty.**

## Approved Product Family

```text
ATLAS
├── Desktop: Windows / Linux / macOS
├── CLI: Windows / Linux / macOS
├── Web
├── PWA: iOS Safari
├── API
└── Mobile: iOS / Android
```

Windows Desktop is the current release-critical surface. All later surfaces reuse canonical/provenance/trust contracts and must not create a second source of truth.

## Approved Windows Security Corpus

The Windows knowledge program includes:

- Security-Auditing;
- Sysmon;
- PowerShell Operational;
- Windows Defender;
- AppLocker;
- WMI Activity;
- Task Scheduler Operational;
- RDP / Terminal Services;
- Windows Firewall / Filtering Platform;
- DNS;
- Service/persistence telemetry.

Coverage is measured against explicit provider/channel/version denominators rather than marketing counts.

## Product Outcomes

ATLAS succeeds when users can:

1. find a covered security concept/event quickly;
2. understand why it matters;
3. traverse relationships without losing context;
4. inspect evidence behind material claims;
5. distinguish verified, unavailable and out-of-scope knowledge;
6. operate against verified installed content without Internet access;
7. consume the same canonical knowledge across Desktop, CLI, Web/API and future mobile surfaces;
8. use future AI assistance without losing provenance or canonical-vs-generated distinction;
9. improve/correct content through a governed engineering workflow.

## Non-Goals

ATLAS is not intended to:

- replace SIEM, EDR, SOAR or CTI platforms;
- claim complete telemetry coverage without a frozen denominator;
- claim vendor-specific validation without evidence;
- republish restricted/copyrighted documentation wholesale;
- obscure uncertainty behind generated prose;
- force every concept into every query/detection language;
- treat an AI answer, UI page or search index as canonical truth.
