# ATLAS Telemetry Source Authority Policy

Status: **APPROVED**

## Purpose

Define which source is allowed to drive analyst-facing Quick Detail content for Windows Security and Sysmon records, while preserving independent provenance and legal/redistribution controls.

## Windows Security Event IDs

### Primary Quick Detail Reference

**Ultimate Windows Security — Windows Security Log Encyclopedia**

- index: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
- event pattern: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=<EVENT_ID>
- source role: `PRIMARY_QUICK_DETAIL_REFERENCE`
- scope: Windows Security Event ID analyst-facing description, field grouping, field/value semantics, version notes, corresponding events, correlation guidance and operational explanation.

### Quick Detail rule

For Windows Security Event IDs, the Quick Detail pane is derived from this reference only.

Other sources may support:

- canonical identity validation;
- provider/channel/version verification;
- schema/manifest validation;
- Full Record provenance;
- source conflict review;
- legal/redistribution review.

They must not silently alter the analyst-facing Quick Detail content.

If Ultimate Windows Security does not provide a fact needed by the Quick Detail contract, ATLAS displays an explicit unavailable/not-provided state rather than filling that Quick Detail field from another source.

### Redistribution boundary

Ultimate Windows Security is a copyrighted third-party reference. ATLAS must not redistribute substantial verbatim page prose without explicit rights.

ATLAS may:

- retain the source URL and attribution;
- extract factual identifiers, field names, categories, versions and value relationships where legally permissible;
- independently author concise ATLAS wording that preserves the factual meaning;
- structure the facts into ATLAS field/value/correlation records;
- provide the source link for analyst verification.

The public corpus must not become a mirror of the reference site.

## Sysmon

### Primary Quick Detail Reference

**Microsoft Sysinternals — Sysmon**

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

- source role: `PRIMARY_QUICK_DETAIL_REFERENCE`
- scope: Sysmon event identities, event meaning, event behavior, configuration/filtering context and analyst-facing Quick Detail.

The Microsoft-published Sysmon schema/manifest may additionally provide exact field names/types/version structure as technical evidence, but the analyst-facing Quick Detail remains anchored to the official Sysmon documentation.

### Current source freshness

As of 2026-09-18 the official Microsoft page identifies **Sysmon v15.22**, published 2026-09-10.

Release ingestion must use an immutable pinned MicrosoftDocs revision rather than relying only on the floating Learn page.

## Provenance display

Every Quick Detail must visibly identify:

- Primary Reference;
- source URL;
- source/retrieval or pinned version;
- ATLAS transformation state;
- validation state.

The Full Record & Provenance workspace may expose additional authoritative/secondary evidence without changing the Quick Detail source-role contract.

## Conflict handling

If another source disagrees with the Primary Quick Detail Reference:

1. do not silently merge the disagreement;
2. retain the conflict in review evidence;
3. keep the last accepted Quick Detail fact until reviewed;
4. show an applicability/uncertainty state when material;
5. update the Quick Detail only after source-role review.

## Product goal

Quick Detail should feel like a high-quality security-event encyclopedia response:

- immediate;
- field-oriented;
- version-aware;
- correlation-aware;
- operationally useful;
- concise enough for first response;
- expandable into the full Record & Provenance workspace.
