# ATLAS Windows Telemetry Source Authority Policy

Status: **APPROVED**

## Purpose

Define which source is allowed to drive analyst-facing Quick Detail content for Windows Security and Sysmon records, while preserving independent provenance and legal/redistribution controls.

## Windows Security Event IDs

### Primary Quick Detail Reference

**Ultimate Windows Security — Windows Security Log Encyclopedia**

- index: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
- event pattern: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=<EVENT_ID>
- source role: `PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE`
- scope: analyst-facing coverage/section benchmark, external verification link, field-grouping and correlation-review reference.
- ingestion authority: **NO AUTOMATED OR BULK INGESTION** without explicit written permission from the rights holder.

### Quick Detail rule

For Windows Security Event IDs, Ultimate Windows Security is the approved **external analyst-reference benchmark**, but its pages are not a bulk-ingestion feed.

Quick Detail must match the useful information classes an analyst expects from that reference — identity, OS applicability, category/subcategory, success/failure type, legacy/corresponding events, field groups, value semantics, version notes and correlation pivots — while the redistributable ATLAS facts are independently authored from Microsoft/provider evidence.

The UI displays the exact Ultimate Windows Security event URL as the Primary External Reference.

If the rights holder later grants written ingestion/redistribution permission, this policy may be upgraded through an explicit source-rights review.

### Redistribution boundary

Ultimate Windows Security is a copyrighted third-party reference whose published Terms restrict automated/manual retrieval processes used to index, database, data-mine or reproduce the site.

Unless explicit written permission is obtained, ATLAS must not scrape, crawl, bulk-extract, mirror, or package the site's prose/content as a competing encyclopedia corpus.

ATLAS may safely preserve an outbound event reference URL and use the site as a human review/UX benchmark. Redistributable field facts and analysis are authored independently from sources with an accepted ingestion/rights boundary.

The public corpus must not become a mirror or substantial recreation of the reference site.

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

If Microsoft/provider evidence and the external UWS reference appear to disagree:

1. do not silently merge the disagreement;
2. retain the conflict in review evidence;
3. treat Microsoft/provider evidence as canonical technical verification;
4. show an applicability/uncertainty state when material;
5. preserve the UWS outbound reference for analyst comparison;
6. update ATLAS facts only after source/version review.

## Product goal

Quick Detail should feel like a high-quality security-event encyclopedia response:

- immediate;
- field-oriented;
- version-aware;
- correlation-aware;
- operationally useful;
- concise enough for first response;
- expandable into the full Record & Provenance workspace.
