# ATLAS Windows Telemetry Source Authority Policy

Status: **APPROVED SOURCE POLICY**

## Purpose

This policy defines the primary semantic reference used by ATLAS for Windows Security Event IDs and Sysmon Event IDs.

The goal is to keep the analyst-facing answer consistent and predictable while preserving ATLAS provenance, licensing, versioning and validation rules.

## Windows Security Event IDs

### Primary Quick Detail reference

For Windows Security Log Event IDs, the approved primary analyst-reference source is:

- Ultimate Windows Security — Windows Security Log Encyclopedia
- Base URL: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
- Event URL pattern: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={EVENT_ID}

The **Quick Detail / Quick Response** surface for a Windows Security Event ID is driven by factual content normalized from this primary reference.

Applicable categories include, where present:

- Event ID and title;
- supported/observed Windows operating-system generations;
- category/subcategory;
- success/failure type;
- legacy/corresponding Event IDs;
- short event purpose;
- field groups and field names;
- field-level semantics;
- version-introduced fields;
- enumerated/value dictionaries;
- correlations to other Event IDs;
- collection/audit-policy notes;
- security-relevant caveats.

### Quick Detail source isolation

For a Windows Security Event Quick Detail response:

- Ultimate Windows Security is the primary semantic reference;
- content from unrelated sources must not be silently mixed into the Quick Detail text;
- any ATLAS-authored interpretation must be visibly labeled as ATLAS analysis rather than source fact;
- deeper Record & Provenance views may separately show corroborating authoritative sources, but the Quick Detail source identity remains explicit.

### Redistribution boundary

Ultimate Windows Security identifies its site content as copyrighted/all-rights-reserved. ATLAS therefore must not package or reproduce substantial page prose or full examples verbatim without separate permission.

ATLAS may instead:

- retain source URL and retrieval metadata;
- normalize factual event identifiers, titles, field names, platform/version facts and value dictionaries where legally appropriate;
- independently author concise field explanations and security analysis;
- preserve claim-level provenance back to the source;
- link the analyst to the original page.

The target UX may mirror the **information architecture** of the reference page without copying protected explanatory prose wholesale.

## Sysmon

### Primary semantic authority

For Sysmon, the approved primary source is Microsoft Sysinternals / Microsoft Learn:

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

ATLAS uses the Microsoft Learn page as the canonical public semantic reference for:

- current Sysmon release context;
- Event ID names and descriptions;
- operational log/channel information;
- configuration behavior;
- filter tags and event filtering semantics;
- documented field/configuration guidance.

For deterministic release ingestion, ATLAS may bind the corresponding MicrosoftDocs/sysinternals repository document to an exact commit/blob while retaining the Learn URL as the canonical public reference.

### Current freshness observation

The Microsoft Learn page currently identifies Sysmon **v15.22**, published **2026-09-10**.

The existing controlled ATLAS Sysmon schema/export baseline is older and must be refreshed/validated before ATLAS claims current 15.22 schema coverage.

Documentation freshness and telemetry-schema freshness are separate states and must not be conflated.

## Source precedence

For the approved Windows Security Corpus:

1. Windows Security Event Quick Detail semantics → Ultimate Windows Security Encyclopedia.
2. Sysmon Event semantics → Microsoft Sysinternals / Microsoft Learn Sysmon page.
3. Provider/schema exports → controlled Windows/Sysmon reference exports for field/version denominator and structural validation.
4. MITRE ATT&CK / D3FEND / CAR → their own pinned authoritative sources.
5. ATLAS analysis → independently authored and explicitly identified as ATLAS defensive analysis.

No lower-precedence source may silently overwrite a higher-precedence source's Quick Detail semantics.

## Provenance requirement

Every Quick Detail payload must record:

- source ID;
- source URL;
- source role;
- retrieved/snapshot date;
- source version/revision when available;
- transformation type;
- validation state.

A Quick Detail payload with missing source identity is not release-eligible.
