# Telemetry Record Content Contract

Status: **MANDATORY FOR WINDOWS SECURITY CORPUS ACCEPTANCE**

## Purpose

An Event ID or telemetry record is not considered covered merely because ATLAS can resolve its identifier.

For Windows Security, Sysmon and the approved Windows telemetry families, a record reaches **ENCYCLOPEDIA_GRADE** only when ATLAS can explain the record at field level with source-backed semantics and operational context.

## Quick Detail source rule

- Windows Security Event IDs: analyst-facing Quick Detail is derived from the Ultimate Windows Security event page for that Event ID.
- Sysmon Event IDs: analyst-facing Quick Detail is derived from the official Microsoft Sysinternals Sysmon documentation.
- Full Record & Provenance may contain additional verification sources, but those sources must not silently rewrite Quick Detail.
- Missing primary-reference content is represented explicitly rather than filled from another reference.

## Required record sections

Every applicable telemetry record must carry or resolve to:

1. **Identity**
   - canonical ID;
   - native Event/record ID;
   - provider;
   - channel/log;
   - title;
   - event version(s);
   - minimum/supported platform/version applicability.

2. **Collection prerequisites**
   - audit policy / logging prerequisite;
   - optional policy/settings required for additional fields;
   - default-on/default-off state where authoritative evidence exists;
   - security/privacy caveats where collection may expose secrets.

3. **Field dictionary**
   - field/section name;
   - native field name;
   - data type;
   - meaning;
   - event-version applicability;
   - optional/conditional status;
   - normalization notes;
   - known encoded/enumerated values;
   - field-specific provenance.

4. **Value semantics**
   - symbolic/encoded values and meanings;
   - SID/RID/integrity/elevation/value dictionaries where applicable;
   - value applicability by event/provider version.

5. **Correlation pivots**
   - related Event IDs or telemetry;
   - correlation key;
   - correlation direction;
   - scope/uniqueness limitations;
   - version/applicability constraints.

6. **Security interpretation**
   - why the record matters;
   - defensive investigation pivots;
   - suspicious patterns;
   - false-positive/normal-context considerations;
   - explicit separation between source fact and ATLAS-authored defensive analysis.

7. **Relationships**
   - related Windows/Sysmon telemetry;
   - ATT&CK/D3FEND/CAR relationships where evidence supports them;
   - detection/hunting/DFIR context where governed content exists;
   - no forced mapping when no verified mapping exists.

8. **Provenance**
   - source identity;
   - source version/revision/retrieval date;
   - claim-level or field-level locator;
   - transformation type;
   - reviewer/validation state.

## Coverage states

A telemetry identifier can have these product coverage states:

- `IDENTIFIED` — identifier/title/provider known;
- `STRUCTURED` — record fields/versions parsed;
- `SEMANTIC` — field meanings and prerequisites modeled;
- `PROVENANCE_VERIFIED` — material claims are evidence-bound;
- `ENCYCLOPEDIA_GRADE` — all applicable content requirements and acceptance tests pass.

Only `ENCYCLOPEDIA_GRADE` counts toward the release numerator for the approved Windows Security Corpus.

## Windows Security Event 4688 acceptance exemplar

Event 4688 must, at minimum, model and present the applicable semantics for:

- Creator Subject:
  - Security ID;
  - Account Name;
  - Account Domain;
  - Logon ID.
- Target Subject where supported:
  - Security ID;
  - Account Name;
  - Account Domain;
  - Logon ID.
- Process Information:
  - New Process ID;
  - New Process Name;
  - Token Elevation Type;
  - Mandatory Label;
  - Creator Process ID;
  - Creator Process Name;
  - Process Command Line.

The record must also represent version/applicability differences, including fields introduced in later event versions, without assuming every field exists on every supported Windows generation.

Operational correlations such as Logon ID → logon telemetry and process-ID relationships must record their limitations and must not imply global uniqueness.

## Redistribution rule

ATLAS must not copy substantial third-party explanatory text into the public pack unless redistribution rights permit it.

The product may:

- use authoritative sources as evidence/provenance;
- independently author field semantics and defensive analysis;
- retain facts, identifiers, field names, types, versions and normalized value dictionaries where legally permitted;
- cite/link secondary references.

Secondary commercial/community encyclopedias may be used for research and cross-checking, but their prose must not be copied wholesale into the ATLAS public corpus.

## UI acceptance

The Record & Provenance workspace must make field-level detail usable without exposing raw canonical JSON as the primary analyst experience.

The page must support:

- grouped field sections;
- field name/type;
- field meaning;
- version badge/applicability;
- enumerated/value dictionary;
- correlation hints;
- security interpretation;
- claim/source provenance;
- explicit unavailable/N/A state.

A field that has no accepted semantic claim must not be displayed as if its meaning were verified.

## Test acceptance

For every `ENCYCLOPEDIA_GRADE` record:

- all expected in-scope fields are present or explicitly N/A/version-excluded;
- field count matches the frozen source/provider inventory;
- field semantics resolve to valid field entities/claims;
- source locators exist;
- version applicability is testable;
- value dictionaries are deterministic;
- correlation pivots reference existing canonical records or explicit out-of-scope targets;
- search by Event ID and important field names resolves deterministically;
- packaged UI acceptance confirms the field-detail experience.
