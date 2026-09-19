# Windows & Sysmon Knowledge Coverage Plan

Status: **ACTIVE MANDATORY WINDOWS SECURITY CORPUS / IMPLEMENTATION IN PROGRESS**

## Objective

Expand ATLAS from a verified engineering-fixture pack into a measurable, provenance-first Windows security knowledge corpus.

The objective is not merely to store Event IDs. Each covered item must answer, where authoritative evidence permits:

- what the event/telemetry represents;
- provider/channel and version applicability;
- trigger conditions;
- important fields and interpretation;
- security meaning and investigation pivots;
- related events/artifacts;
- ATT&CK / D3FEND / CAR relationships when defensible;
- detection/hunting context where sourced or independently authored;
- source/version/provenance;
- validation and coverage state.

## Current measured baseline

The current engineering-preview builder and merged Phase 5.10.10 content report:

| Measure | Current engineering pack |
| --- | ---: |
| Canonical records | 230 (`79` entities / `79` claims / `65` relationships / `7` sources) |
| Search projections | 16 |
| Graph edges | 3 |
| Packaged Windows Security examples | 2 (`4624`, `4688`) |
| Packaged Sysmon examples | 2 (`1`, `3`) |
| Encyclopedia-grade exemplars | 3 (`4624`, `4688`, Sysmon `3`) |
| Clean-Windows acceptance evidence | Windows `4688` + Sysmon `1` |
| Public Preview corpus | No |
| Pack scope | `engineering-preview-fixture-only` |

The controlled Sysmon `15.22` / schema `4.91` reference baseline is now **VALIDATED / OPERATOR REVIEWED / PROMOTED**. Reference workflow run `35413291632` produced `24` schema manifests and `587` parsed records, with `30` current Event IDs and no observed structural drift from the previous promoted baseline. Sysmon Event `3` is encyclopedia-grade; **29 Sysmon Event IDs remain** to reach the same content-depth contract.

No honest percentage is assigned yet to "all Windows Event IDs" because Windows event telemetry spans many providers/channels and the exhaustive denominator has not yet been frozen.

## Approved mandatory Windows Security Corpus scope

The following telemetry families are **approved mandatory corpus scope**, not optional backlog items:

1. **Microsoft-Windows-Security-Auditing / Security**
2. **Microsoft Sysmon**
3. **PowerShell Operational**
4. **Windows Defender native operational/security telemetry** and Defender for Endpoint-adjacent native Windows telemetry where authoritative and redistributable
5. **AppLocker**
6. **WMI Activity**
7. **Task Scheduler Operational**
8. **Remote Desktop / Terminal Services**
9. **Windows Firewall / Windows Filtering Platform**
10. **DNS Client and DNS Server telemetry where applicable**
11. **Windows Service Control Manager and service/persistence-relevant telemetry**
12. **Additional persistence-relevant Windows providers** admitted only through explicit source/version/provenance review

A Windows corpus is not considered **complete for the approved scope** merely because Security-Auditing and Sysmon are complete. Every mandatory family above requires a frozen provider/channel/version denominator, explicit coverage states, provenance, index/pack inclusion and acceptance evidence.

Where a provider has no meaningful numeric Event-ID denominator or changes across Windows versions, coverage is measured by the authoritative manifest/provider contract rather than by a fabricated percentage.

## Coverage workstreams

1. **Denominator freeze**
   - define provider/channel/version scope;
   - generate machine-readable expected-ID inventories;
   - distinguish documented IDs, manifest-derived IDs, deprecated/reserved IDs and version-specific IDs.

2. **Authoritative acquisition**
   - pin source revision or immutable snapshot;
   - capture source hash and retrieval metadata;
   - fail closed on semantic drift.

3. **Canonicalization**
   - create deterministic canonical records;
   - preserve native ID/provider/channel/version;
   - attach lifecycle/applicability data.

4. **Security enrichment**
   - independently authored security interpretation;
   - ATT&CK/D3FEND/CAR relationships only where supported;
   - detection/hunting/DFIR pivots without copying restricted source text.

5. **Index and graph**
   - exact identifier aliases;
   - FTS5 lexical projection;
   - bounded graph relationships;
   - deterministic ordering.

6. **Pack and trust**
   - include accepted records in governed pack;
   - bind source/license inventory;
   - validate TUF target hashes and immutable generation behavior.

7. **Acceptance**
   - per-ID lookup tests;
   - negative/unknown-ID tests;
   - provider/channel disambiguation tests;
   - Record/Provenance tests;
   - graph relationship tests;
   - clean-Windows package acceptance;
   - coverage manifest consistency.

## Encyclopedia-grade depth requirement

A telemetry identifier does **not** count toward release coverage merely because the identifier resolves.

The mandatory content-depth contract is defined in [`docs/content/telemetry-record-content-contract.md`](content/telemetry-record-content-contract.md).

Only records that reach `ENCYCLOPEDIA_GRADE` — including applicable field dictionary, field semantics, version applicability, collection prerequisites, value semantics, correlation pivots and provenance — count toward the release numerator.

This prevents shallow records such as "Event ID exists and has a title" from being reported as complete corpus coverage.

## Completion criteria

The approved Windows Security Corpus release is complete only when:

- the target denominator is machine-readable and frozen;
- every in-scope identifier has an explicit state;
- no ID is silently omitted;
- every `VERIFIED` record has authoritative provenance;
- generated search/index artifacts match the canonical corpus;
- unknown/reserved/deprecated cases are represented intentionally;
- automated exhaustive identifier lookup passes;
- sampled semantic review passes;
- clean packaged Windows acceptance passes;
- the final coverage manifest is bound to the exact pack/package digest;
- every mandatory telemetry family in the approved scope has an explicit provider/channel/version coverage snapshot;
- no mandatory family is silently deferred without a documented release exception approved by the maintainer.
