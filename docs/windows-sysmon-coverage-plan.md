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
| Canonical records | 303 (`102` entities / `106` claims / `88` relationships / `7` sources) |
| Search projections | 16 |
| Graph edges | 3 |
| Packaged Windows Security examples | 2 (`4624`, `4688`) |
| Packaged Sysmon examples | 2 (`1`, `3`) |
| Encyclopedia-grade exemplars | 4 (`4624`, `4688`, Sysmon `1`, Sysmon `3`) |
| Clean-Windows acceptance evidence | Windows `4688` + Sysmon `1` |
| Public Preview corpus | No |
| Pack scope | `engineering-preview-fixture-only` |

The controlled Sysmon `15.22` / schema `4.91` reference baseline is **VALIDATED / OPERATOR REVIEWED / PROMOTED**. Reference workflow run `35413291632` produced `24` schema manifests and `587` parsed records, with `30` current Event IDs and no observed structural drift from the previous promoted baseline. Sysmon Events `1` and `3` are encyclopedia-grade; **28 Sysmon Event IDs remain** below the same content-depth contract. A sanitized structural-digest manifest binds approved Sysmon field sets, event versions and schema locators back to that controlled reference export without redistributing the raw export.

For `Microsoft-Windows-Security-Auditing / Security`, the controlled Windows Server 2025 Datacenter 24H2 build `26100.33296` inventory freezes an exact denominator of **423 unique Event IDs** (`488` provider event/version definitions). Windows `4624` and `4688` are encyclopedia-grade, so this narrowly scoped provider/build snapshot is **2/423 (0.47%)**, with **421** IDs below encyclopedia-grade. This number MUST NOT be presented as all-Windows completion. The global Windows denominator remains unfrozen until every mandatory telemetry family has an explicit provider/channel/version denominator.

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
   - Security-Auditing / Security / build `26100.33296`: **FROZEN — 423 IDs**;
   - Sysmon 15.22: **FROZEN — 30 documented/current IDs**;
   - all other mandatory Windows families: **NOT YET FROZEN**;
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

## Machine-readable coverage authorities

- `content/encyclopedia/coverage-manifest.json` — fail-closed family state; global Windows denominator remains unfrozen.
- `content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json` — exact Security-Auditing provider/build denominator and per-ID state.
- `content/encyclopedia/sysmon-15.22-coverage.snapshot.json` — exact Sysmon 15.22 denominator and per-ID state.

## Completion criteria

The approved Windows Security Corpus release is complete only when:

- the target denominator is machine-readable and frozen for every mandatory telemetry family;
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
