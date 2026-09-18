# Windows & Sysmon Knowledge Coverage Plan

Status: **APPROVED / IMPLEMENTATION REQUIRED**

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

The latest downloaded Engineering Usable Data Preview evidence reports:

| Measure | Current engineering pack |
| --- | ---: |
| Canonical records | 23 |
| Search projections | 14 |
| Graph edges | 3 |
| Windows Security IDs end-to-end acceptance-tested | 1 (`4688`) |
| Sysmon IDs end-to-end acceptance-tested | 1 (`1`) |
| Public Preview corpus | No |
| Pack scope | `engineering-preview-fixture-only` |

For Sysmon 15.21, the pinned source profile lists 30 documented event IDs (`1..29`, `255`). Therefore 29 documented IDs remain outside the current packaged end-to-end acceptance guarantee.

No honest percentage is assigned yet to "all Windows Event IDs" because Windows event telemetry spans many providers/channels and the exhaustive denominator has not yet been frozen.

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

## Completion criteria

A Windows/Sysmon coverage release is complete only when:

- the target denominator is machine-readable and frozen;
- every in-scope identifier has an explicit state;
- no ID is silently omitted;
- every `VERIFIED` record has authoritative provenance;
- generated search/index artifacts match the canonical corpus;
- unknown/reserved/deprecated cases are represented intentionally;
- automated exhaustive identifier lookup passes;
- sampled semantic review passes;
- clean packaged Windows acceptance passes;
- the final coverage manifest is bound to the exact pack/package digest.
