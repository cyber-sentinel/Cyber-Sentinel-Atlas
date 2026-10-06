# Windows Security Log Coverage Scope

Status: **ACTIVE / CONTROLLED REVIEW BENCHMARK**

## Purpose

ATLAS distinguishes the broad **Windows Security Log** analyst-facing review scope from any single Windows event provider denominator.

The Windows Security Log review benchmark is aligned with the Ultimate Windows Security **Windows Security Log Encyclopedia** index at:

`https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx`

As reviewed on 2026-10-05, that index is sparse and lists **422 unique Windows Security Log Event IDs**, beginning at Event ID `1100` and ending at Event ID `8191`.

This means the Security Log scope is **not** the continuous arithmetic range `1100..8191`. Only Event IDs actually admitted by controlled source review count as benchmark identities.

The opening entries include:

- `1100` — event logging service shutdown;
- `1101` — audit events dropped by transport;
- `1102` — audit log cleared;
- `1104` — Security log full;
- `1105` — event log automatic backup;
- `1108` — event logging service error;
- `4608` — Windows startup.

The final benchmark entry is `8191`, described by the external benchmark as the highest system-defined audit message value.

## Authority model

Ultimate Windows Security remains a **coverage and Quick Detail review benchmark**. It is not the canonical semantic authority for ATLAS.

For every promoted Event ID:

1. Microsoft official documentation and controlled provider/channel/version evidence remain authoritative for identity, fields, versions and semantics;
2. Ultimate Windows Security is reviewed manually for analyst-facing Quick Detail comparison and coverage awareness;
3. no bulk ingestion of third-party prose is permitted;
4. material disagreement between Microsoft/provider evidence and the external benchmark must be recorded and resolved fail-closed rather than silently merged;
5. each promoted record still requires provenance, deterministic search/pack projection, tests and normal release gates.

## Relationship to the frozen Security-Auditing denominator

The existing frozen denominator remains independently valid for:

`Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296`

That provider-specific scope contains **423 unique Event IDs / 488 Event ID-version definitions** and is measured separately.

The Windows Security Log review benchmark and the Microsoft-Windows-Security-Auditing provider denominator MUST NOT be treated as interchangeable sets merely because their counts are numerically close.

In particular, the Security Log benchmark contains the `1100`-series Event IDs before `4608`, so ATLAS coverage planning must include those identities instead of describing modern Security Log coverage as beginning at `4608`.

## Current controlled coverage

At the time this scope correction was introduced:

- Windows Security Auditing provider coverage: `10/423` encyclopedia-grade;
- remaining provider-specific identities: `413`;
- Sysmon 15.22: `30/30` complete;
- global Windows denominator: intentionally unfrozen.

This document changes the **review and product scope framing**; it does not falsely convert the external benchmark into a release denominator and does not grant encyclopedia-grade status to any newly admitted Event ID.

## Planning rule

The next Security Log coverage work must prioritize the previously omitted `1100`-series identities (`1100`, `1101`, `1102`, `1104`, `1105`, `1108`) before continuing the later uncovered Security-Auditing queue, while preserving provider-specific denominators and provenance.
