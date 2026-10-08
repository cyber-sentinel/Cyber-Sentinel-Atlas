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

Current controlled progress after bounded Windows Security Log Batch 14:

- Windows Security Log UWS review benchmark: `246/422` listed identities encyclopedia-grade (`58.29%`), `176` remaining;
- newly promoted Security-Auditing IDs in this batch: `4948`, `4949`, `4950`, `4951`, `4952`, `4953`, `4954`, `4956`, `4957`, `4958`;
- Windows Security Auditing provider coverage: `240/423` encyclopedia-grade with `183` provider-specific identities remaining;
- the provider denominator itself remains frozen at `423` unique IDs / `488` Event ID-version definitions;
- Sysmon 15.22: `30/30` complete;
- global Windows denominator: intentionally unfrozen.

The benchmark progress counter is an analyst-facing Security-log coverage measure, not a replacement for provider-specific denominators and not an all-Windows completion percentage.

## Planning rule

After each bounded batch is promoted, rebuild the controlled UWS benchmark queue from fresh `main` and select only identities actually listed by the benchmark and independently supported by Microsoft/provider evidence. The next batch must be derived from that rebuilt queue rather than from a continuous numeric range.
