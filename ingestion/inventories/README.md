# Authoritative Inventories

This directory contains machine-readable inventories used to measure source completeness and detect controlled change.

ATLAS keeps documentation inventories separate from telemetry/provider inventories. Current evidence includes Windows Security Auditing provider scope, Sysmon documentation scope, and controlled Sysmon schema inventories, with historical baselines preserved for drift analysis.

## Rules

- every inventory declares its exact source/provider/version scope;
- denominators must be explicit before percentages are published;
- inventory changes are reviewed through deterministic diffs;
- deprecated, historical, reserved, missing, and version-specific identities are represented intentionally;
- inventory presence alone does not make a record `ENCYCLOPEDIA_GRADE` or release-ready.

Current product coverage authority is machine-readable and intentionally centralized:

- `content/encyclopedia/coverage-manifest.json` — family-level coverage authority;
- `content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json` — Windows Security Auditing denominator and accepted numerator;
- `content/encyclopedia/sysmon-15.22-coverage.snapshot.json` — Sysmon 15.22 denominator and accepted numerator.

Moving numerator counters are not duplicated in this inventory README. Human-readable status documents must be synchronized to these files, never the reverse.
