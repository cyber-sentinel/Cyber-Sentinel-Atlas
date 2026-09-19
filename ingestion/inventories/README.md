# Authoritative Inventories

This directory contains machine-readable inventories used to measure source completeness and detect controlled change.

ATLAS keeps documentation inventories separate from telemetry/provider inventories. Current evidence includes Windows Security Auditing provider scope, Sysmon documentation scope, and controlled Sysmon schema inventories, with historical baselines preserved for drift analysis.

## Rules

- every inventory declares its exact source/provider/version scope;
- denominators must be explicit before percentages are published;
- inventory changes are reviewed through deterministic diffs;
- deprecated, historical, reserved, missing, and version-specific identities are represented intentionally;
- inventory presence alone does not make a record `ENCYCLOPEDIA_GRADE` or release-ready.

Current product coverage authority is summarized in `content/encyclopedia/coverage-manifest.json`.
