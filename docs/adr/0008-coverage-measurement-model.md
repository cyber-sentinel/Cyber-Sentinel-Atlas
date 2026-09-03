# ADR-0008 — Coverage Measurement Model

**Status:** Accepted
**Decision:** 2026-09-03

## Context

Atlas must measure both the completeness of telemetry knowledge and the completeness/maturity of defensive detection content. These are different questions and cannot share one mutable percentage.

## Decision

Telemetry Coverage and Detection Coverage are separate first-class measurements.

### Telemetry Coverage

Measures completeness of Atlas telemetry knowledge against a declared authoritative inventory and declared source/pack/version scope.

Conceptual states include:

- Expected
- Collected
- Normalized
- Validated
- Published
- Missing
- Invalid

100% Telemetry Coverage means 100% of the declared authoritative inventory for the stated scope/version is represented and valid.

It does not claim knowledge of every possible record a technology might emit outside the declared inventory.

### Detection Coverage

Measures defensive detection/hunting coverage over a declared scope.

It may consider:

- behaviors/techniques covered;
- telemetry requirements available;
- validated detections available;
- engine/backend implementation coverage;
- validation maturity.

Detection Coverage does not need to reach 100% for a telemetry pack to be telemetry-complete.

### Snapshot Model

Coverage is recorded through versioned `CoverageSnapshot` / `CoverageRecord` objects.

Every coverage value must declare:

- metric type;
- scope;
- denominator;
- source/inventory version;
- pack/content version;
- measurement timestamp;
- counts/state breakdown;
- validation status.

## Required Rule

```text
Telemetry Coverage != Detection Coverage
```

A valid state may be:

```text
Telemetry Coverage: 100%
Detection Coverage: 72%
```

## Consequences

Positive:

- prevents misleading completeness claims;
- allows telemetry packs to be complete even when defensive analytics are still growing;
- enables historical coverage reporting.

Constraints:

- coverage denominator/inventory must be explicit;
- production schema design occurs in Phase 5.2.
