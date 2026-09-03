# Coverage Model

Authoritative decision: [ADR-0008](../adr/0008-coverage-measurement-model.md).

## Core Rule

```text
Telemetry Coverage != Detection Coverage
```

They are separate first-class measurements.

## Telemetry Coverage

Telemetry Coverage measures Atlas completeness against a declared authoritative inventory and a declared scope/version.

Conceptual inventory states:

```text
Expected
Collected
Normalized
Validated
Published
Missing
Invalid
```

100% Telemetry Coverage means all records in the declared authoritative denominator for the stated scope/version are represented and valid.

It does **not** mean Atlas knows every possible telemetry record a technology may ever emit outside that declared inventory.

## Detection Coverage

Detection Coverage measures defensive analytic coverage over a declared scope.

It may include:

- behaviors/ATT&CK techniques covered;
- required telemetry availability;
- validated detection availability;
- hunting coverage;
- engine/backend implementation coverage;
- validation maturity.

Detection Coverage may remain incomplete even when the telemetry inventory is complete.

Example:

```text
Telemetry Coverage: 100%
Detection Coverage: 72%
```

## Versioned Snapshot Model

Coverage is historical/versioned state, not one mutable percentage on an entity.

A future `CoverageSnapshot` / `CoverageRecord` model must carry at minimum:

- coverage type;
- declared scope;
- denominator definition;
- denominator count;
- numerator/count/state breakdown;
- authoritative inventory/source version;
- content/pack version;
- schema version;
- measured_at;
- validation status.

## Interpretation Rule

Every displayed coverage percentage must answer:

1. Coverage of **what**?
2. Against **which denominator**?
3. For **which source/product/pack version**?
4. At **what validation maturity**?
5. Measured **when**?

Without those fields, Atlas must not present the value as a completeness claim.
