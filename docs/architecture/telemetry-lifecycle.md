# Telemetry Lifecycle and Legacy Preservation

Authoritative decision: [ADR-0010](../adr/0010-telemetry-lifecycle-and-legacy-preservation.md).

## Preservation Rule

Atlas never deletes a historical telemetry identity merely because newer telemetry exists.

Each historically distinct telemetry definition retains its own canonical entity and remains searchable, including offline where its pack is installed.

## Lifecycle States

### current

Supported/currently applicable telemetry.

### legacy

Valid historical telemetry associated primarily with older product/platform generations.

### deprecated

Explicitly deprecated/discouraged by the authoritative upstream source.

### superseded

A defined newer telemetry entity replaces or materially succeeds the older telemetry definition.

### retired

No longer applicable to supported/current systems but retained for historical investigation/reference.

## Applicability Metadata

Lifecycle status is complemented by applicability such as:

- `valid_from`
- `valid_to`
- platform versions
- product versions
- provider versions

Exact Phase 5.2 field design is not defined here.

## Historical Relationships

Supported semantic relationships include:

- SUPERSEDES
- SUPERSEDED_BY
- EQUIVALENT_SIGNAL
- VERSION_OF
- RELATED_TO

Old/new mappings require authoritative source or validated engineering evidence.

Atlas must not infer equivalence automatically.

## Example

```text
atlas:event:microsoft.windows.security:592
        ↓ SUPERSEDED_BY / EQUIVALENT_SIGNAL
atlas:event:microsoft.windows.security:4688
```

The exact relationship used in a real record depends on source-backed evidence.

The two Event IDs remain distinct canonical telemetry identities and must not be collapsed into aliases.

## Alias Boundary

Aliases improve lookup but do not erase lifecycle/history.

Historical names and source-native forms may be aliases only when they refer to the same canonical identity.
