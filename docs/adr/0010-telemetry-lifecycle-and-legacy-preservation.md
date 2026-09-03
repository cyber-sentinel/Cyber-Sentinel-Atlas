# ADR-0010 — Telemetry Lifecycle and Legacy Preservation

**Status:** Accepted
**Decision:** 2026-09-03

## Context

Historical telemetry remains important for DFIR, legacy systems, old log archives, and cross-version investigation. Replacing historical identities with modern equivalents would destroy provenance and forensic meaning.

## Decision

Atlas never deletes historical telemetry merely because newer telemetry exists.

Each historically distinct telemetry definition retains its own canonical entity.

Required lifecycle states:

- current
- legacy
- deprecated
- superseded
- retired

Definitions:

### current

Supported/currently applicable telemetry.

### legacy

Valid historical telemetry associated primarily with older platform/product generations.

### deprecated

Explicitly deprecated or discouraged by an authoritative upstream source.

### superseded

A defined newer telemetry entity replaces or materially succeeds it.

### retired

No longer applicable to supported/current systems but preserved for historical investigation/reference.

## Applicability Metadata

Entities may declare:

- `valid_from`
- `valid_to`
- platform versions
- product versions
- provider versions

## Relationship Semantics

Historical relationships must be explicit graph relationships.

Supported semantics include:

- SUPERSEDES
- SUPERSEDED_BY
- EQUIVALENT_SIGNAL
- VERSION_OF
- RELATED_TO

Example:

```text
Windows Event 592
    ↓ EQUIVALENT_SIGNAL / SUPERSEDED_BY
Windows Event 4688
```

The exact relationship must be determined from authoritative source documentation or validated engineering evidence.

Atlas must not infer equivalence automatically.

## Alias Rule

Distinct historical Event IDs or record identities are not modeled merely as aliases when they are separately emitted telemetry identities.

## Consequences

Positive:

- historical logs remain resolvable offline;
- legacy/current analysis is explicit;
- migrations do not erase forensic identity.

Constraints:

- Phase 5.2 must model lifecycle and applicability;
- source/version evidence is required for historical relationship claims.
