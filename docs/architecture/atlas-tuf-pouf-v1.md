# Atlas TUF POUF / Profile v1

Status: **ACCEPTED PROFILE FOR PHASE 5.5.1**

This document narrows ADR-0023 into the concrete TUF profile used by Atlas content packs. It does not define application binary updates.

## Repository model

Atlas uses the four top-level TUF roles: `root`, `targets`, `snapshot`, and `timestamp`.

Production minimum policy:

- Root: at least 3 keys, threshold 2, offline and independently controlled.
- Targets: at least 3 keys, threshold 2, release-controlled; offline-capable strongly preferred.
- Snapshot: at least 1 key, threshold 1; online automation permitted.
- Timestamp: at least 1 key, threshold 1; online automation permitted.
- Consistent snapshots: required for production repositories.
- Required target hash: SHA-256.
- Reference/test signature scheme: Ed25519.

Fixture repositories may use a separate 1-of-1 trust root that is cryptographically and operationally incapable of establishing production trust.

## Trusted root bootstrap

The application ships or is provisioned with an explicitly trusted root metadata version through an authenticated application/administrative channel. Atlas does not bootstrap its TUF root from the network endpoint serving the repository.

Root rotation follows TUF root update semantics. Clients must not skip required intermediate root versions.

## Metadata freshness and rollback

Activation requires valid, non-expired metadata under the local trusted-time policy. Highest-seen trusted metadata and pack versions are durable runtime state. Loss or rollback of that state is a recovery event, not a reason to disable checks.

Expired metadata can be exposed only by an explicit inspection-only operation. Inspection-only cannot modify active generation, LKG, trusted-version state, or production search/runtime visibility.

## Target namespace

The following top-level target namespaces are reserved:

- `atlas/` — mandatory Atlas control targets;
- `content/` — canonical/source-backed data payloads;
- `search/` — derived/disposable search artifacts.

Mandatory control targets:

- `atlas/pack-manifest.json`
- `atlas/source-license-inventory.json`

Atlas v1 does not require delegated roles. If delegations are introduced later, their paths must remain bounded to explicit target namespaces and require a new architecture review.

## Offline transport

A self-contained `.atlaspack` contains:

```text
metadata/
  root.json
  timestamp.json
  snapshot.json
  targets.json
targets/
  atlas/pack-manifest.json
  atlas/source-license-inventory.json
  content/...
  search/...
```

The ZIP container is transport only. The verifier authenticates TUF metadata and each target length/hash before Atlas contract validation. No target is executed.

## Activation policy

A pack is activatable only when all of the following pass:

1. trusted root chain verification;
2. metadata signature thresholds;
3. metadata freshness;
4. metadata and pack rollback checks;
5. target length/hash verification;
6. Pack Manifest v1 schema and invariant checks;
7. Source/License Inventory v1 schema and publication-policy checks;
8. canonical/search compatibility checks;
9. derived search artifact binding or deterministic rebuild;
10. pre-activation health checks.

Activation is immutable-generation staging followed by an atomic active-pointer swap. LKG is advanced only after post-activation health checks pass.

## Failure semantics

Any ambiguity or verification failure is fail-closed for activation. Failures do not mutate the active generation or LKG. Post-swap health failure restores the previous LKG atomically and emits a rollback report.

## Non-goals

This profile does not select:

- production HSM/KMS/vendor;
- application code-signing architecture;
- Shared Core implementation language;
- Web/PWA packaging;
- semantic/vector model distribution.
