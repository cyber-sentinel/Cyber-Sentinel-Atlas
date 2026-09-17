# Source Freshness & Public Pack Publication Policy

Status: **ACCEPTED FOR PUBLIC PREVIEW READINESS**

Applies to: Cyber-Sentinel ATLAS public knowledge-pack publication and refresh decisions.

## Objective

Public ATLAS content must remain attributable, reviewable, reproducible, and fresh enough for its declared use without converting upstream availability into automatic trust. This policy defines the minimum acceptance contract for source freshness and public-pack publication.

## Principles

1. **Provenance before convenience.** Every material technical claim must remain bound to inspectable source/provenance metadata.
2. **Deterministic publication.** Public packs must be generated from versioned inputs and reproducible build steps.
3. **Freshness is source-specific.** Update expectations depend on upstream change cadence, security impact, and operational use.
4. **No silent downgrade.** Missing, stale, malformed, or unverifiable upstream data must not be silently replaced by lower-trust content.
5. **Fail closed on publication uncertainty.** If source identity, redistribution status, integrity, or required review cannot be established, publication stops.
6. **Last Known Good remains available.** A failed refresh must not invalidate the last verified pack.

## Source classes and refresh objectives

| Source class | Examples | Target review/refresh objective | Maximum unattended age before publication is blocked |
| --- | --- | --- | --- |
| Security behavior / technique catalogs | ATT&CK, D3FEND, CAR | 7 days after detected upstream change | 30 days |
| Platform telemetry references | Windows/Sysmon/platform audit references | 14 days after detected upstream change | 45 days |
| Detection / defensive engineering imports | Reviewed DefenseOps releases | On accepted upstream release | 30 days |
| Static standards / architecture references | Stable standards and specifications | On published revision | 180 days |
| Maintainer-authored canonical mappings | Curated ATLAS mappings | On material upstream or model change | 90 days |

These are publication-control objectives, not claims that every upstream source changes on that cadence.

## Required source metadata

Every public-pack source record must identify, where applicable:

- source name and authoritative publisher;
- canonical source URL or documented acquisition location;
- acquisition timestamp in UTC;
- upstream version, release identifier, commit, ETag, Last-Modified value, digest, or equivalent immutable reference when available;
- parser/normalizer version;
- applicable redistribution or publication status;
- review outcome and reviewer/automation evidence;
- lineage into canonical records and claims.

## Freshness evaluation

A source is publishable only when all applicable checks pass:

1. source identity is known and matches the expected authority;
2. acquisition completed without integrity or transport ambiguity;
3. upstream revision metadata is captured where available;
4. parser/normalizer output passes schema and invariant validation;
5. inventory diff is reviewed for unexpected deletion, rename, lifecycle, or cardinality changes;
6. claim-level provenance remains resolvable;
7. source age remains within the applicable publication threshold;
8. third-party redistribution status is not blocked;
9. pack build, manifest, trust metadata, and deterministic validation succeed;
10. the resulting pack passes health checks before activation or publication.

## Staleness handling

When a source exceeds its maximum unattended age:

- new public-pack publication is blocked unless an explicit reviewed exception exists;
- the last verified public pack may remain available with its original timestamps and provenance;
- the UI and release metadata must not misrepresent stale content as current;
- an exception must identify the affected source, reason, risk, expiry, owner, and compensating control;
- exceptions must not waive integrity, provenance, redistribution, or signature requirements.

## Upstream outage / restricted-network handling

ATLAS is offline-first. Temporary inability to reach an upstream source must not force runtime network access or bypass verification.

During an upstream outage or restricted-network period:

- runtime search and investigation continue from the verified local pack;
- publication automation records the acquisition failure;
- the previous verified pack remains Last Known Good;
- no fabricated timestamp or synthetic freshness marker is allowed;
- publication resumes only after normal acquisition and validation controls pass.

## Public-pack acceptance criteria

A public pack may be promoted only when:

- all mandatory source records satisfy this freshness policy;
- the exact source inventory and versions are recorded;
- deterministic build and verification complete successfully;
- third-party publication/redistribution review is closed for the included material;
- TUF metadata and pack signatures satisfy the accepted trust model;
- the package is bound to release evidence and a release-authority commit;
- rollback/LKG recovery has been validated for the release line.

## Publication evidence

Each Public Preview release must provide or reference machine-readable evidence containing at least:

- release-authority commit;
- pack identifier and version;
- pack SHA-256;
- source inventory with timestamps and immutable revisions where available;
- freshness decision for every mandatory source;
- validation result;
- third-party review result;
- signing/trust metadata identifiers;
- release timestamp in UTC.

## Governance

The release authority may tighten freshness thresholds without changing canonical data contracts. Relaxing a maximum publication age requires an explicit reviewed change with documented rationale.

This policy closes the definition gap for **PPR-08**. Operational release evidence remains mandatory for every published pack.
