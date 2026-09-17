# Production Signing & Key Custody — Phase 5.10.2

Status: **CONTROL PLANE READY / PROVIDER DECISION BLOCKED**

This contract defines the technical and security conditions for PPR-05 without selecting a certificate authority, cloud signing service, HSM/KMS vendor, legal certificate subject, or commercial plan. Those are explicit owner/business/security decisions.

## Objective

Every Public Preview Windows binary that is distributed as an ATLAS release must be traceable from exact source commit to exact unsigned artifact, SBOM, vulnerability evidence, signed artifact, timestamp, signature verification and release attestation.

The signing boundary must not become a way to weaken build reproducibility, package integrity or release governance.

## Mandatory signing architecture

```text
Exact release commit
        ↓
Reproducible build + tests
        ↓
Unsigned artifact SHA-256
        ↓
SBOM + dependency/license + vulnerability gates
        ↓
Authorized signing request
        ↓
Hardware-backed / non-exportable private key operation
        ↓
Authenticode SHA-256 signature + trusted RFC 3161 timestamp
        ↓
Independent signature / chain / timestamp verification
        ↓
Signed artifact SHA-256 + attestation
        ↓
Public release package
```

## Non-negotiable security requirements

- The production code-signing private key must be **non-exportable** from its accepted protected custody boundary.
- No production private key, PFX, recovery secret, PIN or equivalent signing secret may be stored in the repository, committed workflow files, build artifact, package, ordinary environment variable or general-purpose CI secret store.
- The signing operation must be separately authorized from ordinary build execution.
- Signing must be bound to an exact release commit and exact unsigned artifact SHA-256.
- Authenticode must use SHA-256 or a stronger Windows-supported profile; SHA-1-only signing is prohibited.
- A trusted RFC 3161 timestamp is mandatory so signature validity does not depend only on the certificate's later expiry.
- Signature verification must run after signing and before publication.
- Verification must prove the expected signer identity, chain status, timestamp, file digest and exact signed-artifact SHA-256.
- Release attestation must bind source commit, workflow/run identity, unsigned SHA-256, signed SHA-256, SBOM digest and signing certificate identity/fingerprint.
- A failed, missing, unexpected or unverifiable signature is a publication failure.
- Signing must not silently mutate unrelated package contents after their hashes were recorded. Any packaging step after signing must have its own final package hash and manifest.

## Accepted custody classes

PPR-05 may use one of the following architecture classes after explicit owner selection:

1. **Managed cloud code-signing service with hardware-backed non-exportable keys** — CI authenticates to an authorized signing service; private key material never reaches the runner.
2. **Dedicated HSM/KMS-backed organizational signing service** — a controlled service mediates signing requests and authorization against a hardware-backed key.
3. **Hardware token / HSM attached to a dedicated signing station** — supported only if automation, operator access, backup/rotation and incident handling are demonstrably controlled.

A raw exportable `.pfx` copied into GitHub Actions or a self-hosted runner is **not an accepted production custody model**.

## Authorization and separation of duties

The release process must distinguish:

- build authority;
- signing-request authority;
- signing-key custody;
- release-publication authority;
- emergency revocation authority.

One person may hold more than one role in the current owner-led project, but the system must record which authority was exercised and must not infer signing permission from ordinary repository write access.

## Certificate lifecycle

Before PPR-05 can PASS, the project must record:

- selected provider / custody class;
- certificate subject and publisher identity;
- certificate serial number and SHA-256 fingerprint;
- validity period and renewal lead time;
- trusted timestamp service policy;
- signing authorization method;
- rotation procedure;
- loss/compromise response;
- revocation procedure;
- replacement/recovery process;
- audit/evidence retention period.

Certificate renewal must not silently change publisher identity or release trust without review.

## Key compromise / emergency procedure

If compromise or unauthorized signing is suspected:

1. stop Public Preview publication immediately;
2. disable or revoke signing authorization;
3. preserve signing/audit logs and affected artifact hashes;
4. identify every artifact signed with the affected credential;
5. revoke the certificate/key when appropriate;
6. rotate to a new protected key/certificate through reviewed enrollment;
7. publish withdrawal/revocation guidance under the launch-governance process;
8. rebuild and re-sign from known-good source if replacement artifacts are required.

No emergency may be resolved by disabling signature verification or trusting an unsigned replacement.

## Required machine-readable evidence

`docs/releases/production-signing-readiness.json` is the machine-readable authority for this slice. It remains `BLOCKED` until the owner selects an accepted custody/provider model and an exact production signing certificate is enrolled and verified.

Strict release evidence must include at least:

```text
release_commit
unsigned_artifact_sha256
signed_artifact_sha256
sbom_sha256
signing_provider
custody_class
certificate_subject
certificate_serial
certificate_sha256_fingerprint
rfc3161_timestamp_verified
signature_verified
signing_run_or_audit_id
release_attestation_sha256
```

## Current boundary

The First Preview and Phase 5.10.5 engineering artifacts remain intentionally unsigned. This document does not convert them into Public Preview releases and does not select a provider on behalf of the owner.

PPR-05 remains **BLOCKED** until provider/custody selection, certificate enrollment and exact signed-candidate evidence are complete.
