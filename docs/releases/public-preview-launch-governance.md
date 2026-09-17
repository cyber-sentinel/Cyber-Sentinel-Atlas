# Public Preview Launch Governance

Status: **ACCEPTED FOR PUBLIC PREVIEW READINESS**

Applies to: Cyber-Sentinel ATLAS Public Preview release authorization, publication, rollback, and revocation.

## Objective

A Public Preview release must be a deliberate, evidence-backed change of product state. CI success alone does not authorize publication. This document defines the launch authority, mandatory evidence, go/no-go criteria, rollback model, and emergency revocation path.

## Release authority

- `main` is the source and control-plane authority.
- Public Preview publication requires an explicit release-authority commit on `main`.
- The strict Phase 5.10 readiness validator must pass against that exact commit.
- Artifacts must be cryptographically bound to the exact release-authority commit and their own immutable digests.
- Publication authority remains with the project maintainer/release owner; automation may verify but may not self-authorize a release.

## Required go/no-go conditions

A Public Preview release is **GO** only when all mandatory PPR-01 through PPR-11 gates are `PASS` and the following evidence exists:

1. exact release-authority commit;
2. successful strict `validate_phase510_readiness.py --release` result;
3. approved first-party license;
4. closed third-party redistribution inventory for shipped artifacts/content;
5. production code-signing evidence and accepted key-custody controls;
6. signed public package plus immutable SHA-256 evidence;
7. clean-machine installation/launch/offline smoke evidence;
8. accessibility release review evidence;
9. public-pack source freshness evidence;
10. supported-release and vulnerability disclosure policy;
11. rollback/revocation procedure tested for the release line;
12. release notes identifying known limitations and unsupported use cases.

Any mandatory failure is **NO-GO**. There is no waiver mechanism that converts a mandatory blocked gate into PASS without closing the underlying requirement.

## Release evidence record

The release record `docs/releases/public-preview-release-evidence.json` must be created only for an actual release candidate and must identify at least:

- release version;
- release-authority commit;
- build workflow/run identifier;
- package filename;
- package SHA-256;
- signing certificate identity/fingerprint or equivalent attestation identifier;
- signing timestamp evidence where applicable;
- SBOM reference and digest;
- vulnerability-scan evidence;
- third-party notice/inventory evidence;
- accessibility review evidence;
- source freshness/public-pack evidence;
- clean-machine smoke evidence;
- release decision owner and UTC decision timestamp;
- rollback target / Last Known Good release.

The file is release evidence, not a template for fabricating readiness. Missing real evidence must remain missing and keep strict release mode blocked.

## Rollback and revocation

A release must be reversible at the distribution and content levels.

### Application release rollback

- stop promotion of the affected release;
- remove or quarantine the affected download from the public channel when necessary;
- restore the previous supported package as the recommended release;
- publish a concise security/reliability notice when user impact exists;
- preserve evidence and hashes for forensic traceability;
- do not overwrite a previously published binary under the same version identifier.

### Knowledge-pack rollback

- use the accepted TUF/verified-pack Last Known Good path;
- preserve trusted-time/highest-seen anti-rollback semantics;
- issue a new, validly signed metadata state rather than bypassing rollback protection;
- record the affected pack version, reason, and replacement state.

### Emergency security revocation

Emergency revocation may be triggered for compromised signing material, malicious/tampered artifacts, critical reachable vulnerabilities, incorrect trust metadata, material provenance failure, or third-party rights issues affecting distribution.

Emergency action must prioritize stopping unsafe distribution. A post-action review records the trigger, affected versions, evidence, containment, recovery, and follow-up controls.

## Change control

Release-governance changes require reviewed PRs and CI. Weakening mandatory gates, changing release authority, or introducing an alternate unsigned distribution path is a security-significant change and must not be merged as routine documentation maintenance.

## Post-release monitoring

For every Public Preview release:

- monitor vulnerability and dependency disclosures for shipped components;
- track source freshness and pack publication health;
- track security reports and reproducible crash/launch failures;
- record any release withdrawal or supported-version change;
- feed validated findings into ATLAS, DefenseOps, or Skills according to ownership boundaries.

This policy closes the governance-definition gap for **PPR-09**. An actual launch remains blocked until all other mandatory gates are also closed and release evidence exists.
