# Security Policy

Cyber-Sentinel-Atlas is security-sensitive software. Please do not disclose exploitable vulnerabilities, credentials, signing material, private data, unpublished release artifacts, or weaponizable proof-of-concept details in a public issue.

## Current support posture

The source repository is public, while the product remains **Pre-preview / unreleased** for public binary distribution. First Preview engineering readiness is **READY**, but that milestone is not equivalent to a signed Public Preview or GA release.

Until Public Preview, supported security triage is limited to:

- the current authoritative `main` development line;
- explicitly identified First Preview or release-candidate baselines;
- artifacts whose hashes and provenance are published as project evidence.

Historical commits, experimental branches, unmerged forks, locally modified binaries, and third-party repackaging are not supported releases.

## Reporting vulnerabilities

Report security issues through a **private vulnerability reporting channel**. Prefer GitHub Private Vulnerability Reporting / Security Advisories when available. If no private repository channel is available, contact the repository owner privately before sharing technical details.

Do not place exploit details, production secrets, signing material, private customer data, or sensitive third-party data in public issues, discussions, pull requests, or logs.

A useful report should include:

- affected component and version / commit / artifact digest;
- reproduction conditions;
- security impact;
- minimal proof sufficient to validate the issue;
- known mitigations or containment options, when available.

Do not include real production credentials or confidential third-party material.

## Response model

Security reports are triaged against the supported state above. Confirmed issues should receive, as applicable:

1. a bounded remediation branch;
2. a regression test that reproduces the defect where safe;
3. CI and relevant architecture/security gate validation;
4. review of affected trust, protocol, pack, desktop, or supply-chain boundaries;
5. controlled merge and post-merge verification;
6. coordinated disclosure after an effective fix or mitigation is available.

No mandatory security gate should be weakened merely to obtain green CI or accelerate publication.

## Public Preview security boundary

Phase 5.10 Public Preview Readiness is fail-closed. Public Preview must not be declared ready while mandatory release gates remain unresolved, including applicable licensing/redistribution, production signing/key custody, public packaging/distribution, accessibility, source freshness, and launch-governance requirements.

The machine-readable readiness authority is `docs/releases/phase-5.10-public-preview-readiness.json`.

## Supply-chain and signing material

Production private keys, code-signing credentials, pack-signing keys, HSM/KMS credentials, release tokens, and publication secrets must never be committed to this repository.

Test keys, when needed, must be unmistakably fixture-only and unusable for production trust.

Production signing remains a separate Public Preview gate. Selection of a certificate authority, code-signing provider, HSM/KMS, or key-custody model requires explicit acceptance; this policy does not silently choose one.
