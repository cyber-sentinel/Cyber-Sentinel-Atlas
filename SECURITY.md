# Security Policy

Cyber-Sentinel-Atlas is security-sensitive infrastructure. Please do not disclose exploitable vulnerabilities, credentials, signing material, private data or weaponizable proof-of-concept details in a public issue.

## Reporting

For the current private-development stage, report security issues privately to the repository maintainer through an available private GitHub channel, such as a private vulnerability report / Security Advisory when enabled. If no private repository channel is available, contact the repository owner privately before sharing technical details.

A report should include the affected component/version, reproduction conditions, impact, and a minimal proof sufficient to validate the issue. Do not include real production secrets or third-party confidential data.

## Response model

Security reports are triaged against the current supported development head and release candidates. Confirmed issues receive a bounded remediation branch, tests that reproduce the defect where safe, CI validation, architecture/security review and a controlled merge. Disclosure timing is coordinated after a fix or mitigation is available.

## Supported state

Until Public Preview, only the current controlled development line and explicitly identified release candidates are supported. Historical commits, experimental branches and unmerged forks are not supported releases.

## Supply-chain and signing material

Production private keys, code-signing credentials, pack-signing keys and release secrets must never be committed to this repository. Test keys, when needed, must be unmistakably fixture-only and unusable for production trust.
