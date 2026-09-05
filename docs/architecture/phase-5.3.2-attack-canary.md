# Phase 5.3.2 — MITRE ATT&CK Canary

This slice proves the Phase 5.3 ingestion framework against an official, structured, version-pinned upstream source before the Windows/Sysmon encyclopedia pipeline.

## Pinned authority

- Source: MITRE ATT&CK `attack-stix-data`
- Domain: Enterprise ATT&CK
- Release: `19.2`
- Upstream commit: `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`
- Bundle: `enterprise-attack/enterprise-attack-19.2.json`

Production acquisition uses the exact commit-pinned HTTPS raw resource. Floating `main`, `master`, `latest`, and `HEAD` references are not accepted for release builds. Discovery metadata is non-authoritative for a pinned build.

## Deterministic boundary

```text
Pinned RawSnapshot
  -> STIX 2.1 Parser
  -> Parsed Source Representation (PSR)
  -> ATT&CK Mapping Profile
  -> Deterministic Normalizer
  -> Canonical Candidate Records + Normalization Lineage
```

The parser and normalizer have no network or AI capability. Unknown structured source fields are preserved and diagnosed rather than silently discarded. Ambiguous identity is quarantined.

## Repository policy

The full ATT&CK corpus is not committed. Only a small prose-free deterministic fixture is stored in `fixtures/phase-5.3/attack-canary-stix.json`. The live CI canary retrieves the pinned upstream bundle transiently, validates its exact release binding, parses and normalizes it, and discards the raw corpus after the job.

## Trust and lifecycle

A Tier-A source does not automatically make normalized claims `authoritative`. Pre-review normalized claims remain non-authoritative. ATT&CK `revoked` and `x_mitre_deprecated` may drive lifecycle mapping when explicitly present; absence of those fields is never interpreted as removal.

## Scope boundary

This slice authorizes only the MITRE ATT&CK canary implementation. Windows Security, Sysmon, D3FEND, CAR, DefenseOps, content-pack runtime, signing, and Detection IR remain outside this slice.
