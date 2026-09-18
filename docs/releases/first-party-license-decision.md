# First-Party License Decision Control — PPR-03

Status: **BLOCKED — OWNER / LEGAL-BUSINESS DECISION REQUIRED**

This control defines how Cyber-Sentinel ATLAS may move PPR-03 to PASS. It does not select a license on behalf of the maintainer.

## Scope

The decision applies to first-party ATLAS source code, documentation, schemas, tests, fixtures, and repository-owned assets unless a file or directory carries a more specific notice. Third-party material remains governed by its original terms and PPR-04.

## PASS requirements

PPR-03 may become PASS only when all of the following are true:

1. the maintainer explicitly approves a first-party license strategy;
2. the exact SPDX license identifier or approved custom-license identifier is recorded;
3. the repository contains the approved top-level LICENSE text;
4. the SHA-256 of that exact license file is recorded in the machine-readable readiness state;
5. README and CONTRIBUTING language is synchronized so it does not claim that no project license exists;
6. contribution-rights handling is explicitly compatible with the selected license and maintainer-governed contribution model;
7. third-party content is explicitly excluded from any first-party relicensing claim;
8. the strict release validator passes on the exact release branch.

## Decision classes

The control supports an OSI/open-source license, a source-available/custom commercial license, or another maintainer-approved model. The repository must not infer a license merely from public visibility.

## Fail-closed rule

Until an explicit decision is recorded and the exact LICENSE file is hash-bound, PPR-03 remains BLOCKED and Public Preview publication remains prohibited.
