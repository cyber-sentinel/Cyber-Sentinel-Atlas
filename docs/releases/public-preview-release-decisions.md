# Public Preview Release Decisions — Phase 5.10.6

Status: **TECHNICAL RELEASE VEHICLE SELECTED / RELEASE EVIDENCE BLOCKED**

This record captures the owner-authorized technical release vehicle for the first ATLAS Public Preview. It does not grant publication authority and does not bypass PPR-03, PPR-04, PPR-05, PPR-06, or PPR-07 evidence requirements.

## Selected release vehicle

- Windows distribution format: **signed portable ZIP**.
- Canonical publication channel: **GitHub Releases** in `cyber-sentinel/Cyber-Sentinel-Atlas`.
- Binary auto-update: **disabled** for Public Preview.
- Content-pack updates: remain governed by the accepted TUF trust/update boundary.
- Installer formats such as MSI/MSIX: deferred until after Public Preview unless a later reviewed decision replaces this record.

## Rationale

The signed portable ZIP preserves the already verified portable deployment model, minimizes installer-specific privilege and rollback complexity, keeps artifact bytes directly inspectable, and allows the package SHA-256 to remain identical between release approval and canonical publication.

GitHub Releases is selected as the canonical public byte source because the repository, release history, source commit, immutable release assets, checksums, notices, SBOM, and release notes can be bound in one reviewable release record.

## Mandatory release boundary

Selection is not acceptance. PPR-06 remains **BLOCKED** until the exact final package is production-signed and timestamped, hash-bound to SBOM/notices/release notes, accepted on clean Windows, accessibility-bound, published through the selected channel, and independently reverified after publication.

PPR-05 remains independently **BLOCKED** until an approved non-exportable/hardware-backed production signing provider/certificate/custody implementation and exact signed-candidate evidence exist.
