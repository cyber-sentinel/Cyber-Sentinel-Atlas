# Source Profiles

This directory contains source-specific ingestion profiles that bind upstream identity, version/revision, acquisition expectations, freshness, and canonical `SourceRecord` references.

Current profiles include ATT&CK, D3FEND, CAR, Microsoft Sysmon documentation/schema, Microsoft Windows Security/provider evidence, the controlled DefenseOps boundary, and approved external quick-detail/reference sources where applicable.

Source profiles do not duplicate or override canonical licensing/redistribution decisions. Public-pack eligibility remains governed by the release inventory and PPR-04 controls.

Historical source versions are retained when needed for reproducibility, lifecycle analysis, or drift evidence.


## Coverage and provenance boundary

Source-profile presence proves that an upstream/source boundary is governed; it does not by itself make a telemetry identity encyclopedia-grade.

For the active Windows Security expansion, per-event curated source records under `content/encyclopedia/sources/` are bound to the frozen provider/channel/build denominator and then materialized through the canonical encyclopedia builder, deterministic search projection, verified pack and acceptance path.

The current reviewed Windows Security Auditing numerator is **50/423**; the cross-provider Security Log UWS review benchmark is **56/422**; Sysmon 15.22 remains **30/30**. Moving coverage state is authoritative in `content/encyclopedia/coverage-manifest.json`.
