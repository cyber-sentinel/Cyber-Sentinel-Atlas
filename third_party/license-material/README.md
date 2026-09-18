# Pinned Third-Party License Material

Status: **PPR-04 EVIDENCE ONLY / NOT REDISTRIBUTION ACCEPTANCE**

This directory contains byte-identical license material copied from the exact upstream revisions already pinned by the ATLAS redistribution inventory.

Purpose:

- keep required upstream license material available offline for release assembly;
- prove byte identity against the upstream Git blob recorded in `manifest.json`;
- make future notice/package assembly deterministic and auditable;
- avoid depending on live network access during final release construction.

The presence of a license file here does **not** change an inventory entry to `ACCEPTED`, does not determine legal compatibility, and does not authorize Public Preview publication.

The current evidence set covers the conditionally-clearable knowledge sources selected by the PPR-04 inventory:

- MITRE ATT&CK Enterprise;
- MITRE CAR;
- MITRE D3FEND ontology;
- Microsoft Sysinternals / Sysmon documentation.

`tools/release/validate_pinned_license_material.py` computes the Git blob object identity from each local file and compares it to the upstream blob SHA recorded at the pinned upstream revision. It also emits SHA-256 evidence for package/release tooling.

Microsoft Windows Security documentation and Cyber-Sentinel DefenseOps source text remain excluded under the current redistribution model and therefore have no pinned redistributable license-material payload here.
