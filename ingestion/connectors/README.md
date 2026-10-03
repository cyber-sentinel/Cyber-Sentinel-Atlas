# Source Connector Definitions

This directory contains reviewed source-connector manifests used by the ATLAS ingestion control plane.

Current connector definitions cover controlled acquisition paths for ATT&CK, Microsoft Sysmon documentation, Microsoft Windows Security Event 4688 documentation, MITRE D3FEND, and MITRE CAR. The broader Phase 5.10.10 Windows Security encyclopedia is not represented as one connector per Event ID: curated per-event source records and the frozen provider inventory are used where appropriate. Additional source families are admitted only through explicit source, provenance, licensing, and security review.

Connector manifests describe acquisition behavior and source identity. They must not contain credentials, tokens, private keys, or environment-specific secrets.

A connector does not grant canonical or release authority by itself. Acquired material still passes parser, normalization, inventory, validation, review, and applicable redistribution controls.


## Relationship to current Windows exemplars

The reviewed Windows Security encyclopedia currently includes Event IDs `4624`, `4625`, `4648`, `4672`, `4688`, `4740`, `4768`, and `4771`.

Only Event 4688 currently has a dedicated acquisition connector in this directory. The remaining curated exemplars use controlled source records plus the authoritative provider inventory; this is intentional and must not be interpreted as missing provenance.

Connector presence is therefore **not** the coverage numerator.
