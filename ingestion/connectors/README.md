# Source Connector Definitions

This directory contains reviewed source-connector manifests used by the ATLAS ingestion control plane.

Current connector definitions cover controlled acquisition paths for ATT&CK, Microsoft Sysmon documentation, Microsoft Windows Security Event 4688 documentation, MITRE D3FEND, and MITRE CAR. Additional source families are admitted only through explicit source, provenance, licensing, and security review.

Connector manifests describe acquisition behavior and source identity. They must not contain credentials, tokens, private keys, or environment-specific secrets.

A connector does not grant canonical or release authority by itself. Acquired material still passes parser, normalization, inventory, validation, review, and applicable redistribution controls.
