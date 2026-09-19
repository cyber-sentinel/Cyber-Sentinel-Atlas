# Mapping Profiles

This directory contains immutable/versioned mapping profiles that translate parsed source representations into ATLAS normalization and canonical-candidate semantics.

Current mappings cover ATT&CK, D3FEND, CAR, DefenseOps, Microsoft Sysmon documentation/schema, and Microsoft Windows provider/documentation evidence.

Every normalization run must bind the mapping profile identity/version and SHA-256 digest. Mapping changes are reviewable semantic changes and must not silently rewrite canonical meaning.

Mappings do not override source provenance, lifecycle/applicability evidence, or canonical-schema constraints.
