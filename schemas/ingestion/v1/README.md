# ATLAS Ingestion Contracts v1

Ingestion Contract Version: **1.0.0**

Canonical URI base:

```text
https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/ingestion/v1/
```

These schemas define the governed ingestion control/artifact plane used by the completed Phase 5.3 implementation. They are **not** members of the canonical `AtlasRecord` union and do not alter `schemas/v1/` or Canonical Schema Version `1.0.0`.

The ingestion contract version stream is independent from the canonical schema version stream.

Implemented ingestion paths consume these contracts for controlled source profiles, acquisition evidence, Parsed Source Representation, inventories/diffs, validation, review, and promotion toward `PACK_READY`. ATT&CK, Windows Security, Sysmon, D3FEND, CAR, and the controlled DefenseOps boundary are represented by the current Phase 5.3 implementation.

Changes to this contract require compatibility review and must not silently mutate canonical schema semantics.
