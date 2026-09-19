# Deterministic Normalizers

This directory contains the production/reviewed deterministic normalization implementations and their definitions.

Current normalizers cover ATT&CK, D3FEND, CAR, DefenseOps, Microsoft Sysmon documentation/schema, and Microsoft Windows provider/documentation evidence.

Normalizers consume pinned Parsed Source Representation (PSR), mapping profiles, controlled registries, and canonical schema contracts. The deterministic core:

- performs no network access;
- does not call AI/LLM services;
- preserves provenance and source/version identity;
- fails closed on unsupported structural assumptions;
- must not invent security semantics that are absent from the source or approved authored enrichment.
