# Deterministic Parsers

This directory contains reviewed parsers and parser definitions for the ATLAS ingestion control plane.

Current parsers cover STIX 2.1 ATT&CK, D3FEND Turtle/RDF, MITRE CAR YAML, DefenseOps exports, Microsoft Sysmon Markdown/schema evidence, and Microsoft Windows provider/documentation evidence.

Parser requirements:

- offline/no-network execution in the deterministic core;
- source content is treated as data and never executed;
- bounded parsing and explicit format validation;
- unknown structured fields are preserved or reported;
- source/version identity and lineage are retained;
- output is a Parsed Source Representation (PSR), not canonical truth.

Canonical promotion occurs only after normalization, validation, inventory/review, and provenance checks.
