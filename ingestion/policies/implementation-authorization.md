# Ingestion Authorization Policy

Phase 5.3 ingestion implementations are fail-closed.

The Phase 5.3.1 foundation intentionally rejected all real connector, parser, and normalizer implementations. Starting with Phase 5.3.2, implementation files may exist only when their exact repository paths are explicitly authorized by `tools/ingestion/validate_ingestion_authorization.py` for an Architecture-approved slice.

Unknown implementation paths remain CI-blocking. Authorization of a path does not imply source authority, validation success, publication eligibility, or PACK_READY status.
