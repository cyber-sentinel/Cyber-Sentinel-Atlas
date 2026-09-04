# Atlas Controlled Registries

Phase 5.2 keeps vendor/product vocabulary out of monolithic JSON Schema enums. JSON Schema validates syntax and record structure; `tools/validate_phase52.py` enforces membership in these registries.

Registry changes are controlled data-model changes and require review. Additive registry entries do not by themselves require a schema major version unless the schema semantics change.