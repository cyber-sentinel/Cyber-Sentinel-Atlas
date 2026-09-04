# Controlled Registries

Phase 5.2 uses registries for controlled vocabulary membership instead of hard-coding future vendor values into monolithic JSON Schema enums.

Every registry JSON document must contain `registry`, `registry_version`, and unique `values`. Registry identity is unique across the registry directory. `registry_version` follows semantic-version syntax but is **independent** from canonical schema version and may evolve on its own lifecycle.

Required v1 registries: `entity-types`, `namespaces`, `relationship-types`, `native-identifier-types`, `claim-predicates`, and `alias-kinds`.
