from __future__ import annotations

from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "phase_policy",
    ROOT / "tools" / "ingestion" / "validate_ingestion_authorization.py",
)
phase_policy = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(phase_policy)


class IngestionAuthorizationTests(unittest.TestCase):
    def authorized_paths(self):
        return sorted(phase_policy.AUTHORIZED_IMPLEMENTATIONS)

    def test_01_current_authorization_allowlist_is_exact(self):
        phase532 = {
            "ingestion/connectors/mitre-attack-enterprise.json",
            "ingestion/parsers/mitre-attack-stix21.definition.json",
            "ingestion/parsers/mitre_attack_stix.py",
            "ingestion/normalizers/mitre-attack-enterprise.definition.json",
            "ingestion/normalizers/mitre_attack.py",
        }
        phase533 = {
            "ingestion/connectors/microsoft-sysmon-docs.json",
            "ingestion/parsers/microsoft-sysmon-markdown.definition.json",
            "ingestion/parsers/microsoft_sysmon_markdown.py",
            "ingestion/parsers/microsoft-sysmon-schema.definition.json",
            "ingestion/parsers/microsoft_sysmon_schema.py",
            "ingestion/normalizers/microsoft-sysmon-docs.definition.json",
            "ingestion/normalizers/microsoft_sysmon_docs.py",
            "ingestion/normalizers/microsoft-sysmon-schema.definition.json",
            "ingestion/normalizers/microsoft_sysmon_schema.py",
            "ingestion/connectors/microsoft-windows-security-event-4688-doc.json",
            "ingestion/parsers/microsoft-windows-security-event-html.definition.json",
            "ingestion/parsers/microsoft_windows_security_event_html.py",
            "ingestion/normalizers/microsoft-windows-security-event-doc.definition.json",
            "ingestion/normalizers/microsoft_windows_security_event_doc.py",
            "ingestion/parsers/microsoft-windows-provider-metadata.definition.json",
            "ingestion/parsers/microsoft_windows_provider_metadata.py",
            "ingestion/normalizers/microsoft-windows-provider-metadata.definition.json",
            "ingestion/normalizers/microsoft_windows_provider_metadata.py",
        }
        self.assertEqual(phase532 | phase533, set(phase_policy.AUTHORIZED_IMPLEMENTATIONS))
        self.assertEqual(phase532, {p for p, phase in phase_policy.AUTHORIZED_IMPLEMENTATIONS.items() if phase == "phase-5.3.2"})
        self.assertEqual(phase533, {p for p, phase in phase_policy.AUTHORIZED_IMPLEMENTATIONS.items() if phase == "phase-5.3.3"})
        self.assertEqual({"phase-5.3.2", "phase-5.3.3"}, set(phase_policy.AUTHORIZED_IMPLEMENTATIONS.values()))

    def test_02_exact_authorized_set_is_accepted(self):
        self.assertEqual([], phase_policy.implementation_authorization_errors(self.authorized_paths()))

    def test_03_unknown_connector_fails_closed(self):
        tracked = self.authorized_paths() + ["ingestion/connectors/unapproved.json"]
        errors = phase_policy.implementation_authorization_errors(tracked)
        self.assertTrue(any("undeclared ingestion implementation" in error for error in errors))

    def test_04_unknown_parser_fails_closed(self):
        tracked = self.authorized_paths() + ["ingestion/parsers/unapproved.py"]
        errors = phase_policy.implementation_authorization_errors(tracked)
        self.assertTrue(any("undeclared ingestion implementation" in error for error in errors))

    def test_05_unknown_normalizer_fails_closed(self):
        tracked = self.authorized_paths() + ["ingestion/normalizers/unapproved.py"]
        errors = phase_policy.implementation_authorization_errors(tracked)
        self.assertTrue(any("undeclared ingestion implementation" in error for error in errors))

    def test_06_missing_authorized_asset_fails_closed(self):
        tracked = self.authorized_paths()[1:]
        errors = phase_policy.implementation_authorization_errors(tracked)
        self.assertTrue(any("authorized implementation missing" in error for error in errors))

    def test_07_readmes_and_other_ingestion_areas_do_not_expand_authority(self):
        tracked = self.authorized_paths() + [
            "ingestion/connectors/README.md",
            "ingestion/parsers/README.md",
            "ingestion/normalizers/README.md",
            "ingestion/mappings/mitre-attack-enterprise-v1.json",
            "ingestion/mappings/microsoft-sysmon-docs-v1.json",
            "ingestion/mappings/microsoft-sysmon-schema-v1.json",
            "ingestion/mappings/microsoft-windows-security-event-doc-v1.json",
            "ingestion/mappings/microsoft-windows-provider-metadata-v1.json",
            "ingestion/source-profiles/mitre-attack-enterprise.source.json",
            "ingestion/source-profiles/microsoft-sysmon-docs.source.json",
            "ingestion/source-profiles/microsoft-windows-security-auditing-4688-doc.source.json",
            "ingestion/source-profiles/microsoft-windows-provider-metadata.source.json",
            "ingestion/source-profiles/microsoft-sysmon-schema-export.source.json",
            "ingestion/inventories/sysmon-docs-15.21.documentation.json",
        ]
        self.assertEqual([], phase_policy.implementation_authorization_errors(tracked))


if __name__ == "__main__":
    unittest.main()
