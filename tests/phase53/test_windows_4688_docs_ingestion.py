from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


foundation = mod("w4688_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
phase52 = mod("w4688_phase52", ROOT / "tools/validate_phase52.py")
parser = mod("w4688_parser", ROOT / "ingestion/parsers/microsoft_windows_security_event_html.py")
normalizer = mod("w4688_normalizer", ROOT / "ingestion/normalizers/microsoft_windows_security_event_doc.py")

SOURCE_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-4688-doc"
SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:windows-4688-synthetic"
RETRIEVED_AT = "2026-09-05T04:45:00Z"


class Windows4688DocsIngestionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = load("ingestion/source-profiles/microsoft-windows-security-auditing-4688-doc.source.json")
        cls.release = load("ingestion/source-profiles/microsoft-windows-security-auditing-4688-doc.release.json")
        cls.connector = load("ingestion/connectors/microsoft-windows-security-event-4688-doc.json")
        cls.parser_def = load("ingestion/parsers/microsoft-windows-security-event-html.definition.json")
        cls.normalizer_def = load("ingestion/normalizers/microsoft-windows-security-event-doc.definition.json")
        cls.mapping = load("ingestion/mappings/microsoft-windows-security-event-doc-v1.json")
        cls.fixture = (ROOT / "fixtures/phase-5.3/windows-security-4688.synthetic.html").read_text(encoding="utf-8")

    def parse(self, html=None, snapshot_id=SNAPSHOT_ID):
        return parser.parse_html(
            html if html is not None else self.fixture,
            source_id=SOURCE_ID,
            source_snapshot_id=snapshot_id,
        )

    def normalize(self, records=None, mapping=None):
        return normalizer.normalize_psr(
            records if records is not None else self.parse(),
            mapping_profile=copy.deepcopy(mapping or self.mapping),
            source_version=self.release["source_version"],
            retrieved_at=RETRIEVED_AT,
        )

    def test_01_source_is_official_restricted_documentation(self):
        self.assertEqual("tier-a-authoritative", self.source["source_class"])
        self.assertEqual("official", self.source["official_status"])
        self.assertEqual("restricted", self.source["redistribution"]["policy"])
        self.assertEqual(self.release["page_url"], self.source["canonical_urls"][0])

    def test_02_release_semantic_expectations(self):
        self.assertEqual("4688", self.release["expected_event_id"])
        self.assertEqual("Microsoft-Windows-Security-Auditing", self.release["expected_provider"])
        self.assertEqual("Security", self.release["expected_channel"])
        self.assertEqual(["0", "1", "2"], self.release["expected_event_versions"])
        self.assertIn("not the telemetry completeness denominator", self.release["change_policy"])

    def test_03_connector_schema_and_security(self):
        validator = foundation.ingestion_validator("connector-definition.schema.json")
        self.assertTrue(validator.is_valid(self.connector))
        self.assertEqual(self.release["page_url"], self.connector["targets"][0]["resource_uri"])
        security = self.connector["security_policy"]
        self.assertEqual(["learn.microsoft.com"], security["allowed_hosts"])
        self.assertEqual(0, security["redirect_limit"])
        self.assertTrue(security["tls_verify"])
        self.assertTrue(security["block_private_destinations"])

    def test_04_parser_and_normalizer_definition_schemas(self):
        self.assertTrue(foundation.ingestion_validator("parser-definition.schema.json").is_valid(self.parser_def))
        self.assertTrue(foundation.ingestion_validator("normalizer-definition.schema.json").is_valid(self.normalizer_def))
        self.assertEqual(parser.PARSER_ID, self.parser_def["parser_id"])
        self.assertEqual(parser.PARSER_VERSION, self.parser_def["parser_version"])

    def test_05_mapping_profile_digest(self):
        self.assertEqual(self.mapping["profile_digest"], normalizer.mapping_profile_digest(self.mapping))

    def test_06_parser_extracts_source_native_4688_structure(self):
        record = self.parse()[0]
        fields = record["native_fields"]
        self.assertEqual("4688", fields["event_id"])
        self.assertEqual("Microsoft-Windows-Security-Auditing", fields["provider"])
        self.assertEqual("Security", fields["channel"])
        self.assertEqual("2", fields["sample_event_xml_version"])
        self.assertEqual(["0", "1", "2"], fields["documented_event_versions"])
        self.assertEqual("13312", fields["task"])
        self.assertEqual("0", fields["opcode"])
        self.assertEqual("0x8020000000000000", fields["keywords"])
        self.assertEqual("Audit Process Creation", fields["audit_subcategory"])
        self.assertEqual("Windows Server 2008, Windows Vista", fields["minimum_os_version"])
        for critical in ("SubjectUserSid", "NewProcessId", "NewProcessName", "CommandLine", "ParentProcessName"):
            self.assertIn(critical, fields["event_data_fields"])

    def test_07_parser_replay_is_deterministic(self):
        first, second = self.parse(), self.parse()
        self.assertEqual(first, second)
        self.assertEqual(parser.representation_digest(first), parser.representation_digest(second))

    def test_08_psr_schema_and_phase531_digest_contract(self):
        record = self.parse()[0]
        self.assertTrue(foundation.ingestion_validator("parsed-source-record.schema.json").is_valid(record))
        payload = {
            key: record.get(key)
            for key in ("native_type", "native_key", "native_identifiers", "native_fields", "unknown_fields", "locator")
        }
        self.assertEqual(foundation.sha256_digest(payload), record["record_digest"])
        expected = foundation.stable_artifact_id(
            "parsed-source-record",
            {
                "source_snapshot_id": record["source_snapshot_id"],
                "parser_id": record["parser_id"],
                "parser_version": record["parser_version"],
                "psr_version": record["psr_version"],
                "native_type": record["native_type"],
                "native_key": record["native_key"],
                "record_digest": record["record_digest"],
            },
        )
        self.assertEqual(expected, record["parsed_record_id"])

    def test_09_snapshot_identity_changes_psr_identity(self):
        first = self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:a")
        second = self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:b")
        self.assertNotEqual(first[0]["parsed_record_id"], second[0]["parsed_record_id"])

    def test_10_heading_xml_event_id_mismatch_fails_closed(self):
        tampered = self.fixture.replace("&lt;EventID&gt;4688", "&lt;EventID&gt;9999")
        self.assertNotEqual(self.fixture, tampered)
        with self.assertRaises(ValueError):
            self.parse(tampered)

    def test_10a_identical_duplicate_rendered_heading_is_deduplicated(self):
        duplicate = self.fixture + "\n<h2>4688(S): A new process has been created.</h2>\n"
        records = self.parse(duplicate)
        self.assertEqual(1, len(records))
        self.assertEqual("4688", records[0]["native_fields"]["event_id"])
        self.assertTrue(any("deduplicated identical headings" in item for item in records[0]["diagnostics"]))

    def test_10b_conflicting_duplicate_heading_fails_closed(self):
        conflicting = self.fixture + "\n<h2>9999(S): A conflicting event heading.</h2>\n"
        with self.assertRaises(ValueError):
            self.parse(conflicting)

    def test_11_missing_event_versions_section_fails_closed(self):
        tampered = self.fixture.replace("Event Versions:", "Synthetic Version List:")
        with self.assertRaises(ValueError):
            self.parse(tampered)

    def test_12_provider_drift_fails_at_normalizer(self):
        records = self.parse()
        records[0]["native_fields"]["provider"] = "Unexpected-Provider"
        with self.assertRaises(ValueError):
            self.normalize(records)

    def test_13_mapping_tamper_fails_closed(self):
        mapping = copy.deepcopy(self.mapping)
        mapping["provider"] = "Unexpected-Provider"
        with self.assertRaises(ValueError):
            self.normalize(mapping=mapping)

    def test_14_canonical_4688_identity_and_search_context(self):
        entity = self.normalize()["records"][0]
        self.assertEqual("atlas:event:microsoft.windows.security:4688", entity["id"])
        self.assertEqual("4688", entity["canonical_key"])
        native = entity["native_identifiers"][0]
        self.assertEqual("event_id", native["type"])
        self.assertEqual("4688", native["value"])
        self.assertEqual("Microsoft-Windows-Security-Auditing", native["context"]["provider"])
        self.assertEqual("Security", native["context"]["channel"])
        self.assertEqual("Windows Security Auditing", native["context"]["product"])
        self.assertEqual("Windows", native["context"]["platform"])

    def test_15_event_detail_structure_preserved_for_phase54(self):
        components = self.normalize()["records"][0]["native_identifiers"][0]["components"]
        self.assertEqual("documented", components["documentation_status"])
        self.assertEqual(["0", "1", "2"], components["documented_event_versions"])
        self.assertEqual("2", components["sample_event_xml_version"])
        self.assertEqual("Audit Process Creation", components["audit_subcategory"])
        self.assertIn("CommandLine", components["event_data_fields"])
        self.assertNotIn("numeric_sort_value", components)

    def test_16_documentation_does_not_set_canonical_lifecycle(self):
        output = self.normalize()
        self.assertNotIn("lifecycle", output["records"][0])
        self.assertTrue(any("lifecycle intentionally remains unset" in item for item in output["diagnostics"]))

    def test_17_canonical_candidate_validates(self):
        entity = self.normalize()["records"][0]
        errors = list(phase52.root_validator().iter_errors(entity))
        self.assertEqual([], errors, [error.message for error in errors])

    def test_18_lineage_valid_and_snapshot_bound(self):
        lineage = self.normalize()["lineage"][0]
        self.assertTrue(foundation.ingestion_validator("normalization-lineage.schema.json").is_valid(lineage))
        self.assertEqual([SNAPSHOT_ID], lineage["source_snapshot_ids"])
        body = copy.deepcopy(lineage)
        body.pop("lineage_id")
        body.pop("lineage_digest")
        digest = foundation.sha256_digest(body)
        self.assertEqual(digest, lineage["lineage_digest"])
        self.assertEqual(f"atlas:normalization-lineage:atlas.ingestion:{digest}", lineage["lineage_id"])

    def test_19_normalizer_replay_is_deterministic(self):
        self.assertEqual(self.normalize(), self.normalize())

    def test_20_source_profile_expectations_match_fixture_parse(self):
        fields = self.parse()[0]["native_fields"]
        self.assertEqual(self.release["expected_event_id"], fields["event_id"])
        self.assertEqual(self.release["expected_provider"], fields["provider"])
        self.assertEqual(self.release["expected_channel"], fields["channel"])
        self.assertEqual(self.release["expected_event_versions"], fields["documented_event_versions"])
        self.assertEqual(self.release["expected_minimum_os"], fields["minimum_os_version"])


if __name__ == "__main__":
    unittest.main()
