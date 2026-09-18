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


foundation = mod("sysmon_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
phase52 = mod("sysmon_phase52", ROOT / "tools/validate_phase52.py")
parser = mod("sysmon_parser", ROOT / "ingestion/parsers/microsoft_sysmon_markdown.py")
normalizer = mod("sysmon_normalizer", ROOT / "ingestion/normalizers/microsoft_sysmon_docs.py")

SOURCE_ID = "atlas:source:atlas.source:microsoft-sysmon-docs"
SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:sysmon-docs-synthetic-v15.21"
RETRIEVED_AT = "2026-09-05T04:30:00Z"


class SysmonDocsIngestionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = load("ingestion/source-profiles/microsoft-sysmon-docs.source.json")
        cls.release = load("ingestion/source-profiles/microsoft-sysmon-docs.release.json")
        cls.connector = load("ingestion/connectors/microsoft-sysmon-docs.json")
        cls.parser_def = load("ingestion/parsers/microsoft-sysmon-markdown.definition.json")
        cls.normalizer_def = load("ingestion/normalizers/microsoft-sysmon-docs.definition.json")
        cls.mapping = load("ingestion/mappings/microsoft-sysmon-docs-v1.json")
        cls.inventory = load("ingestion/inventories/sysmon-docs-15.22.documentation.json")
        cls.fixture = (ROOT / "fixtures/phase-5.3/sysmon-docs.synthetic.md").read_text(encoding="utf-8")

    def parse(self, text=None, snapshot_id=SNAPSHOT_ID):
        return parser.parse_markdown(
            text if text is not None else self.fixture,
            source_id=SOURCE_ID,
            source_snapshot_id=snapshot_id,
        )

    def normalize(self, records=None, mapping=None):
        return normalizer.normalize_psr(
            records if records is not None else self.parse(),
            mapping_profile=copy.deepcopy(mapping or self.mapping),
            source_version=self.release["release_version"],
            retrieved_at=RETRIEVED_AT,
        )

    def test_01_source_is_official_and_license_verified(self):
        self.assertEqual("tier-a-authoritative", self.source["source_class"])
        self.assertEqual("official", self.source["official_status"])
        self.assertEqual("verified", self.source["license"]["status"])
        self.assertEqual("CC-BY-4.0", self.source["license"]["identifier"])
        self.assertIn("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon", self.source["canonical_urls"])

    def test_02_release_is_exact_commit_and_blob_pinned(self):
        self.assertEqual("15.22", self.release["release_version"])
        self.assertEqual("2fd3249657118505564fd220e672e8ea45d35916", self.release["upstream_commit_sha"])
        self.assertEqual("e9ee1e967957074ba4536dc8ed0c524a321992e7", self.release["document_git_blob_sha1"])
        self.assertIn(self.release["upstream_commit_sha"], self.release["document_url"])
        self.assertNotIn("/main/", self.release["document_url"])
        self.assertNotIn("/master/", self.release["document_url"])

    def test_03_connector_schema_and_pin(self):
        validator = foundation.ingestion_validator("connector-definition.schema.json")
        self.assertTrue(validator.is_valid(self.connector))
        self.assertEqual(self.release["document_url"], self.connector["targets"][0]["resource_uri"])
        self.assertEqual(0, self.connector["security_policy"]["redirect_limit"])
        self.assertTrue(self.connector["security_policy"]["tls_verify"])
        self.assertTrue(self.connector["security_policy"]["block_private_destinations"])

    def test_04_parser_and_normalizer_definition_schemas(self):
        self.assertTrue(foundation.ingestion_validator("parser-definition.schema.json").is_valid(self.parser_def))
        self.assertTrue(foundation.ingestion_validator("normalizer-definition.schema.json").is_valid(self.normalizer_def))

    def test_05_mapping_profile_digest(self):
        self.assertEqual(self.mapping["profile_digest"], normalizer.mapping_profile_digest(self.mapping))

    def test_06_documentation_inventory_schema_and_digest(self):
        validator = foundation.ingestion_validator("inventory-definition.schema.json")
        self.assertTrue(validator.is_valid(self.inventory))
        self.assertEqual(self.inventory["digest"], foundation.digest_without_field(self.inventory, "digest"))
        self.assertEqual("documentation", self.inventory["inventory_kind"])
        self.assertEqual(30, self.inventory["expected_identity_count"])
        self.assertIn("not the Sysmon emitted/provider telemetry denominator", self.inventory["scope_metadata"]["completeness_semantics"])

    def test_07_parser_extracts_only_event_headings(self):
        records = self.parse()
        self.assertEqual(["1", "255"], [record["native_fields"]["event_id"] for record in records])
        self.assertTrue(all(record["native_type"] == "sysmon-event-heading" for record in records))
        self.assertTrue(all(record["unknown_fields"] == {} for record in records))
        self.assertTrue(all("prose remains" in record["diagnostics"][0] for record in records))

    def test_08_parser_replay_is_deterministic(self):
        first = self.parse()
        second = self.parse()
        self.assertEqual(first, second)
        self.assertEqual(parser.representation_digest(first), parser.representation_digest(second))

    def test_09_psr_identity_binds_snapshot(self):
        first = self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:a")
        second = self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:b")
        self.assertNotEqual(first[0]["parsed_record_id"], second[0]["parsed_record_id"])

    def test_10_psr_schema_and_phase531_digest_contract(self):
        validator = foundation.ingestion_validator("parsed-source-record.schema.json")
        for record in self.parse():
            self.assertTrue(validator.is_valid(record))
            payload = {
                key: record.get(key)
                for key in ("native_type", "native_key", "native_identifiers", "native_fields", "unknown_fields", "locator")
            }
            self.assertEqual(foundation.sha256_digest(payload), record["record_digest"])
            expected_id = foundation.stable_artifact_id(
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
            self.assertEqual(expected_id, record["parsed_record_id"])

    def test_11_duplicate_event_heading_is_structural_failure(self):
        duplicate = self.fixture + "\n### Event ID 1: Duplicate synthetic heading\n"
        with self.assertRaises(ValueError):
            self.parse(duplicate)

    def test_12_release_drift_fails_closed_at_normalizer(self):
        records = self.parse()
        records[0]["native_fields"]["document_release_version"] = "99.99"
        with self.assertRaises(ValueError):
            self.normalize(records)

    def test_13_mapping_tamper_fails_closed(self):
        mapping = copy.deepcopy(self.mapping)
        mapping["channel"] = "tampered"
        with self.assertRaises(ValueError):
            self.normalize(mapping=mapping)

    def test_14_sysmon_event_1_canonical_identity_and_context(self):
        output = self.normalize()
        entity = next(record for record in output["records"] if record["id"] == "atlas:event:microsoft.sysmon:1")
        self.assertEqual("event", entity["entity_type"])
        native = entity["native_identifiers"][0]
        self.assertEqual("event_id", native["type"])
        self.assertEqual("1", native["value"])
        self.assertEqual("Microsoft-Windows-Sysmon", native["context"]["provider"])
        self.assertEqual("Microsoft-Windows-Sysmon/Operational", native["context"]["channel"])
        self.assertEqual("Sysmon", native["context"]["product"])
        self.assertEqual("Windows", native["context"]["platform"])
        self.assertEqual("documented", native["components"]["documentation_status"])

    def test_15_documentation_does_not_set_canonical_lifecycle(self):
        output = self.normalize()
        self.assertTrue(all("lifecycle" not in record for record in output["records"]))
        self.assertTrue(any("lifecycle intentionally remains unset" in item for item in output["diagnostics"]))

    def test_16_numeric_native_identifier_remains_lossless_string(self):
        for entity in self.normalize()["records"]:
            self.assertIsInstance(entity["native_identifiers"][0]["value"], str)
            self.assertNotIn("numeric_sort_value", json.dumps(entity))

    def test_17_canonical_candidates_validate(self):
        validator = phase52.root_validator()
        for entity in self.normalize()["records"]:
            errors = list(validator.iter_errors(entity))
            self.assertEqual([], errors, [e.message for e in errors])

    def test_18_lineage_valid_and_binds_source_snapshot(self):
        output = self.normalize()
        validator = foundation.ingestion_validator("normalization-lineage.schema.json")
        for lineage in output["lineage"]:
            self.assertTrue(validator.is_valid(lineage))
            self.assertEqual([SNAPSHOT_ID], lineage["source_snapshot_ids"])
            body = copy.deepcopy(lineage)
            body.pop("lineage_id")
            body.pop("lineage_digest")
            digest = foundation.sha256_digest(body)
            self.assertEqual(digest, lineage["lineage_digest"])
            self.assertEqual(f"atlas:normalization-lineage:atlas.ingestion:{digest}", lineage["lineage_id"])

    def test_19_normalizer_replay_is_deterministic(self):
        self.assertEqual(self.normalize(), self.normalize())

    def test_20_documentation_inventory_expected_ids_match_release_profile(self):
        release_ids = self.release["expected_documented_event_ids"]
        inventory_ids = [item["event_id"] for item in self.inventory["scope_metadata"]["expected_identities"]]
        self.assertEqual(release_ids, inventory_ids)
        self.assertEqual([str(i) for i in range(1, 30)] + ["255"], release_ids)


if __name__ == "__main__":
    unittest.main()
