from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


foundation = mod("windows_provider_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
parser = mod("windows_provider_parser", ROOT / "ingestion/parsers/microsoft_windows_provider_metadata.py")

SOURCE_ID = "atlas:source:atlas.source:microsoft-windows-provider-metadata"
SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:windows-provider-synthetic"


def sample_export() -> dict:
    return {
        "export_format_version": "1.0.0",
        "provider": "Microsoft-Windows-Security-Auditing",
        "provider_guid": "54849625-5478-4994-a5ba-3e3b0328c30d",
        "log_links": [
            {"log_name": "Security", "display_name": "Security", "is_imported": False}
        ],
        "events": [
            {
                "event_id": "4688",
                "version": "2",
                "log_name": "Security",
                "level": {"value": "0", "name": "win:LogAlways"},
                "opcode": {"value": "0", "name": "win:Info"},
                "task": {"value": "13312"},
                "keywords": [{"value": "-9214364837600034816"}],
                "template": "<template xmlns='http://schemas.microsoft.com/win/2004/08/events'><data name='SubjectUserSid' inType='win:SID'/><data name='NewProcessId' inType='win:Pointer'/><data name='CommandLine' inType='win:UnicodeString'/></template>",
            },
            {
                "event_id": "592",
                "version": "0",
                "log_name": "Security",
                "level": {"value": "0"},
                "opcode": {"value": "0"},
                "task": {"value": "0"},
                "keywords": [],
                "template": "<template xmlns='http://schemas.microsoft.com/win/2004/08/events'><data name='ImageFileName' inType='win:UnicodeString'/></template>",
            },
        ],
        "structural_only": True,
        "descriptions_included": False,
    }


class WindowsProviderMetadataParserTests(unittest.TestCase):
    def parse(self, document=None, snapshot_id=SNAPSHOT_ID):
        return parser.parse_document(
            copy.deepcopy(document or sample_export()),
            source_id=SOURCE_ID,
            source_snapshot_id=snapshot_id,
        )

    def test_01_parser_definition_matches_implementation(self):
        import json
        definition = json.loads((ROOT / "ingestion/parsers/microsoft-windows-provider-metadata.definition.json").read_text(encoding="utf-8"))
        self.assertEqual(parser.PARSER_ID, definition["parser_id"])
        self.assertEqual(parser.PARSER_VERSION, definition["parser_version"])
        self.assertTrue(foundation.ingestion_validator("parser-definition.schema.json").is_valid(definition))

    def test_02_parser_emits_event_version_psr_and_template_fields(self):
        records = self.parse()
        self.assertEqual(["592", "4688"], [record["native_fields"]["event_id"] for record in records])
        event4688 = next(record for record in records if record["native_fields"]["event_id"] == "4688")
        self.assertEqual("2", event4688["native_fields"]["event_version"])
        self.assertEqual("Security", event4688["native_fields"]["channel"])
        self.assertEqual(["SubjectUserSid", "NewProcessId", "CommandLine"], event4688["native_fields"]["template_fields"])
        self.assertEqual("4688", event4688["native_identifiers"][0]["value"])
        self.assertEqual("2", event4688["native_identifiers"][0]["context"]["event_version"])

    def test_03_psr_records_validate_and_digest_matches_foundation_contract(self):
        for record in self.parse():
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

    def test_04_replay_is_deterministic_and_snapshot_identity_is_bound(self):
        first = self.parse()
        second = self.parse()
        self.assertEqual(first, second)
        self.assertEqual(parser.representation_digest(first), parser.representation_digest(second))
        other = self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:other")
        self.assertNotEqual(first[0]["parsed_record_id"], other[0]["parsed_record_id"])

    def test_05_duplicate_event_version_channel_identity_fails_closed(self):
        document = sample_export()
        document["events"].append(copy.deepcopy(document["events"][0]))
        with self.assertRaises(ValueError):
            self.parse(document)

    def test_06_malformed_template_fails_closed(self):
        document = sample_export()
        document["events"][0]["template"] = "<template><data name='x'></template>"
        with self.assertRaises(ValueError):
            self.parse(document)

    def test_07_unknown_structured_fields_are_preserved_and_reported(self):
        document = sample_export()
        document["future_export_field"] = {"revision": 2}
        document["events"][0]["future_event_field"] = ["x"]
        event4688 = next(record for record in self.parse(document) if record["native_fields"]["event_id"] == "4688")
        self.assertEqual({"revision": 2}, event4688["unknown_fields"]["export"]["future_export_field"])
        self.assertEqual(["x"], event4688["unknown_fields"]["event"]["future_event_field"])
        self.assertTrue(event4688["diagnostics"])

    def test_08_localized_descriptions_are_forbidden_in_controlled_export(self):
        document = sample_export()
        document["descriptions_included"] = True
        with self.assertRaises(ValueError):
            self.parse(document)

    def test_09_non_numeric_event_or_version_fails_closed(self):
        for field in ("event_id", "version"):
            document = sample_export()
            document["events"][0][field] = "not-numeric"
            with self.assertRaises(ValueError):
                self.parse(document)

    def test_10_provider_export_requires_structural_only_marker(self):
        document = sample_export()
        document["structural_only"] = False
        with self.assertRaises(ValueError):
            self.parse(document)


if __name__ == "__main__":
    unittest.main()
