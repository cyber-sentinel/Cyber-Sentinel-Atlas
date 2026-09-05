from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/phase-5.3/reference-exports/sysmon-schema-export.realistic.synthetic.txt"
SOURCE_ID = "atlas:source:atlas.source:microsoft-sysmon-schema-export"
SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:sysmon-schema-synthetic"


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


foundation = mod("sysmon_schema_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
parser = mod("sysmon_schema_parser", ROOT / "ingestion/parsers/microsoft_sysmon_schema.py")


class SysmonSchemaParserTests(unittest.TestCase):
    def fixture_text(self) -> str:
        return FIXTURE.read_text(encoding="utf-8")

    def parse(self, text: str | None = None, snapshot_id: str = SNAPSHOT_ID):
        return parser.parse_text(
            self.fixture_text() if text is None else text,
            source_id=SOURCE_ID,
            source_snapshot_id=snapshot_id,
        )

    def test_01_parser_definition_matches_implementation(self):
        definition = json.loads((ROOT / "ingestion/parsers/microsoft-sysmon-schema.definition.json").read_text(encoding="utf-8"))
        self.assertEqual(parser.PARSER_ID, definition["parser_id"])
        self.assertEqual(parser.PARSER_VERSION, definition["parser_version"])
        self.assertTrue(foundation.ingestion_validator("parser-definition.schema.json").is_valid(definition))
        self.assertFalse(definition["security_policy"]["network_access"])
        self.assertFalse(definition["security_policy"]["source_execution"])
        self.assertFalse(definition["security_policy"]["xml_external_entities"])
        self.assertFalse(definition["security_policy"]["ai_enabled"])

    def test_02_parser_preserves_schema_event_and_field_structure(self):
        records = self.parse()
        self.assertEqual(3, len(records))
        current = next(
            record
            for record in records
            if record["native_fields"]["schema_version"] == "4.91"
            and record["native_fields"]["event_id"] == "1"
        )
        self.assertEqual("18", current["native_fields"]["binary_version"])
        self.assertEqual("5", current["native_fields"]["event_version"])
        self.assertEqual(1, current["native_fields"]["event_id_numeric_value"])
        self.assertEqual("SYSMONEVENT_CREATE_PROCESS", current["native_fields"]["event_name"])
        self.assertEqual("Process Create", current["native_fields"]["template"])
        self.assertEqual("ProcessCreate", current["native_fields"]["rule_name"])
        self.assertEqual("include", current["native_fields"]["rule_default"])
        self.assertEqual(
            ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "CommandLine"],
            [field["name"] for field in current["native_fields"]["fields"]],
        )
        self.assertEqual("microsoft.sysmon", current["native_identifiers"][0]["namespace"])
        self.assertEqual("Microsoft-Windows-Sysmon/Operational", current["native_identifiers"][0]["context"]["channel"])

    def test_03_same_event_id_across_schema_versions_remains_distinct_psr(self):
        event_one = [record for record in self.parse() if record["native_fields"]["event_id"] == "1"]
        self.assertEqual(2, len(event_one))
        self.assertEqual({"4.90", "4.91"}, {record["native_fields"]["schema_version"] for record in event_one})
        self.assertEqual(2, len({record["native_key"] for record in event_one}))
        self.assertEqual(2, len({record["parsed_record_id"] for record in event_one}))

    def test_04_psr_records_validate_and_digests_match_foundation_contract(self):
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

    def test_05_replay_is_deterministic_and_snapshot_identity_is_bound(self):
        first = self.parse()
        second = self.parse()
        self.assertEqual(first, second)
        self.assertEqual(parser.representation_digest(first), parser.representation_digest(second))
        other = self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:sysmon-schema-other")
        self.assertNotEqual(first[0]["parsed_record_id"], other[0]["parsed_record_id"])

    def test_06_duplicate_schema_version_fails_closed(self):
        text = self.fixture_text()
        first_manifest = parser.MANIFEST_RE.search(text)
        assert first_manifest
        with self.assertRaisesRegex(ValueError, "duplicate Sysmon schema version"):
            self.parse(text + "\n" + first_manifest.group(0))

    def test_07_duplicate_event_id_within_manifest_fails_closed(self):
        duplicate = (
            '<event name="DUPLICATE" value="1" level="Informational" template="Duplicate" version="1">'
            '<data name="UtcTime" inType="win:UnicodeString" /></event>'
        )
        text = self.fixture_text().replace("</events>", duplicate + "</events>", 1)
        with self.assertRaisesRegex(ValueError, "duplicate Sysmon Event ID 1"):
            self.parse(text)

    def test_08_duplicate_field_name_fails_closed(self):
        text = self.fixture_text().replace(
            '<data name="CommandLine" inType="win:UnicodeString" outType="xs:string" />',
            '<data name="CommandLine" inType="win:UnicodeString" outType="xs:string" />'
            '<data name="CommandLine" inType="win:UnicodeString" outType="xs:string" />',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate field 'CommandLine'"):
            self.parse(text)

    def test_09_malformed_xml_and_invalid_identifiers_fail_closed(self):
        malformed = '<manifest schemaversion="4.91" binaryversion="18"><events><event value="1"></events></manifest>'
        with self.assertRaises(ValueError):
            self.parse(malformed)

        bad_event = self.fixture_text().replace('value="255"', 'value="not-numeric"', 1)
        with self.assertRaisesRegex(ValueError, "invalid event ID"):
            self.parse(bad_event)

        bad_version = self.fixture_text().replace('version="3"', 'version="v3"', 1)
        with self.assertRaisesRegex(ValueError, "nonnumeric event version"):
            self.parse(bad_version)

    def test_10_dtd_and_entity_declarations_are_rejected_before_xml_parse(self):
        for declaration in (
            '<!DOCTYPE manifest SYSTEM "file:///etc/passwd">',
            '<!ENTITY atlas SYSTEM "http://127.0.0.1/">',
        ):
            with self.assertRaisesRegex(ValueError, "forbidden DTD/entity"):
                self.parse(declaration + "\n" + self.fixture_text())

    def test_11_unknown_structured_attributes_are_preserved_and_reported(self):
        text = self.fixture_text().replace(
            '<manifest schemaversion="4.91" binaryversion="18">',
            '<manifest schemaversion="4.91" binaryversion="18" futureManifest="x">',
            1,
        ).replace(
            'name="SYSMONEVENT_CREATE_PROCESS" value="1"',
            'name="SYSMONEVENT_CREATE_PROCESS" value="1" futureEvent="y"',
            1,
        ).replace(
            '<data name="CommandLine" inType="win:UnicodeString" outType="xs:string" />',
            '<data name="CommandLine" inType="win:UnicodeString" outType="xs:string" futureField="z" />',
            1,
        )
        current = next(
            record
            for record in self.parse(text)
            if record["native_fields"]["schema_version"] == "4.91"
            and record["native_fields"]["event_id"] == "1"
        )
        self.assertEqual("x", current["unknown_fields"]["manifest_attributes"]["futureManifest"])
        self.assertEqual("y", current["unknown_fields"]["event_attributes"]["futureEvent"])
        self.assertEqual("z", current["unknown_fields"]["field_attributes"]["5"]["futureField"])
        self.assertTrue(current["diagnostics"])

    def test_12_input_must_be_utf8_and_size_bounded(self):
        with self.assertRaisesRegex(ValueError, "normalized UTF-8"):
            parser.parse_bytes(b"\xff\xfe\xfd", source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT_ID)
        with self.assertRaisesRegex(ValueError, "exceeds input limit"):
            parser.parse_bytes(b"x" * (parser.MAX_INPUT_BYTES + 1), source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT_ID)


if __name__ == "__main__":
    unittest.main()
