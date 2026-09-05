from __future__ import annotations

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


parser = mod("sysmon_schema_historical_parser", ROOT / "ingestion/parsers/microsoft_sysmon_schema.py")
SOURCE_ID = "atlas:source:atlas.source:microsoft-sysmon-schema-export"
SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:sysmon-schema-historical-test"


class SysmonHistoricalBinaryVersionTests(unittest.TestCase):
    def test_decimal_binary_versions_from_historical_sysmon_schemas_are_valid(self):
        text = """
<manifest schemaversion="4.70" binaryversion="15.0">
  <events>
    <event name="SYSMONEVENT_CREATE_PROCESS" value="1" level="Informational" template="Process Create" version="5">
      <data name="UtcTime" inType="win:UnicodeString" />
    </event>
  </events>
</manifest>
<manifest schemaversion="4.32" binaryversion="9.20">
  <events>
    <event name="SYSMONEVENT_CREATE_PROCESS" value="1" level="Informational" template="Process Create" version="4">
      <data name="UtcTime" inType="win:UnicodeString" />
    </event>
  </events>
</manifest>
"""
        records = parser.parse_text(text, source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT_ID)
        self.assertEqual(["4.32", "4.70"], [record["native_fields"]["schema_version"] for record in records])
        self.assertEqual(["9.20", "15.0"], [record["native_fields"]["binary_version"] for record in records])

    def test_non_version_binary_value_fails_closed(self):
        text = """
<manifest schemaversion="4.70" binaryversion="15.x">
  <events>
    <event name="SYSMONEVENT_CREATE_PROCESS" value="1" level="Informational" template="Process Create" version="5">
      <data name="UtcTime" inType="win:UnicodeString" />
    </event>
  </events>
</manifest>
"""
        with self.assertRaisesRegex(ValueError, "invalid binaryversion"):
            parser.parse_text(text, source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT_ID)

    def test_historical_hex_event_id_is_preserved_losslessly_with_numeric_derivation(self):
        text = """
<manifest schemaversion="4.32" binaryversion="9.20">
  <events>
    <event name="SYSMONEVENT_LEGACY_INTERNAL" value="0xf002" level="Informational" template="Legacy Internal" version="1">
      <data name="UtcTime" inType="win:UnicodeString" />
    </event>
  </events>
</manifest>
"""
        records = parser.parse_text(text, source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT_ID)
        self.assertEqual(1, len(records))
        record = records[0]
        self.assertEqual("0xf002", record["native_fields"]["event_id"])
        self.assertEqual(0xF002, record["native_fields"]["event_id_numeric_value"])
        self.assertEqual("0xf002", record["native_identifiers"][0]["value"])
        self.assertIn("event-id:0xf002", record["native_key"])

    def test_decimal_and_hex_spellings_of_same_event_id_cannot_duplicate_within_schema(self):
        text = """
<manifest schemaversion="4.32" binaryversion="9.20">
  <events>
    <event name="HEX" value="0xf002" level="Informational" template="Hex" version="1">
      <data name="UtcTime" inType="win:UnicodeString" />
    </event>
    <event name="DECIMAL" value="61442" level="Informational" template="Decimal" version="1">
      <data name="UtcTime" inType="win:UnicodeString" />
    </event>
  </events>
</manifest>
"""
        with self.assertRaisesRegex(ValueError, "duplicate Sysmon Event ID"):
            parser.parse_text(text, source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT_ID)


if __name__ == "__main__":
    unittest.main()
