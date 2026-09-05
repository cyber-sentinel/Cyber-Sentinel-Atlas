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


foundation = mod("structural_norm_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
phase52 = mod("structural_norm_phase52", ROOT / "tools/validate_phase52.py")
windows_parser = mod("structural_norm_windows_parser", ROOT / "ingestion/parsers/microsoft_windows_provider_metadata.py")
windows_normalizer = mod("structural_norm_windows_normalizer", ROOT / "ingestion/normalizers/microsoft_windows_provider_metadata.py")
sysmon_parser = mod("structural_norm_sysmon_parser", ROOT / "ingestion/parsers/microsoft_sysmon_schema.py")
sysmon_normalizer = mod("structural_norm_sysmon_normalizer", ROOT / "ingestion/normalizers/microsoft_sysmon_schema.py")

WINDOWS_SOURCE_ID = "atlas:source:atlas.source:microsoft-windows-provider-metadata"
WINDOWS_SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:windows-provider-structural-test"
SYSMON_SOURCE_ID = "atlas:source:atlas.source:microsoft-sysmon-schema-export"
SYSMON_SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:sysmon-schema-structural-test"
RETRIEVED_AT = "2026-09-05T13:03:53Z"


class WindowsSysmonStructuralNormalizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.windows_mapping = load("ingestion/mappings/microsoft-windows-provider-metadata-v1.json")
        cls.sysmon_mapping = load("ingestion/mappings/microsoft-sysmon-schema-v1.json")
        cls.windows_definition = load("ingestion/normalizers/microsoft-windows-provider-metadata.definition.json")
        cls.sysmon_definition = load("ingestion/normalizers/microsoft-sysmon-schema.definition.json")
        cls.windows_fixture = load("fixtures/phase-5.3/reference-exports/windows-security-provider-export.realistic.synthetic.json")
        cls.sysmon_fixture = (ROOT / "fixtures/phase-5.3/reference-exports/sysmon-schema-export.realistic.synthetic.txt").read_text(encoding="utf-8")

    def windows_psr(self):
        return windows_parser.parse_document(
            copy.deepcopy(self.windows_fixture),
            source_id=WINDOWS_SOURCE_ID,
            source_snapshot_id=WINDOWS_SNAPSHOT_ID,
        )

    def sysmon_psr(self, text=None):
        return sysmon_parser.parse_text(
            self.sysmon_fixture if text is None else text,
            source_id=SYSMON_SOURCE_ID,
            source_snapshot_id=SYSMON_SNAPSHOT_ID,
        )

    def normalize_windows(self, mapping=None):
        return windows_normalizer.normalize_psr(
            self.windows_psr(),
            mapping_profile=copy.deepcopy(mapping or self.windows_mapping),
            source_version=self.windows_mapping["source_version"],
            retrieved_at=RETRIEVED_AT,
        )

    def normalize_sysmon(self, records=None, mapping=None):
        return sysmon_normalizer.normalize_psr(
            records if records is not None else self.sysmon_psr(),
            mapping_profile=copy.deepcopy(mapping or self.sysmon_mapping),
            source_version=self.sysmon_mapping["source_version"],
            retrieved_at=RETRIEVED_AT,
        )

    def test_01_normalizer_definitions_validate_and_match_implementations(self):
        schema = foundation.ingestion_validator("normalizer-definition.schema.json")
        self.assertTrue(schema.is_valid(self.windows_definition))
        self.assertTrue(schema.is_valid(self.sysmon_definition))
        self.assertEqual(windows_normalizer.NORMALIZER_ID, self.windows_definition["normalizer_id"])
        self.assertEqual(sysmon_normalizer.NORMALIZER_ID, self.sysmon_definition["normalizer_id"])
        self.assertFalse(self.windows_definition["network_access"])
        self.assertFalse(self.sysmon_definition["network_access"])
        self.assertFalse(self.windows_definition["ai_enabled"])
        self.assertFalse(self.sysmon_definition["ai_enabled"])

    def test_02_mapping_profile_digests_are_bound(self):
        self.assertEqual(self.windows_mapping["profile_digest"], windows_normalizer.mapping_profile_digest(self.windows_mapping))
        self.assertEqual(self.sysmon_mapping["profile_digest"], sysmon_normalizer.mapping_profile_digest(self.sysmon_mapping))

    def test_03_windows_provider_versions_consolidate_into_canonical_identity_shells(self):
        result = self.normalize_windows()
        records = {record["canonical_key"]: record for record in result["records"]}
        self.assertIn("4688", records)
        self.assertIn("592", records)
        event = records["4688"]
        self.assertEqual("atlas:event:microsoft.windows.security:4688", event["id"])
        self.assertEqual("4688", event["native_identifiers"][0]["value"])
        self.assertEqual("Microsoft-Windows-Security-Auditing", event["native_identifiers"][0]["context"]["provider"])
        self.assertNotIn("lifecycle", event)
        self.assertEqual("observed", event["native_identifiers"][0]["components"]["provider_inventory_status"])
        self.assertEqual(["1", "2"], event["native_identifiers"][0]["components"]["observed_event_versions"])

    def test_04_windows_provider_normalization_is_deterministic_and_lineage_valid(self):
        first = self.normalize_windows()
        second = self.normalize_windows()
        self.assertEqual(first, second)
        root = phase52.root_validator()
        lineage_schema = foundation.ingestion_validator("normalization-lineage.schema.json")
        for record in first["records"]:
            self.assertEqual([], list(root.iter_errors(record)))
        for lineage in first["lineage"]:
            self.assertEqual([], list(lineage_schema.iter_errors(lineage)))
        self.assertEqual(first["candidate_digest"], foundation.sha256_digest(first["records"]))

    def test_05_sysmon_normalizer_selects_only_pinned_current_schema(self):
        result = self.normalize_sysmon()
        records = {record["canonical_key"]: record for record in result["records"]}
        self.assertEqual({"1", "255"}, set(records))
        self.assertEqual("Process Create", records["1"]["title"])
        self.assertEqual("4.91", records["1"]["native_identifiers"][0]["context"]["schema_version"])
        self.assertEqual("1", records["1"]["native_identifiers"][0]["value"])
        self.assertNotIn("lifecycle", records["1"])
        self.assertEqual(5, int(records["1"]["native_identifiers"][0]["components"]["event_version"]))

    def test_06_sysmon_current_schema_normalization_is_deterministic_and_valid(self):
        first = self.normalize_sysmon()
        second = self.normalize_sysmon()
        self.assertEqual(first, second)
        root = phase52.root_validator()
        lineage_schema = foundation.ingestion_validator("normalization-lineage.schema.json")
        for record in first["records"]:
            self.assertEqual([], list(root.iter_errors(record)))
        for lineage in first["lineage"]:
            self.assertEqual([], list(lineage_schema.iter_errors(lineage)))
        self.assertEqual(first["candidate_digest"], foundation.sha256_digest(first["records"]))

    def test_07_historical_hexadecimal_sysmon_event_is_preserved_in_psr_but_not_current_output(self):
        historical = """
<manifest schemaversion="4.32" binaryversion="9.20">
  <events>
    <event name="SYSMONEVENT_HISTORICAL" value="0xf002" level="Informational" template="Historical" version="1">
      <data name="UtcTime" inType="win:UnicodeString" />
    </event>
  </events>
</manifest>
"""
        records = self.sysmon_psr(self.sysmon_fixture + "\n" + historical)
        old = next(record for record in records if record["native_fields"]["event_id"] == "0xf002")
        self.assertEqual("0xf002", old["native_identifiers"][0]["value"])
        result = self.normalize_sysmon(records=records)
        self.assertNotIn(str(int("f002", 16)), {record["canonical_key"] for record in result["records"]})

    def test_08_mapping_tamper_fails_closed(self):
        windows_mapping = copy.deepcopy(self.windows_mapping)
        windows_mapping["windows_build"] = "tampered"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.normalize_windows(mapping=windows_mapping)

        sysmon_mapping = copy.deepcopy(self.sysmon_mapping)
        sysmon_mapping["current_schema_version"] = "4.90"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.normalize_sysmon(mapping=sysmon_mapping)

    def test_09_structural_normalizers_do_not_make_global_lifecycle_claims(self):
        for result in (self.normalize_windows(), self.normalize_sysmon()):
            self.assertTrue(result["records"])
            self.assertTrue(all("lifecycle" not in record for record in result["records"]))
            self.assertTrue(any("lifecycle" in diagnostic for diagnostic in result["diagnostics"]))


if __name__ == "__main__":
    unittest.main()
