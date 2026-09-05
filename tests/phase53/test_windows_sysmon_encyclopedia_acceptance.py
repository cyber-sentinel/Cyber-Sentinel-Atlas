from __future__ import annotations

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


builder = mod(
    "windows_sysmon_encyclopedia_acceptance",
    ROOT / "tools/ingestion/build_windows_sysmon_encyclopedia_acceptance.py",
)
foundation = mod("windows_sysmon_acceptance_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
phase52 = mod("windows_sysmon_acceptance_phase52", ROOT / "tools/validate_phase52.py")


class WindowsSysmonEncyclopediaAcceptanceTests(unittest.TestCase):
    def build(self):
        return builder.build_acceptance_corpus()

    def test_01_acceptance_corpus_is_deterministic(self):
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)
        self.assertEqual(first["candidate_digest"], foundation.sha256_digest(first["records"]))

    def test_02_canonical_records_validate(self):
        corpus = self.build()
        root = phase52.root_validator()
        for record in corpus["records"]:
            errors = list(root.iter_errors(record))
            self.assertEqual([], errors, f"{record['id']}: {[e.message for e in errors]}")

    def test_03_acceptance_identities_and_lifecycle_are_exact(self):
        records = {record["id"]: record for record in self.build()["records"]}
        self.assertEqual(
            {
                "atlas:event:microsoft.sysmon:1",
                "atlas:event:microsoft.windows.security:4688",
                "atlas:event:microsoft.windows.security:592",
            },
            set(records),
        )
        self.assertEqual("current", records["atlas:event:microsoft.windows.security:4688"]["lifecycle"]["state"])
        self.assertEqual("current", records["atlas:event:microsoft.sysmon:1"]["lifecycle"]["state"])
        self.assertEqual("legacy", records["atlas:event:microsoft.windows.security:592"]["lifecycle"]["state"])

    def test_04_native_event_ids_remain_lossless_strings(self):
        for record in self.build()["records"]:
            native = [item for item in record.get("native_identifiers", []) if item.get("type") == "event_id"]
            self.assertEqual(1, len(native))
            self.assertIsInstance(native[0]["value"], str)

    def test_05_legacy_592_is_not_collapsed_into_4688_alias(self):
        records = {record["id"]: record for record in self.build()["records"]}
        current = records["atlas:event:microsoft.windows.security:4688"]
        legacy = records["atlas:event:microsoft.windows.security:592"]
        self.assertNotEqual(current["id"], legacy["id"])
        self.assertNotEqual(current["canonical_key"], legacy["canonical_key"])
        self.assertFalse(any(alias.get("value") == "592" for alias in current.get("aliases", [])))
        self.assertFalse(self.build()["acceptance_semantics"]["legacy_592_is_alias_of_4688"])

    def test_06_real_inventory_bindings_are_digest_bound_and_scoped(self):
        bindings = self.build()["inventory_bindings"]
        self.assertEqual(423, bindings["windows_provider"]["expected_identity_count"])
        self.assertEqual(1, bindings["windows_documentation"]["expected_identity_count"])
        self.assertEqual(30, bindings["sysmon_schema"]["expected_identity_count"])
        self.assertEqual(30, bindings["sysmon_documentation"]["expected_identity_count"])
        for binding in bindings.values():
            self.assertRegex(binding["digest"], r"^sha256-[a-f0-9]{64}$")

    def test_07_lineage_for_documentation_normalized_records_validates(self):
        corpus = self.build()
        validator = foundation.ingestion_validator("normalization-lineage.schema.json")
        self.assertEqual(2, len(corpus["lineage"]))
        for lineage in corpus["lineage"]:
            errors = list(validator.iter_errors(lineage))
            self.assertEqual([], errors, [e.message for e in errors])
        self.assertEqual(
            {
                "atlas:event:microsoft.sysmon:1",
                "atlas:event:microsoft.windows.security:4688",
            },
            {lineage["output_record_id"] for lineage in corpus["lineage"]},
        )

    def test_08_acceptance_corpus_does_not_materialize_search_projection(self):
        corpus = self.build()
        errors = []
        for record in corpus["records"]:
            errors.extend(foundation.find_forbidden_projection_keys(record))
        self.assertEqual([], errors)
        self.assertFalse(corpus["acceptance_semantics"]["phase54_search_projection_materialized"])
        self.assertFalse(corpus["acceptance_semantics"]["event_id_is_globally_unique"])

    def test_09_fixture_corpus_is_not_pack_ready_or_global_completeness_claim(self):
        corpus = self.build()
        self.assertTrue(corpus["fixture_only"])
        self.assertFalse(corpus["pack_ready"])
        self.assertTrue(corpus["acceptance_semantics"]["documentation_and_telemetry_coverage_are_independent"])
        self.assertTrue(any("not PACK_READY" in item for item in corpus["diagnostics"]))
        self.assertTrue(any("dedicated historical source ingestion" in item for item in corpus["diagnostics"]))


if __name__ == "__main__":
    unittest.main()
