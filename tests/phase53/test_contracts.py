from __future__ import annotations

from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("iv", ROOT / "tools" / "ingestion" / "validate_ingestion_foundation.py")
iv = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(iv)


class Phase53ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = iv.load_fixture_bundle()
        cls.artifacts = iv.bundle_artifacts(cls.bundle)

    def assert_schema_valid(self, fixture, schema):
        errors = list(iv.ingestion_validator(schema).iter_errors(self.artifacts[fixture]))
        self.assertEqual([], errors, [e.message for e in errors])

    def test_01_connector_definition(self):
        self.assert_schema_valid("connector-definition.json", "connector-definition.schema.json")

    def test_02_acquisition_run(self):
        self.assert_schema_valid("acquisition-run.json", "acquisition-run.schema.json")

    def test_03_raw_snapshot(self):
        self.assert_schema_valid("raw-snapshot.json", "raw-snapshot.schema.json")

    def test_04_parser_definition(self):
        self.assert_schema_valid("parser-definition.json", "parser-definition.schema.json")

    def test_05_parser_run(self):
        self.assert_schema_valid("parser-run.json", "parser-run.schema.json")

    def test_06_parsed_source_record(self):
        self.assert_schema_valid("parsed-source-record.json", "parsed-source-record.schema.json")

    def test_07_normalizer_definition(self):
        self.assert_schema_valid("normalizer-definition.json", "normalizer-definition.schema.json")

    def test_08_normalization_run(self):
        self.assert_schema_valid("normalization-run.json", "normalization-run.schema.json")

    def test_09_normalization_lineage(self):
        self.assert_schema_valid("normalization-lineage.json", "normalization-lineage.schema.json")

    def test_10_inventory_definition(self):
        self.assert_schema_valid("inventory-definition.json", "inventory-definition.schema.json")

    def test_11_three_layer_inventory_diff(self):
        self.assert_schema_valid("inventory-diff.json", "inventory-diff.schema.json")
        diff = self.artifacts["inventory-diff.json"]
        self.assertTrue(all(layer in diff for layer in ("raw", "parsed", "canonical")))

    def test_12_build_validation_report(self):
        self.assert_schema_valid("build-validation-report.json", "build-validation-report.schema.json")
        self.assertEqual({f"G{i}" for i in range(1, 16)}, {g["gate"] for g in self.artifacts["build-validation-report.json"]["gates"]})

    def test_13_review_decision(self):
        self.assert_schema_valid("review-decision.json", "review-decision.schema.json")

    def test_14_canonical_build_manifest(self):
        self.assert_schema_valid("canonical-build-manifest.json", "canonical-build-manifest.schema.json")

    def test_15_full_foundation_validator(self):
        self.assertEqual([], iv.validate_repository(ROOT))

    def test_16_required_optional_acquisition_semantics(self):
        connector = self.artifacts["connector-definition.json"]
        run = self.artifacts["acquisition-run.json"]
        self.assertEqual([], iv.acquisition_semantic_errors(connector, run))

    def test_17_cross_corpus_snapshot_resolution(self):
        snapshot = self.artifacts["raw-snapshot.json"]
        source_ids = {r["id"] for r in self.bundle["canonical_support"]}
        for claim in [r for r in self.bundle["canonical_candidates"] if r["record_kind"] == "claim"]:
            for evidence in claim["evidence"]:
                self.assertEqual(snapshot["snapshot_id"], evidence["source_snapshot_id"])
                self.assertIn(evidence["source_id"], source_ids)
                self.assertEqual(snapshot["source_version"], evidence["source_version"])

    def test_18_pack_ready_after_all_mandatory_gates(self):
        build = self.artifacts["canonical-build-manifest.json"]
        report = self.artifacts["build-validation-report.json"]
        review = self.artifacts["review-decision.json"]
        diff = self.artifacts["inventory-diff.json"]
        actual = iv.sha256_digest(sorted(self.bundle["canonical_candidates"], key=lambda r: r["id"]))
        self.assertEqual([], iv.review_and_pack_ready_errors(build, report, review, diff, [self.artifacts["normalization-run.json"]], actual))

    def test_19_numeric_event_id_is_lossless_string(self):
        values = [n["value"] for r in self.bundle["search_readiness"] for n in r.get("native_identifiers", []) if n.get("type") == "event_id"]
        self.assertTrue(values)
        self.assertTrue(all(isinstance(v, str) for v in values))

    def test_20_same_event_id_remains_distinct_by_context(self):
        self.assertEqual([], iv.search_readiness_errors(self.bundle["search_readiness"]))

    def test_21_legacy_event_id_is_independent(self):
        records = self.bundle["search_readiness"]
        legacy = [r for r in records if any(n.get("value") == "592" for n in r.get("native_identifiers", []))]
        self.assertEqual(1, len(legacy))
        self.assertEqual("legacy", legacy[0]["lifecycle"]["state"])

    def test_22_no_search_projection_contamination(self):
        errors = []
        for record in self.bundle["canonical_candidates"] + self.bundle["search_readiness"]:
            errors.extend(iv.find_forbidden_projection_keys(record))
        self.assertEqual([], errors)

    def test_23_ingestion_and_canonical_versions_are_independent(self):
        self.assertEqual("1.0.0", iv.INGESTION_CONTRACT_VERSION)
        self.assertEqual("1.0.0", iv.CANONICAL_SCHEMA_VERSION)
        self.assertNotEqual(iv.INGESTION_SCHEMA_URI_BASE, iv.CANONICAL_SCHEMA_URI_BASE)

    def test_24_no_eighth_atlas_record_family(self):
        self.assertFalse(iv.canonical_root_validator().is_valid(self.artifacts["connector-definition.json"]))


if __name__ == "__main__":
    unittest.main()
