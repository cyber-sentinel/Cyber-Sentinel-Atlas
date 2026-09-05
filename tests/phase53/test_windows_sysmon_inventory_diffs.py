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


foundation = mod("windows_sysmon_diff_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
reconcile = mod("windows_sysmon_diff_reconcile", ROOT / "tools/ingestion/validate_windows_sysmon_inventories.py")

DIFFS = {
    "windows": ROOT / "ingestion/inventories/diffs/phase-5.3.3-windows-security-initial.json",
    "sysmon": ROOT / "ingestion/inventories/diffs/phase-5.3.3-sysmon-schema-initial.json",
}
INVENTORIES = {
    "windows": ROOT / "ingestion/inventories/windows-security-auditing-provider-26100.33296.telemetry.json",
    "sysmon": ROOT / "ingestion/inventories/sysmon-schema-15.21-4.91.telemetry.json",
}
EMPTY_SET_DIGEST = foundation.sha256_digest([])


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class WindowsSysmonInventoryDiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.diffs = {name: load(path) for name, path in DIFFS.items()}
        cls.inventories = {name: load(path) for name, path in INVENTORIES.items()}

    def test_01_inventory_diffs_validate_and_bind_digest(self):
        schema = foundation.ingestion_validator("inventory-diff.schema.json")
        for name, diff in self.diffs.items():
            errors = list(schema.iter_errors(diff))
            self.assertEqual([], errors, f"{name}: {[e.message for e in errors]}")
            self.assertEqual(foundation.digest_without_field(diff, "diff_digest"), diff["diff_digest"])

    def test_02_diff_inventory_ids_resolve_exactly(self):
        for name, diff in self.diffs.items():
            inventory = self.inventories[name]
            self.assertEqual(inventory["inventory_id"], diff["inventory_id"])
            self.assertEqual([], foundation.inventory_guardrail_errors(inventory, diff))

    def test_03_initial_baselines_are_explicit_and_non_destructive(self):
        for diff in self.diffs.values():
            self.assertFalse(diff["not_observed_is_removed"])
            self.assertTrue(diff["guardrail_evaluation"]["growth_explained"])
            self.assertFalse(diff["guardrail_evaluation"]["blocked"])
            for layer in ("raw", "parsed", "canonical"):
                self.assertEqual(0, diff[layer]["before_count"])
                self.assertEqual(EMPTY_SET_DIGEST, diff[layer]["baseline_digest"])

    def test_04_windows_three_layer_counts_bind_real_reference_scope(self):
        diff = self.diffs["windows"]
        inventory = self.inventories["windows"]
        self.assertEqual(1, diff["raw"]["after_count"])
        self.assertEqual(488, diff["parsed"]["after_count"])
        self.assertEqual(423, diff["canonical"]["after_count"])
        self.assertEqual(inventory["expected_identity_count"], diff["canonical"]["after_count"])
        self.assertEqual(inventory["scope_metadata"]["raw_artifact_sha256"], diff["raw"]["candidate_digest"])
        self.assertEqual(inventory["scope_metadata"]["psr_representation_digest"], diff["parsed"]["candidate_digest"])
        expected = foundation.sha256_digest(sorted(reconcile.event_ids(inventory), key=int))
        self.assertEqual(expected, diff["canonical"]["candidate_digest"])

    def test_05_sysmon_three_layer_counts_bind_real_reference_scope(self):
        diff = self.diffs["sysmon"]
        inventory = self.inventories["sysmon"]
        self.assertEqual(1, diff["raw"]["after_count"])
        self.assertEqual(587, diff["parsed"]["after_count"])
        self.assertEqual(30, diff["canonical"]["after_count"])
        self.assertEqual(inventory["expected_identity_count"], diff["canonical"]["after_count"])
        self.assertEqual(inventory["scope_metadata"]["raw_artifact_sha256"], diff["raw"]["candidate_digest"])
        self.assertEqual(inventory["scope_metadata"]["psr_representation_digest"], diff["parsed"]["candidate_digest"])
        expected = foundation.sha256_digest(sorted(reconcile.event_ids(inventory), key=int))
        self.assertEqual(expected, diff["canonical"]["candidate_digest"])

    def test_06_initial_growth_explanation_cannot_be_silently_removed(self):
        for name, diff in self.diffs.items():
            inventory = self.inventories[name]
            tampered = json.loads(json.dumps(diff))
            tampered["guardrail_evaluation"]["growth_explained"] = False
            self.assertTrue(any("explosion" in error for error in foundation.inventory_guardrail_errors(inventory, tampered)))


if __name__ == "__main__":
    unittest.main()
