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


validator = mod(
    "windows_sysmon_inventory_reconciliation",
    ROOT / "tools/ingestion/validate_windows_sysmon_inventories.py",
)
foundation = mod("inventory_reconciliation_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class WindowsSysmonInventoryReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventories = {name: load(path) for name, path in validator.INVENTORY_PATHS.items()}

    def test_01_all_phase533_inventories_validate_and_bind_digest(self):
        schema = foundation.ingestion_validator("inventory-definition.schema.json")
        for name, inventory in self.inventories.items():
            errors = list(schema.iter_errors(inventory))
            self.assertEqual([], errors, f"{name}: {[e.message for e in errors]}")
            self.assertEqual(foundation.digest_without_field(inventory, "digest"), inventory["digest"])
            ids = validator.event_ids(inventory)
            self.assertEqual(inventory["expected_identity_count"], len(ids))
            self.assertEqual(len(ids), len(set(ids)))

    def test_02_declared_real_inventory_denominators_are_exact(self):
        windows = self.inventories["windows_provider"]
        sysmon = self.inventories["sysmon_schema"]
        self.assertEqual(423, windows["expected_identity_count"])
        self.assertEqual(30, sysmon["expected_identity_count"])
        self.assertEqual("26100.33296", windows["scope_metadata"]["windows_build"])
        self.assertEqual("15.21", sysmon["scope_metadata"]["sysmon_version"])
        self.assertEqual("4.91", sysmon["scope_metadata"]["current_schema_version"])
        self.assertEqual(24, sysmon["scope_metadata"]["schema_document_count"])
        self.assertEqual(587, sysmon["scope_metadata"]["parsed_schema_event_record_count"])

    def test_03_windows_4688_documentation_reconciles_without_becoming_denominator(self):
        report = validator.reconcile(copy.deepcopy(self.inventories))
        self.assertEqual([], report["errors"])
        self.assertEqual(["4688"], report["windows"]["documented_and_observed"])
        self.assertEqual(423, report["windows"]["provider_identity_count"])
        self.assertEqual(1, report["windows"]["documented_identity_count_in_declared_scope"])
        self.assertEqual(422, report["windows"]["provider_only_count"])
        self.assertFalse(report["windows"]["documentation_is_telemetry_denominator"])

    def test_04_legacy_592_is_not_observed_but_must_be_preserved(self):
        report = validator.reconcile(copy.deepcopy(self.inventories))
        self.assertEqual([], report["errors"])
        self.assertEqual("NOT_OBSERVED", report["windows"]["legacy_592_current_provider_status"])
        self.assertEqual("PRESERVE_HISTORICAL_IDENTITY", report["windows"]["legacy_592_canonical_action"])
        self.assertFalse(report["semantics"]["not_observed_is_removed"])

    def test_05_sysmon_docs_and_current_schema_match_but_remain_independent(self):
        report = validator.reconcile(copy.deepcopy(self.inventories))
        self.assertEqual([], report["errors"])
        self.assertEqual(30, report["sysmon"]["current_schema_identity_count"])
        self.assertEqual(30, report["sysmon"]["documented_identity_count"])
        self.assertEqual([], report["sysmon"]["schema_only"])
        self.assertEqual([], report["sysmon"]["docs_only"])
        self.assertTrue(report["sysmon"]["identity_sets_equal_for_pinned_release"])
        self.assertTrue(report["sysmon"]["independent_denominators_even_when_counts_match"])

    def test_06_event_identity_and_phase54_boundary_remain_explicit(self):
        report = validator.reconcile(copy.deepcopy(self.inventories))
        self.assertFalse(report["semantics"]["event_id_is_globally_unique"])
        self.assertFalse(report["semantics"]["phase54_search_projection_materialized"])
        self.assertTrue(report["semantics"]["documentation_and_telemetry_coverage_are_independent"])

    def test_07_inventory_digest_tamper_fails_closed(self):
        inventories = copy.deepcopy(self.inventories)
        inventories["sysmon_schema"]["scope_metadata"]["current_schema_version"] = "999.0"
        report = validator.reconcile(inventories)
        self.assertTrue(any("digest does not bind complete inventory definition" in error for error in report["errors"]))

    def test_08_sysmon_identity_drift_fails_closed_after_digest_rebind(self):
        inventories = copy.deepcopy(self.inventories)
        sysmon = inventories["sysmon_schema"]
        sysmon["scope_metadata"]["expected_identities"] = [
            identity for identity in sysmon["scope_metadata"]["expected_identities"] if identity["event_id"] != "255"
        ]
        sysmon["expected_identity_count"] = 29
        sysmon["digest"] = foundation.digest_without_field(sysmon, "digest")
        report = validator.reconcile(inventories)
        self.assertTrue(any("identity sets drifted" in error for error in report["errors"]))

    def test_09_windows_documented_identity_missing_from_provider_fails_closed(self):
        inventories = copy.deepcopy(self.inventories)
        docs = inventories["windows_4688_docs"]
        docs["scope_metadata"]["expected_identities"] = [{"event_id": "9999"}]
        docs["digest"] = foundation.digest_without_field(docs, "digest")
        report = validator.reconcile(inventories)
        self.assertTrue(any("documented Windows identities are not present" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
