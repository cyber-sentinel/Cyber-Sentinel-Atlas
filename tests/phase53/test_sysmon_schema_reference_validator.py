from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/phase-5.3/reference-exports/sysmon-schema-export.realistic.synthetic.txt"


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


validator = mod("sysmon_schema_reference_validator", ROOT / "tools/ingestion/validate_sysmon_schema_reference.py")


class SysmonSchemaReferenceValidatorTests(unittest.TestCase):
    def test_01_synthetic_reference_matches_declared_scope(self):
        result = validator.validate_reference(
            FIXTURE,
            source_id="atlas:source:atlas.source:microsoft-sysmon-schema-export",
            snapshot_id="atlas:raw-snapshot:atlas.ingestion:sysmon-schema-validator-test",
            expected_schema_count=2,
            expected_current_schema="4.91",
            expected_current_event_count=2,
            required_event_ids={"1", "255"},
        )
        self.assertEqual("4.91", result["current_schema"])
        self.assertEqual(["1", "255"], result["current_event_ids"])
        self.assertEqual({"4.90": 1, "4.91": 2}, result["event_counts_by_schema"])

    def test_02_scope_drift_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "schema-count drift"):
            validator.validate_reference(
                FIXTURE,
                source_id="atlas:source:atlas.source:microsoft-sysmon-schema-export",
                snapshot_id="atlas:raw-snapshot:atlas.ingestion:sysmon-schema-validator-test",
                expected_schema_count=24,
            )
        with self.assertRaisesRegex(ValueError, "missing required Event IDs"):
            validator.validate_reference(
                FIXTURE,
                source_id="atlas:source:atlas.source:microsoft-sysmon-schema-export",
                snapshot_id="atlas:raw-snapshot:atlas.ingestion:sysmon-schema-validator-test",
                required_event_ids={"22"},
            )


if __name__ == "__main__":
    unittest.main()
