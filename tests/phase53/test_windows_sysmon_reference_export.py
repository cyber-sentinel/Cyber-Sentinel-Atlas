from __future__ import annotations

import copy
import hashlib
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


foundation = mod("ws_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
phase52 = mod("ws_phase52", ROOT / "tools/validate_phase52.py")

REF_DIR = ROOT / "fixtures/phase-5.3/reference-exports"
SOURCE_DIR = ROOT / "ingestion/source-profiles"

DESCRIPTORS = {
    "windows": REF_DIR / "windows-security-provider-export.descriptor.json",
    "sysmon": REF_DIR / "sysmon-schema-export.descriptor.json",
}
RAW = {
    "windows": REF_DIR / "windows-security-provider-export.synthetic.json",
    "sysmon": REF_DIR / "sysmon-schema-export.synthetic.xml",
}
SOURCES = {
    "windows_provider": SOURCE_DIR / "microsoft-windows-provider-metadata.source.json",
    "windows_doc": SOURCE_DIR / "microsoft-windows-security-auditing-4688-doc.source.json",
    "sysmon_doc": SOURCE_DIR / "microsoft-sysmon-docs.source.json",
    "sysmon_schema": SOURCE_DIR / "microsoft-sysmon-schema-export.source.json",
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def expected_reference_export_id(descriptor: dict) -> str:
    body = copy.deepcopy(descriptor)
    body.pop("reference_export_id", None)
    return foundation.stable_artifact_id("reference-export", body)


class WindowsSysmonReferenceExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.descriptors = {name: load(path) for name, path in DESCRIPTORS.items()}
        cls.sources = {name: load(path) for name, path in SOURCES.items()}

    def test_01_extension_schema_valid(self):
        validator = foundation.ingestion_validator("extensions/reference-export.schema.json")
        for name, descriptor in self.descriptors.items():
            errors = list(validator.iter_errors(descriptor))
            self.assertEqual([], errors, f"{name}: {[e.message for e in errors]}")

    def test_02_reference_export_identity_binds_descriptor(self):
        for descriptor in self.descriptors.values():
            self.assertEqual(expected_reference_export_id(descriptor), descriptor["reference_export_id"])

    def test_03_raw_artifact_digest_and_length_bind_descriptor(self):
        for name, path in RAW.items():
            raw = path.read_bytes()
            descriptor = self.descriptors[name]
            digest = "sha256-" + hashlib.sha256(raw).hexdigest()
            self.assertEqual(digest, descriptor["artifact"]["sha256"])
            self.assertEqual(f"blob:{digest}", descriptor["artifact"]["blob_ref"])
            self.assertEqual(len(raw), descriptor["artifact"]["byte_length"])

    def test_04_atlas_core_never_executes_upstream_binary(self):
        for descriptor in self.descriptors.values():
            controls = descriptor["controls"]
            self.assertIs(True, controls["collected_outside_atlas_core"])
            self.assertIs(False, controls["upstream_binary_executed_by_atlas_core"])
            self.assertIs(True, controls["source_execution_isolated"])
            self.assertIs(True, controls["immutable_after_ingest"])
            self.assertIs(True, controls["operator_review_required"])

    def test_05_committed_exports_are_fixture_only(self):
        for descriptor in self.descriptors.values():
            self.assertIs(True, descriptor["fixture_only"])
            self.assertTrue(any("Synthetic fixture only" in item for item in descriptor["diagnostics"]))

    def test_06_source_profiles_are_canonical_source_records(self):
        validator = phase52.root_validator()
        for name, source in self.sources.items():
            errors = list(validator.iter_errors(source))
            self.assertEqual([], errors, f"{name}: {[e.message for e in errors]}")

    def test_07_reference_export_source_ids_resolve(self):
        source_ids = {source["id"] for source in self.sources.values()}
        for descriptor in self.descriptors.values():
            self.assertIn(descriptor["source_id"], source_ids)

    def test_08_documentation_and_inventory_sources_are_distinct(self):
        self.assertNotEqual(
            self.sources["windows_provider"]["id"],
            self.sources["windows_doc"]["id"],
        )
        self.assertNotEqual(
            self.sources["sysmon_doc"]["id"],
            self.sources["sysmon_schema"]["id"],
        )

    def test_09_canonical_sysmon_source_is_sysinternals(self):
        urls = self.sources["sysmon_doc"]["canonical_urls"]
        self.assertIn("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon", urls)

    def test_10_windows_reference_export_method_is_official_first_party(self):
        descriptor = self.descriptors["windows"]
        self.assertEqual("wevtutil-gp-ge", descriptor["collection_method"])
        self.assertEqual("Microsoft", descriptor["collector"]["tool_publisher"])
        self.assertIn(
            "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil",
            self.sources["windows_provider"]["canonical_urls"],
        )

    def test_11_sysmon_reference_export_is_version_pinned_and_out_of_band(self):
        descriptor = self.descriptors["sysmon"]
        self.assertEqual("sysmon-s-all", descriptor["collection_method"])
        self.assertEqual("15.21", descriptor["collector"]["tool_version"])
        self.assertEqual("sysmon-15.21-fixture", descriptor["source_version"])

    def test_12_no_upstream_binary_committed_as_reference_fixture(self):
        forbidden = {".exe", ".sys", ".dll", ".msi", ".cab", ".zip"}
        for path in REF_DIR.rglob("*"):
            if path.is_file():
                self.assertNotIn(path.suffix.lower(), forbidden)

    def test_13_architecture_boundary_and_search_readiness_are_recorded(self):
        text = (ROOT / "docs/architecture/phase-5.3.3-windows-sysmon-encyclopedia.md").read_text(encoding="utf-8")
        for phrase in (
            "MUST NOT download or execute Windows, Sysmon, or other upstream binaries",
            "out-of-band controlled import",
            "4688",
            "592",
            "sysmon 1",
            "NOT_OBSERVED != REMOVED",
            "Phase 5.4",
            "documentation coverage separately from telemetry inventory coverage",
        ):
            self.assertIn(phrase, text)

    def test_14_reference_export_artifacts_do_not_extend_atlas_record_union(self):
        atlas_root = json.loads((ROOT / "schemas/v1/atlas-record.schema.json").read_text(encoding="utf-8"))
        refs = atlas_root.get("oneOf", [])
        self.assertEqual(7, len(refs))
        self.assertFalse(any("reference-export" in json.dumps(item) for item in refs))


if __name__ == "__main__":
    unittest.main()
