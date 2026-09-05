from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


foundation = mod("reference_host_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
builder = mod("reference_host_builder", ROOT / "tools/ingestion/build_reference_export_descriptor.py")


class ReferenceHostCollectionTests(unittest.TestCase):
    def test_01_descriptor_builder_binds_raw_bytes_and_collector_provenance(self):
        metadata = {
            "ingestion_contract_version": "1.0.0",
            "reference_export_contract_version": "1.0.0",
            "source_id": "atlas:source:atlas.source:microsoft-sysmon-schema-export",
            "source_version": "sysmon-15.21",
            "export_type": "sysmon-schema",
            "collection_method": "sysmon-s-all",
            "reference_environment": {
                "platform": "windows",
                "product": "Windows Server",
                "version": "2025",
                "build": "26100.1",
                "architecture": "x64",
                "locale": "en-US",
            },
            "collector": {
                "tool_name": "Sysmon",
                "tool_publisher": "Microsoft Sysinternals",
                "tool_version": "15.21.0.0",
                "command_shape": "sysmon64 -accepteula -s all",
                "binary_sha256": "sha256-" + "1" * 64,
                "distribution_uri": "https://download.sysinternals.com/files/Sysmon.zip",
                "signature_status": "Valid",
                "signer_subject": "CN=Microsoft Corporation",
            },
            "collected_at": "2026-09-05T07:55:00Z",
            "scope": {
                "provider": "Microsoft-Windows-Sysmon",
                "channels": ["Microsoft-Windows-Sysmon/Operational"],
                "native_identifier_types": ["event_id"],
                "notes": "test",
            },
            "controls": {
                "collected_outside_atlas_core": True,
                "upstream_binary_executed_by_atlas_core": False,
                "immutable_after_ingest": True,
                "source_execution_isolated": True,
                "operator_review_required": True,
            },
            "retention_mode": "full",
            "fixture_only": False,
            "diagnostics": ["test descriptor"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "schema.txt"
            artifact.write_bytes(b"<Sysmon schemaversion=\"4.90\"/>\n")
            descriptor = builder.build_descriptor(metadata, artifact, media_type="text/plain", encoding="utf-8")

        self.assertEqual(foundation.sha256_digest(b"<Sysmon schemaversion=\"4.90\"/>\n"), descriptor["artifact"]["sha256"])
        self.assertEqual("schema.txt", descriptor["artifact"]["logical_name"])
        self.assertEqual("sha256-" + "1" * 64, descriptor["collector"]["binary_sha256"])
        body = copy.deepcopy(descriptor)
        body.pop("reference_export_id")
        self.assertEqual(foundation.stable_artifact_id("reference-export", body), descriptor["reference_export_id"])
        self.assertTrue(foundation.ingestion_validator("extensions/reference-export.schema.json").is_valid(descriptor))

    def test_02_descriptor_builder_rejects_metadata_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metadata.json"
            path.write_text(json.dumps({"reference_export_id": "caller-controlled"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                builder.load_metadata(path)

    def test_03_collection_workflow_is_manual_and_read_only(self):
        text = (ROOT / ".github/workflows/reference-host-export.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("schedule:", text)
        self.assertNotIn("\n  push:", text)
        self.assertIn("contents: read", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("runs-on: windows-latest", text)
        self.assertNotIn("git push", text.lower())
        self.assertNotIn("git commit", text.lower())

    def test_04_collection_workflow_uploads_review_artifacts_only(self):
        text = (ROOT / ".github/workflows/reference-host-export.yml").read_text(encoding="utf-8")
        self.assertIn("path: reference-output/**", text)
        self.assertIn("if-no-files-found: error", text)
        self.assertIn("retention-days: 14", text)
        self.assertIn("Expected exactly four reference-export files", text)
        for suffix in (".exe", ".dll", ".sys", ".msi", ".cab", ".zip", ".pfx", ".pem", ".key"):
            self.assertIn(suffix, text)

    def test_05_collector_uses_first_party_windows_api_and_official_sysmon_distribution(self):
        text = (ROOT / "tools/reference-host/collect_windows_sysmon_reference.ps1").read_text(encoding="utf-8")
        self.assertIn("Microsoft-Windows-Security-Auditing", text)
        self.assertIn("System.Diagnostics.Eventing.Reader.ProviderMetadata", text)
        self.assertIn("$providerMetadata.Events", text)
        self.assertIn("collection_method = 'windows-event-log-api'", text)
        self.assertIn("descriptions_included = $false", text)
        self.assertIn("https://download.sysinternals.com/files/Sysmon.zip", text)
        self.assertIn("Get-AuthenticodeSignature", text)
        self.assertIn("Sysmon version drift", text)
        self.assertIn("-accepteula -s all", text)
        self.assertIn("upstream_binary_executed_by_atlas_core = $false", text)
        self.assertIn("operator_review_required = $true", text)

    def test_06_collector_never_places_downloaded_sysmon_binary_in_output(self):
        text = (ROOT / "tools/reference-host/collect_windows_sysmon_reference.ps1").read_text(encoding="utf-8")
        self.assertIn("$work = Join-Path $env:RUNNER_TEMP", text)
        self.assertIn("$sysmonZip = Join-Path $work", text)
        self.assertIn("$sysmonDir = Join-Path $work", text)
        self.assertIn("$sysmonRawPath = Join-Path $resolvedOutput 'sysmon-schema.txt'", text)
        self.assertIn("$windowsRawPath = Join-Path $resolvedOutput 'windows-security-provider.json'", text)
        self.assertIn("Remove-Item -LiteralPath $work -Recurse -Force", text)
        self.assertNotIn("Copy-Item $sysmonExe", text)

    def test_07_reference_export_schema_keeps_collector_binary_provenance_optional(self):
        schema = json.loads((ROOT / "schemas/ingestion/v1/extensions/reference-export.schema.json").read_text(encoding="utf-8"))
        collector = schema["properties"]["collector"]
        for key in ("binary_sha256", "distribution_uri", "signature_status", "signer_subject"):
            self.assertIn(key, collector["properties"])
            self.assertNotIn(key, collector["required"])

    def test_08_windows_reference_export_uses_structural_provider_metadata_contract(self):
        text = (ROOT / "tools/reference-host/collect_windows_sysmon_reference.ps1").read_text(encoding="utf-8")
        for field in ("event_id", "version", "log_name", "level", "opcode", "task", "keywords", "template"):
            self.assertIn(field, text)
        self.assertIn("Sort-Object @{ Expression = { [long]$_.event_id } }", text)
        self.assertIn("ProviderMetadata.Events returned no events", text)
        self.assertIn("does not expose required channel", text)

    def test_09_reference_output_comparison_is_array_safe_under_strict_mode(self):
        text = (ROOT / "tools/reference-host/collect_windows_sysmon_reference.ps1").read_text(encoding="utf-8")
        self.assertIn("$fileSetDiff = @(Compare-Object", text)
        self.assertIn("if ($fileSetDiff.Count -ne 0)", text)
        self.assertNotIn("(Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $outputFiles).Count", text)


if __name__ == "__main__":
    unittest.main()
