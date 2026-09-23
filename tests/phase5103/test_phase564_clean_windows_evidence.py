import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.release.validate_phase564_clean_windows_evidence import validate_evidence


COMMIT = "a" * 40


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Phase564CleanWindowsEvidenceTests(unittest.TestCase):
    def make_fixture(self, root: Path):
        package = root / "Cyber-Sentinel-ATLAS-First-Preview-win-x64.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Cyber-Sentinel-ATLAS.exe", b"host")
            archive.writestr("atlas-core.exe", b"core")

        probe = root / "phase564-probe.json"
        recovery = root / "phase564-recovery-probe.json"
        payload = {
            "status_result": {
                "core_commit": COMMIT,
                "network_listener": False,
                "offline_capable": True,
            }
        }
        probe.write_text(json.dumps(payload), encoding="utf-8")
        recovery.write_text(json.dumps(payload), encoding="utf-8")

        evidence = {
            "evidence_version": 3,
            "phase": "5.6.4",
            "commit": COMMIT,
            "release_authority": False,
            "signed_candidate_claimed": False,
            "clean_windows_acceptance_claimed": False,
            "package": {
                "file": package.name,
                "sha256": digest(package),
                "size_bytes": package.stat().st_size,
            },
            "probe_evidence": {
                "portable_probe": {"file": probe.name, "sha256": digest(probe)},
                "recovery_probe": {"file": recovery.name, "sha256": digest(recovery)},
            },
            "clean_environment": {
                "runner": "github-hosted",
                "image": "windows-latest",
                "relocated_path": "C:/ATLAS First Preview",
            },
            "webview2": {
                "required": True,
                "present": True,
                "version": "1.2.3.4",
                "prerequisite_source": "preinstalled-on-runner",
                "provisioned_by_ci": False,
                "downloaded_by_atlas": False,
                "runtime_udp_endpoints": [],
            },
            "gui": {"launched": True, "remained_alive_for_seconds": 8, "process_tree": []},
            "network": {
                "tcp_listener_seen": False,
                "atlas_or_core_udp_endpoint_seen": False,
                "webview2_runtime_udp_endpoint_count": 0,
                "policy": "test",
            },
            "integrity_negative_test": "PASS_FAIL_CLOSED",
            "recovery_after_verified_restore": "PASS",
            "portable_relocation": "PASS",
        }
        return package, probe, recovery, evidence

    def test_valid_package_bound_evidence_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, probe, recovery, evidence = self.make_fixture(root)
            errors = validate_evidence(
                evidence,
                package=package,
                probe=probe,
                recovery_probe=recovery,
                expected_commit=COMMIT,
            )
            self.assertEqual(errors, [])

    def test_package_tamper_fails_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, probe, recovery, evidence = self.make_fixture(root)
            with zipfile.ZipFile(package, "a", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("tampered.txt", b"tamper")
            errors = validate_evidence(
                evidence,
                package=package,
                probe=probe,
                recovery_probe=recovery,
                expected_commit=COMMIT,
            )
            self.assertTrue(any("package SHA-256 binding mismatch" in e for e in errors))
            self.assertTrue(any("package size binding mismatch" in e for e in errors))

    def test_release_claim_and_probe_commit_drift_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package, probe, recovery, evidence = self.make_fixture(root)
            evidence["release_authority"] = True
            payload = json.loads(probe.read_text(encoding="utf-8"))
            payload["status_result"]["core_commit"] = "b" * 40
            probe.write_text(json.dumps(payload), encoding="utf-8")
            evidence["probe_evidence"]["portable_probe"]["sha256"] = digest(probe)
            errors = validate_evidence(
                evidence,
                package=package,
                probe=probe,
                recovery_probe=recovery,
                expected_commit=COMMIT,
            )
            self.assertIn("clean-Windows evidence must not claim release authority", errors)
            self.assertIn("portable probe core_commit mismatch", errors)


if __name__ == "__main__":
    unittest.main()
