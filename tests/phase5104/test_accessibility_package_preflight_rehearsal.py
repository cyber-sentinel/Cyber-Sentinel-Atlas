import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.release.validate_accessibility_package_preflight_rehearsal import validate


COMMIT = "a" * 40


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AccessibilityPackagePreflightRehearsalTests(unittest.TestCase):
    def fixture(self, root: Path):
        package = root / "Cyber-Sentinel-ATLAS-First-Preview-win-x64.zip"
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Cyber-Sentinel-ATLAS.exe", b"host")
            archive.writestr("atlas-core.exe", b"core")

        clean = root / "phase564-clean-windows-evidence.json"
        clean_payload = {
            "evidence_version": 3,
            "commit": COMMIT,
            "release_authority": False,
            "signed_candidate_claimed": False,
            "clean_windows_acceptance_claimed": False,
            "package": {
                "file": package.name,
                "sha256": digest(package),
                "size_bytes": package.stat().st_size,
            },
        }
        clean.write_text(json.dumps(clean_payload), encoding="utf-8")

        static_validator = root / "validate_accessibility_preflight.py"
        static_validator.write_text("print('PPR-07 static accessibility preflight passed.')\n", encoding="utf-8")

        evidence = {
            "schema_version": "1.0.0",
            "gate": "PPR-07",
            "evidence_class": "ACCESSIBILITY_PACKAGE_PREFLIGHT_REHEARSAL",
            "release_authority": False,
            "publication_authorized": False,
            "ppr07_pass_claimed": False,
            "manual_review_complete": False,
            "manual_matrix_state": "NOT_RUN",
            "manual_review_required": True,
            "release_commit": COMMIT,
            "package": {
                "file": package.name,
                "sha256": digest(package),
                "size_bytes": package.stat().st_size,
            },
            "clean_windows_evidence": {
                "file": clean.name,
                "sha256": digest(clean),
            },
            "static_preflight": {
                "result": "PASS",
                "validator_file": static_validator.name,
                "validator_sha256": digest(static_validator),
            },
        }
        return package, clean, static_validator, evidence

    def test_valid_rehearsal_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            package, clean, static_validator, evidence = self.fixture(Path(tmp))
            self.assertEqual(validate(evidence, package=package, clean_evidence=clean, static_validator=static_validator, expected_commit=COMMIT), [])

    def test_package_tamper_fails_both_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            package, clean, static_validator, evidence = self.fixture(Path(tmp))
            with zipfile.ZipFile(package, "a", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("tampered.txt", b"tamper")
            errors = validate(evidence, package=package, clean_evidence=clean, static_validator=static_validator, expected_commit=COMMIT)
            self.assertTrue(any("package SHA-256 binding mismatch" in e for e in errors))
            self.assertTrue(any("clean-Windows package SHA-256 mismatch" in e for e in errors))

    def test_manual_or_release_claim_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            package, clean, static_validator, evidence = self.fixture(Path(tmp))
            evidence["manual_review_complete"] = True
            evidence["ppr07_pass_claimed"] = True
            errors = validate(evidence, package=package, clean_evidence=clean, static_validator=static_validator, expected_commit=COMMIT)
            self.assertIn("manual_review_complete must remain false in preflight rehearsal evidence", errors)
            self.assertIn("ppr07_pass_claimed must remain false in preflight rehearsal evidence", errors)

    def test_static_validator_drift_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            package, clean, static_validator, evidence = self.fixture(Path(tmp))
            static_validator.write_text("print('changed')\n", encoding="utf-8")
            errors = validate(evidence, package=package, clean_evidence=clean, static_validator=static_validator, expected_commit=COMMIT)
            self.assertIn("static validator SHA-256 binding mismatch", errors)


if __name__ == "__main__":
    unittest.main()
