import hashlib
import unittest

from tools.release import generate_tauri_redistribution_evidence as evidence


class TauriRedistributionAssetEvidenceTests(unittest.TestCase):
    def test_deterministic_windows_icon_contract(self):
        raw = evidence.deterministic_windows_icon_bytes()
        self.assertEqual(len(raw), evidence.GENERATED_ICON_SIZE_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), evidence.GENERATED_ICON_SHA256)

    def test_generated_icon_recipe_matches_build_script(self):
        errors = []
        record = evidence.deterministic_windows_icon_evidence(errors)
        self.assertEqual(errors, [])
        self.assertTrue(record["generated_at_build"])
        self.assertEqual(record["sha256"], evidence.GENERATED_ICON_SHA256)
        self.assertEqual(record["size_bytes"], evidence.GENERATED_ICON_SIZE_BYTES)
        self.assertTrue(record["path"].endswith("/icons/icon.ico"))

    def test_non_frontend_asset_inventory_is_hash_bound(self):
        errors = []
        assets = evidence.inventory_packaging_assets(errors)
        self.assertEqual(errors, [])
        for item in assets:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreaterEqual(item["size_bytes"], 0)
            self.assertNotIn("/www/", item["path"])


if __name__ == "__main__":
    unittest.main()
