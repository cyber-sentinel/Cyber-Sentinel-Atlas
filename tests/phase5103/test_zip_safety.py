import stat
import unittest
import zipfile

from tools.release.zip_safety import validate_zip_members


def info(name: str, *, mode: int | None = None, encrypted: bool = False) -> zipfile.ZipInfo:
    item = zipfile.ZipInfo(name)
    if mode is not None:
        item.create_system = 3
        item.external_attr = mode << 16
    if encrypted:
        item.flag_bits |= 0x1
    return item


class WindowsPortableZipSafetyTests(unittest.TestCase):
    def test_normal_files_pass(self):
        errors, count = validate_zip_members([
            info("Cyber-Sentinel-ATLAS/atlas.exe", mode=stat.S_IFREG | 0o644),
            info("Cyber-Sentinel-ATLAS/README.md", mode=stat.S_IFREG | 0o644),
        ])
        self.assertEqual(errors, [])
        self.assertEqual(count, 2)

    def test_path_and_windows_alias_attacks_fail(self):
        members = [
            info("../escape.exe"),
            info("C:/escape.exe"),
            info("//server/share/file.exe"),
            info("app/atlas.exe:payload"),
            info("app/NUL.txt"),
            info("app/name. "),
            info("app/Readme.txt"),
            info("app/README.TXT"),
        ]
        errors, _ = validate_zip_members(members)
        joined = "\n".join(errors)
        self.assertIn("unsafe ZIP entry path", joined)
        self.assertIn("drive-qualified ZIP entry path", joined)
        self.assertIn("absolute/UNC ZIP entry path", joined)
        self.assertIn("Windows ADS/colon", joined)
        self.assertIn("Windows reserved-device", joined)
        self.assertIn("Windows trailing-dot/space", joined)
        self.assertIn("Windows case-insensitive ZIP collision", joined)

    def test_symlink_special_and_encrypted_entries_fail(self):
        members = [
            info("link", mode=stat.S_IFLNK | 0o777),
            info("pipe", mode=stat.S_IFIFO | 0o600),
            info("secret.bin", mode=stat.S_IFREG | 0o600, encrypted=True),
        ]
        errors, count = validate_zip_members(members)
        joined = "\n".join(errors)
        self.assertIn("symlink ZIP entry is not allowed", joined)
        self.assertIn("special-file ZIP entry is not allowed", joined)
        self.assertIn("encrypted ZIP entry is not allowed", joined)
        self.assertEqual(count, 3)


if __name__ == "__main__":
    unittest.main()
