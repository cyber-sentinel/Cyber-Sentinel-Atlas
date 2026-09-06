from __future__ import annotations

import stat
import zipfile
from pathlib import Path

import pytest

from tools.pack.archive import (
    PackArchiveError,
    PackSafetyLimits,
    _validate_entry_type,
    safe_extract_atlaspack,
)


def write_zip(path: Path, entries: list[tuple[str, bytes]], *, compression=zipfile.ZIP_STORED) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)


def minimal_entries() -> list[tuple[str, bytes]]:
    return [
        ("metadata/root.json", b"{}"),
        ("metadata/timestamp.json", b"{}"),
        ("metadata/snapshot.json", b"{}"),
        ("metadata/targets.json", b"{}"),
        ("targets/atlas/pack-manifest.json", b"{}"),
    ]


def test_safe_extract_valid_layout(tmp_path: Path) -> None:
    pack = tmp_path / "valid.atlaspack"
    write_zip(pack, minimal_entries())
    out = tmp_path / "out"
    report = safe_extract_atlaspack(pack, out)
    assert report.file_count == 5
    assert (out / "targets" / "atlas" / "pack-manifest.json").read_bytes() == b"{}"


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "../targets/content/a.json",
        "targets/content/../evil.json",
        "/targets/content/a.json",
        "C:/targets/content/a.json",
        "targets\\content\\a.json",
        "targets/content/CON.json",
        "targets/content/name. ",
        "outside/content/a.json",
        "metadata/nested/targets.json",
        "metadata/evil.json",
        "targets/other/a.json",
        "targets/content/run.ps1",
    ],
)
def test_unsafe_archive_names_fail_closed(tmp_path: Path, unsafe_name: str) -> None:
    pack = tmp_path / "unsafe.atlaspack"
    write_zip(pack, minimal_entries() + [(unsafe_name, b"x")])
    with pytest.raises(PackArchiveError):
        safe_extract_atlaspack(pack, tmp_path / "out")


def test_non_nfc_path_fails_closed(tmp_path: Path) -> None:
    pack = tmp_path / "nfc.atlaspack"
    write_zip(pack, minimal_entries() + [("targets/content/cafe\u0301.json", b"x")])
    with pytest.raises(PackArchiveError, match="NFC"):
        safe_extract_atlaspack(pack, tmp_path / "out")


def test_case_collision_fails_closed(tmp_path: Path) -> None:
    pack = tmp_path / "collision.atlaspack"
    write_zip(
        pack,
        minimal_entries()
        + [
            ("targets/content/Records.json", b"a"),
            ("targets/content/records.json", b"b"),
        ],
    )
    with pytest.raises(PackArchiveError, match="colliding"):
        safe_extract_atlaspack(pack, tmp_path / "out")


def test_symlink_and_reparse_entries_fail_closed() -> None:
    symlink = zipfile.ZipInfo("targets/content/link.json")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(PackArchiveError, match="non-regular"):
        _validate_entry_type(symlink)

    reparse = zipfile.ZipInfo("targets/content/reparse.json")
    reparse.external_attr = 0x0400
    with pytest.raises(PackArchiveError, match="reparse"):
        _validate_entry_type(reparse)


def test_encrypted_entry_flag_fails_closed() -> None:
    encrypted = zipfile.ZipInfo("targets/content/secret.json")
    encrypted.flag_bits |= 0x1
    with pytest.raises(PackArchiveError, match="encrypted"):
        _validate_entry_type(encrypted)


def test_unsupported_compression_fails_closed(tmp_path: Path) -> None:
    pack = tmp_path / "bzip.atlaspack"
    write_zip(pack, minimal_entries(), compression=zipfile.ZIP_BZIP2)
    with pytest.raises(PackArchiveError, match="compression"):
        safe_extract_atlaspack(pack, tmp_path / "out")


def test_compression_ratio_bomb_fails_closed(tmp_path: Path) -> None:
    pack = tmp_path / "ratio.atlaspack"
    entries = minimal_entries() + [("targets/content/zeros.bin", b"0" * 1024 * 1024)]
    write_zip(pack, entries, compression=zipfile.ZIP_DEFLATED)
    limits = PackSafetyLimits(max_compression_ratio=10.0)
    with pytest.raises(PackArchiveError, match="compression-ratio"):
        safe_extract_atlaspack(pack, tmp_path / "out", limits=limits)


def test_entry_and_total_size_bounds_fail_closed(tmp_path: Path) -> None:
    pack = tmp_path / "bounds.atlaspack"
    write_zip(pack, minimal_entries())
    with pytest.raises(PackArchiveError, match="entries"):
        safe_extract_atlaspack(pack, tmp_path / "entries", limits=PackSafetyLimits(max_entries=2))

    data_pack = tmp_path / "size.atlaspack"
    write_zip(data_pack, [("targets/content/a.bin", b"12345")])
    with pytest.raises(PackArchiveError, match="per-file"):
        safe_extract_atlaspack(
            data_pack,
            tmp_path / "size",
            limits=PackSafetyLimits(max_file_uncompressed_bytes=4),
        )


def test_nonempty_staging_destination_is_rejected(tmp_path: Path) -> None:
    pack = tmp_path / "valid.atlaspack"
    write_zip(pack, minimal_entries())
    out = tmp_path / "out"
    out.mkdir()
    (out / "existing.txt").write_text("do not overwrite", encoding="utf-8")
    with pytest.raises(PackArchiveError, match="empty"):
        safe_extract_atlaspack(pack, out)
    assert (out / "existing.txt").read_text(encoding="utf-8") == "do not overwrite"
