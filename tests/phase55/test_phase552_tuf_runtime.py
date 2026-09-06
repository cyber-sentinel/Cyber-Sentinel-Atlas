from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
from tuf.api.exceptions import DownloadHTTPError

from tests.phase55.phase552_helpers import (
    bump_repository_metadata,
    make_signed_repository,
    tamper_json_signature,
)
from tools.pack.tuf_runtime import (
    PackDirectoryFetcher,
    PackVerificationError,
    verify_pack_directory,
)


def verify_fixture(fixture, tmp_path: Path):
    return verify_pack_directory(
        fixture.root,
        bootstrap_root=fixture.bootstrap_root,
        metadata_cache_dir=tmp_path / "cache",
        verified_targets_dir=tmp_path / "verified",
        publication=True,
    )


def test_valid_signed_repository_verifies_offline(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    verified = verify_fixture(fixture, tmp_path / "runtime")
    assert verified.pack_id == "atlas:pack:phase552-test"
    assert verified.pack_version == "1.0.0-test.1"
    assert verified.used_rebuilt_search_index is False
    assert verified.runtime_search_index.is_file()


def test_wrong_bootstrap_root_fails_closed(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo-a")
    other = make_signed_repository(tmp_path / "repo-b")
    with pytest.raises(PackVerificationError, match="TUF verification failed"):
        verify_pack_directory(
            fixture.root,
            bootstrap_root=other.bootstrap_root,
            metadata_cache_dir=tmp_path / "cache",
            verified_targets_dir=tmp_path / "verified",
        )


def test_tampered_target_bytes_fail_tuf_hash_verification(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    canonical = fixture.root / "targets" / "content" / "canonical-records.jsonl"
    canonical.write_bytes(canonical.read_bytes() + b" ")
    with pytest.raises(PackVerificationError, match="TUF artifact verification failed"):
        verify_fixture(fixture, tmp_path / "runtime")


def test_tampered_timestamp_signature_fails_closed(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    tamper_json_signature(fixture.root / "metadata" / "timestamp.json")
    with pytest.raises(PackVerificationError, match="TUF verification failed"):
        verify_fixture(fixture, tmp_path / "runtime")


def test_expired_metadata_fails_closed(tmp_path: Path) -> None:
    fixture = make_signed_repository(
        tmp_path / "repo",
        expiry=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(PackVerificationError, match="TUF verification failed"):
        verify_fixture(fixture, tmp_path / "runtime")


def test_persistent_tuf_cache_rejects_metadata_rollback(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    old_repo = tmp_path / "old-repository-copy"
    shutil.copytree(fixture.root, old_repo)
    cache = tmp_path / "durable-tuf-cache"

    # Establish trusted metadata version 1.
    verify_pack_directory(
        fixture.root,
        bootstrap_root=fixture.bootstrap_root,
        metadata_cache_dir=cache,
        verified_targets_dir=tmp_path / "verified-v1",
    )

    # Publish and trust version 2 with the exact same root keys/targets.
    bump_repository_metadata(fixture)
    verify_pack_directory(
        fixture.root,
        bootstrap_root=fixture.bootstrap_root,
        metadata_cache_dir=cache,
        verified_targets_dir=tmp_path / "verified-v2",
    )

    # Replaying the previously valid signed version 1 metadata must now fail closed.
    with pytest.raises(PackVerificationError, match="TUF verification failed"):
        verify_pack_directory(
            old_repo,
            bootstrap_root=fixture.bootstrap_root,
            metadata_cache_dir=cache,
            verified_targets_dir=tmp_path / "verified-replay",
        )


def test_tuf_authorized_but_manifest_undeclared_target_is_rejected(tmp_path: Path) -> None:
    fixture = make_signed_repository(
        tmp_path / "repo",
        extra_tuf_target=("content/undeclared.bin", b"signed but undeclared"),
    )
    with pytest.raises(PackVerificationError, match="undeclared"):
        verify_fixture(fixture, tmp_path / "runtime")


def test_manifest_inventory_exact_byte_binding_fails_closed(tmp_path: Path) -> None:
    fixture = make_signed_repository(
        tmp_path / "repo",
        inventory_digest_override="sha256-" + "0" * 64,
    )
    with pytest.raises(PackVerificationError, match="control contract failed"):
        verify_fixture(fixture, tmp_path / "runtime")


def test_invalid_canonical_record_fails_after_tuf_verification(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo", invalid_canonical=True)
    with pytest.raises(PackVerificationError, match="AtlasRecord schema failure"):
        verify_fixture(fixture, tmp_path / "runtime")


def test_corrupt_but_signed_search_index_is_rebuilt_from_verified_spc(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo", corrupt_search_index=True)
    verified = verify_fixture(fixture, tmp_path / "runtime")
    assert verified.used_rebuilt_search_index is True
    assert "_runtime-derived" in verified.runtime_search_index.parts
    assert verified.runtime_search_index.is_file()


def test_absent_prebuilt_search_index_is_rebuilt(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo", include_search_index=False)
    verified = verify_fixture(fixture, tmp_path / "runtime")
    assert verified.used_rebuilt_search_index is True
    assert verified.runtime_search_index.is_file()


def test_local_fetcher_refuses_any_non_synthetic_origin(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    fetcher = PackDirectoryFetcher(fixture.root)
    with pytest.raises(DownloadHTTPError):
        list(fetcher._fetch("https://example.com/metadata/timestamp.json"))
    with pytest.raises(DownloadHTTPError):
        list(fetcher._fetch("file:///etc/passwd"))
    with pytest.raises(DownloadHTTPError):
        list(fetcher._fetch("https://atlas.invalid/metadata/timestamp.json?x=1"))
