from __future__ import annotations

import shutil
from pathlib import Path

from tests.phase55.phase552_helpers import make_signed_repository
from tools.pack.activation import install_atlaspack, load_runtime_state, resolve_active_generation
from tools.pack.archive import safe_extract_atlaspack
from tools.pack.builder import build_verified_atlaspack
from tools.pack.tuf_runtime import verify_pack_directory


def test_builder_roundtrip_reverifies_transport(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    output = tmp_path / "out" / "atlas-test.atlaspack"
    report = build_verified_atlaspack(
        fixture.root,
        output,
        bootstrap_root=fixture.bootstrap_root,
    )
    assert report.output_path == output
    assert report.sha256.startswith("sha256-")
    assert report.length == output.stat().st_size
    assert report.file_count >= 7

    extracted = tmp_path / "manual-extract"
    safe_extract_atlaspack(output, extracted)
    verified = verify_pack_directory(
        extracted,
        bootstrap_root=fixture.bootstrap_root,
        metadata_cache_dir=tmp_path / "manual-cache",
        verified_targets_dir=tmp_path / "manual-verified",
    )
    assert verified.pack_id == fixture.manifest["pack_id"]


def test_builder_is_byte_deterministic_for_same_signed_source(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    first = tmp_path / "first.atlaspack"
    second = tmp_path / "second.atlaspack"
    r1 = build_verified_atlaspack(fixture.root, first, bootstrap_root=fixture.bootstrap_root)
    r2 = build_verified_atlaspack(fixture.root, second, bootstrap_root=fixture.bootstrap_root)
    assert r1.sha256 == r2.sha256
    assert r1.length == r2.length
    assert first.read_bytes() == second.read_bytes()


def test_end_to_end_atlaspack_install_commits_lkg(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    pack = tmp_path / "atlas-test.atlaspack"
    build_verified_atlaspack(fixture.root, pack, bootstrap_root=fixture.bootstrap_root)

    runtime = tmp_path / "runtime"
    generation = install_atlaspack(
        pack,
        bootstrap_root=fixture.bootstrap_root,
        runtime_root=runtime,
    )
    state = load_runtime_state(runtime)
    assert state["active_generation"] == generation
    assert state["lkg_generation"] == generation
    active = resolve_active_generation(runtime)
    assert (active / "targets" / "atlas" / "pack-manifest.json").is_file()
    assert (active / "derived" / "search" / "atlas-search.sqlite3").is_file()


def test_builder_rejects_output_inside_signed_source_tree(tmp_path: Path) -> None:
    fixture = make_signed_repository(tmp_path / "repo")
    from tools.pack.builder import PackBuildError

    try:
        build_verified_atlaspack(
            fixture.root,
            fixture.root / "bad.atlaspack",
            bootstrap_root=fixture.bootstrap_root,
        )
    except PackBuildError as exc:
        assert "must not be inside" in str(exc)
    else:
        raise AssertionError("builder accepted output inside signed source tree")
