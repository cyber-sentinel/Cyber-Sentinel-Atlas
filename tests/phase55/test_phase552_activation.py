from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.phase55.phase552_helpers import make_signed_repository
from tools.pack.activation import (
    ActivationError,
    install_verified_generation,
    load_runtime_state,
    resolve_active_generation,
)
from tools.pack.tuf_runtime import verify_pack_directory
from tools.pack.versioning import VersionError, compare_versions


def verified_fixture(tmp_path: Path, *, pack_version: str, include_search_index: bool = True):
    fixture = make_signed_repository(
        tmp_path / "repo",
        pack_version=pack_version,
        include_search_index=include_search_index,
    )
    return verify_pack_directory(
        fixture.root,
        bootstrap_root=fixture.bootstrap_root,
        metadata_cache_dir=tmp_path / "cache",
        verified_targets_dir=tmp_path / "verified",
    )


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0.0", "1.0.0", 0),
        ("1.0.1", "1.0.0", 1),
        ("2.0.0", "10.0.0", -1),
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
        ("1.0.0-beta.11", "1.0.0-rc.1", -1),
        ("1.0.0-rc.1", "1.0.0", -1),
    ],
)
def test_strict_semver_precedence(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


def test_strict_semver_rejects_leading_zeroes() -> None:
    with pytest.raises(VersionError):
        compare_versions("01.0.0", "1.0.0")
    with pytest.raises(VersionError):
        compare_versions("1.0.0-alpha.01", "1.0.0-alpha.1")


def test_initial_install_commits_active_and_lkg(tmp_path: Path) -> None:
    verified = verified_fixture(tmp_path / "v1", pack_version="1.0.0-test.1")
    runtime = tmp_path / "runtime"
    generation = install_verified_generation(verified, runtime)
    state = load_runtime_state(runtime)
    assert state["active_generation"] == generation
    assert state["lkg_generation"] == generation
    assert state["highest_seen_packs"][verified.pack_id]["version"] == "1.0.0-test.1"
    assert resolve_active_generation(runtime).name == generation


def test_higher_version_advances_active_lkg_and_highest_seen(tmp_path: Path) -> None:
    v1 = verified_fixture(tmp_path / "v1", pack_version="1.0.0-test.1")
    v2 = verified_fixture(tmp_path / "v2", pack_version="1.0.0-test.2")
    runtime = tmp_path / "runtime"
    g1 = install_verified_generation(v1, runtime)
    g2 = install_verified_generation(v2, runtime)
    state = load_runtime_state(runtime)
    assert g2 != g1
    assert state["active_generation"] == g2
    assert state["lkg_generation"] == g2
    assert state["highest_seen_packs"][v1.pack_id]["version"] == "1.0.0-test.2"


def test_lower_version_is_rejected_without_moving_active(tmp_path: Path) -> None:
    high = verified_fixture(tmp_path / "high", pack_version="1.0.0-test.2")
    low = verified_fixture(tmp_path / "low", pack_version="1.0.0-test.1")
    runtime = tmp_path / "runtime"
    current = install_verified_generation(high, runtime)
    before = load_runtime_state(runtime)
    with pytest.raises(ActivationError, match="rollback rejected"):
        install_verified_generation(low, runtime)
    after = load_runtime_state(runtime)
    assert after == before
    assert after["active_generation"] == current


def test_same_version_with_different_manifest_bytes_is_rejected(tmp_path: Path) -> None:
    first = verified_fixture(
        tmp_path / "first",
        pack_version="1.0.0-test.1",
        include_search_index=True,
    )
    changed = verified_fixture(
        tmp_path / "changed",
        pack_version="1.0.0-test.1",
        include_search_index=False,
    )
    runtime = tmp_path / "runtime"
    install_verified_generation(first, runtime)
    before = load_runtime_state(runtime)
    with pytest.raises(ActivationError, match="same pack version"):
        install_verified_generation(changed, runtime)
    assert load_runtime_state(runtime) == before


def test_pre_health_failure_does_not_advance_trust_or_active_state(tmp_path: Path) -> None:
    v1 = verified_fixture(tmp_path / "v1", pack_version="1.0.0-test.1")
    v2 = verified_fixture(tmp_path / "v2", pack_version="1.0.0-test.2")
    runtime = tmp_path / "runtime"
    install_verified_generation(v1, runtime)
    before = load_runtime_state(runtime)

    def fail_pre(_generation: Path) -> None:
        raise RuntimeError("pre health rejected")

    with pytest.raises(RuntimeError, match="pre health"):
        install_verified_generation(v2, runtime, pre_health=fail_pre)
    assert load_runtime_state(runtime) == before


def test_post_health_failure_restores_previous_lkg_but_keeps_highest_seen(tmp_path: Path) -> None:
    v1 = verified_fixture(tmp_path / "v1", pack_version="1.0.0-test.1")
    v2 = verified_fixture(tmp_path / "v2", pack_version="1.0.0-test.2")
    runtime = tmp_path / "runtime"
    g1 = install_verified_generation(v1, runtime)

    def fail_post(_generation: Path) -> None:
        raise RuntimeError("post activation health rejected")

    with pytest.raises(ActivationError, match="LKG restored"):
        install_verified_generation(v2, runtime, post_health=fail_post)

    state = load_runtime_state(runtime)
    assert state["active_generation"] == g1
    assert state["lkg_generation"] == g1
    assert state["highest_seen_packs"][v1.pack_id]["version"] == "1.0.0-test.2"
    reports = list((runtime / "reports" / "rollback").glob("*.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["restored_generation"] == g1


def test_stale_lock_fails_closed_instead_of_being_broken(tmp_path: Path) -> None:
    verified = verified_fixture(tmp_path / "v1", pack_version="1.0.0-test.1")
    runtime = tmp_path / "runtime"
    lock = runtime / "state" / "install.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text("stale\n", encoding="utf-8")
    with pytest.raises(ActivationError, match="administrative recovery"):
        install_verified_generation(verified, runtime)
    assert lock.exists()


def test_corrupt_runtime_state_fails_closed(tmp_path: Path) -> None:
    verified = verified_fixture(tmp_path / "v1", pack_version="1.0.0-test.1")
    runtime = tmp_path / "runtime"
    state_path = runtime / "state" / "runtime-state.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text('{"state_version":1,"active_generation":"../../evil"}', encoding="utf-8")
    with pytest.raises(ActivationError, match="state"):
        install_verified_generation(verified, runtime)
