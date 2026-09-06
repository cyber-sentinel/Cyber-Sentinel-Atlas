"""Static closure validator for the Phase 5.5.2 verified pack runtime."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REQUIRED = (
    ROOT / "docs" / "adr" / "0023-secure-content-pack-trust-and-update-model.md",
    ROOT / "docs" / "architecture" / "phase-5.5.2-verified-pack-runtime.md",
    ROOT / "tools" / "pack" / "requirements-phase552.txt",
    ROOT / "tools" / "pack" / "archive.py",
    ROOT / "tools" / "pack" / "tuf_runtime.py",
    ROOT / "tools" / "pack" / "activation.py",
    ROOT / "tools" / "pack" / "builder.py",
    ROOT / "tools" / "pack" / "versioning.py",
    ROOT / "tests" / "phase55" / "phase552_helpers.py",
    ROOT / "tests" / "phase55" / "test_phase552_archive.py",
    ROOT / "tests" / "phase55" / "test_phase552_tuf_runtime.py",
    ROOT / "tests" / "phase55" / "test_phase552_activation.py",
    ROOT / "tests" / "phase55" / "test_phase552_builder.py",
)

PRIVATE_KEY_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    for path in REQUIRED:
        require(path.is_file(), f"missing Phase 5.5.2 file: {path.relative_to(ROOT)}")

    adr = REQUIRED[0].read_text(encoding="utf-8")
    require("**Status:** Accepted" in adr, "ADR-0023 must remain Accepted")
    require("The Update Framework (TUF)" in adr, "ADR-0023 TUF decision missing")
    require("tuf==7.0.0" in adr, "ADR-0023 exact reference TUF pin missing")

    architecture = REQUIRED[1].read_text(encoding="utf-8")
    for phrase in (
        "bounded archive preflight",
        "offline TUF refresh/verification",
        "atomic active-state swap",
        "Last Known Good",
        "does **not** select the future production Shared Core language",
    ):
        require(phrase in architecture, f"Phase 5.5.2 architecture invariant missing: {phrase}")

    requirements = {
        line.strip()
        for line in REQUIRED[2].read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    require("tuf==7.0.0" in requirements, "python-tuf must be exactly pinned to 7.0.0")
    require(
        "securesystemslib[crypto]==1.4.0" in requirements,
        "test/reference crypto dependency must be exactly pinned",
    )

    archive = REQUIRED[3].read_text(encoding="utf-8")
    require("extractall(" not in archive and ".extract(" not in archive, "unsafe ZipFile extraction helper detected")
    require("max_compression_ratio" in archive, "archive compression-ratio bound missing")
    require("WINDOWS_REPARSE_POINT" in archive, "Windows reparse-point guard missing")

    tuf_runtime = REQUIRED[4].read_text(encoding="utf-8")
    require("PackDirectoryFetcher" in tuf_runtime, "local-only TUF fetcher missing")
    require("atlas.invalid" in tuf_runtime, "synthetic offline TUF origin missing")
    require("Updater(" in tuf_runtime and "bootstrap=" in tuf_runtime, "TUF updater/bootstrap path missing")
    require("SQLiteSearchCore.open" in tuf_runtime and "build_index" in tuf_runtime, "search validation/rebuild path missing")

    activation = REQUIRED[5].read_text(encoding="utf-8")
    require("os.O_EXCL" in activation, "exclusive runtime lock missing")
    require("os.replace" in activation, "atomic runtime publication primitive missing")
    require("highest_seen_packs" in activation, "pack rollback state missing")
    require("lkg_generation" in activation, "LKG state missing")

    builder = REQUIRED[6].read_text(encoding="utf-8")
    require("CryptoSigner" not in builder, "production builder must not handle signing keys")
    require(".sign(" not in builder, "production builder must not sign TUF metadata")
    require("ZIP_STORED" in builder, "deterministic stored transport profile missing")
    require("safe_extract_atlaspack" in builder, "builder round-trip safe extraction missing")
    require("verify_pack_directory" in builder, "builder round-trip trust verification missing")

    # Private-key fixture material is forbidden. Ephemeral key generation code in the
    # test helper is allowed, but serialized secret material may not be embedded.
    inspected_roots = [
        ROOT / "tools" / "pack",
        ROOT / "tests" / "phase55",
        ROOT / "docs" / "architecture",
    ]
    for directory in inspected_roots:
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() in {".pyc", ".zip", ".sqlite", ".sqlite3"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for marker in PRIVATE_KEY_MARKERS:
                require(marker not in text, f"private key material marker found in {path.relative_to(ROOT)}")

    # The pack/runtime schema family stays parallel: canonical AtlasRecord schemas are
    # frozen and no pack schema may leak into schemas/v1.
    canonical = ROOT / "schemas" / "v1"
    require(canonical.is_dir(), "canonical schemas/v1 missing")
    require(not (canonical / "pack-manifest.schema.json").exists(), "pack schema leaked into canonical model")

    print("Phase 5.5.2 Verified Pack Runtime: STATIC CLOSURE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
