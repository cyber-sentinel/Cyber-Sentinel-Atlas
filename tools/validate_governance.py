#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    ROOT / ".github" / "CODEOWNERS",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "THIRD_PARTY_NOTICES.md",
    ROOT / "CITATION.cff",
    ROOT / "TRADEMARKS.md",
    ROOT / "docs" / "governance" / "licensing-and-contributions.md",
    ROOT / "docs" / "current-status.md",
]


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> int:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED if not path.is_file()]
    if missing:
        fail(f"missing governance files: {missing}")

    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    required_owner_paths = ["* @cyber-sentinel", "/schemas/ @cyber-sentinel", "/.github/ @cyber-sentinel"]
    for rule in required_owner_paths:
        if rule not in codeowners:
            fail(f"CODEOWNERS missing required maintainer rule: {rule}")

    policy = (ROOT / "docs" / "governance" / "licensing-and-contributions.md").read_text(encoding="utf-8")
    if "PUBLIC LICENSE NOT YET GRANTED" not in policy:
        fail("licensing policy no longer declares the controlled pre-license state")

    # During controlled private development, adding a root public-license file is a material
    # release decision and must be accompanied by updating this validator/policy in the same PR.
    root_license_names = {"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"}
    unexpected = [name for name in root_license_names if (ROOT / name).exists()]
    if unexpected:
        fail(
            "public-license file appeared while governance policy is still pre-license: "
            + ", ".join(sorted(unexpected))
        )

    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    if "Unknown, incompatible, missing or ambiguous licensing is a non-waivable publication failure" not in notices:
        fail("third-party publication fail-closed rule is missing")

    print("Governance validation passed: maintainer control and pre-license publication gates intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
