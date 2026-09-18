#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "docs" / "releases" / "first-party-license-readiness.json"
README = ROOT / "README.md"
CONTRIB = ROOT / "CONTRIBUTING.md"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", action="store_true")
    args = ap.parse_args()
    data = json.loads(STATE.read_text(encoding="utf-8"))
    errors: list[str] = []

    if data.get("schema_version") != "1.0.0": errors.append("schema_version must be 1.0.0")
    if data.get("gate") != "PPR-03": errors.append("gate must be PPR-03")
    if data.get("state") not in {"BLOCKED", "PASS"}: errors.append("state must be BLOCKED or PASS")
    if data.get("third_party_relicensed") is not False: errors.append("third_party_relicensed must remain false")
    if not isinstance(data.get("owner_approved"), bool): errors.append("owner_approved must be boolean")

    license_path = ROOT / str(data.get("license_file", "LICENSE"))
    license_id = data.get("license_id")
    recorded_hash = data.get("license_sha256")
    pass_ready = False

    if data.get("state") == "PASS" or args.release:
        if data.get("owner_approved") is not True: errors.append("explicit maintainer approval is required")
        if not isinstance(license_id, str) or not license_id.strip(): errors.append("license_id is required")
        if not license_path.is_file(): errors.append("approved LICENSE file is missing")
        if not isinstance(recorded_hash, str) or not SHA256_RE.fullmatch(recorded_hash):
            errors.append("license_sha256 must be 64 lowercase hex characters")
        elif license_path.is_file():
            actual = hashlib.sha256(license_path.read_bytes()).hexdigest()
            if actual != recorded_hash: errors.append("LICENSE SHA-256 does not match readiness record")
        if data.get("contribution_rights_model") in {None, "", "PENDING"}:
            errors.append("contribution_rights_model must be resolved")
        readme = README.read_text(encoding="utf-8")
        contrib = CONTRIB.read_text(encoding="utf-8")
        contradictions = (
            "No project `LICENSE` is currently published",
            "does not currently publish a general public project license",
        )
        if any(x in readme or x in contrib for x in contradictions):
            errors.append("README/CONTRIBUTING still contains no-license language")
        pass_ready = not errors

    if data.get("state") == "PASS" and not pass_ready:
        errors.append("PPR-03 cannot PASS without complete license evidence")
    if args.release and not pass_ready:
        errors.append("strict release mode requires PPR-03 PASS evidence")

    if errors:
        print("PPR-03 first-party license validation FAILED:")
        for e in errors: print(f"- {e}")
        return 1
    print(f"PPR-03 first-party license validation passed ({'strict release' if args.release else 'baseline'} mode; state={data.get('state')}).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
