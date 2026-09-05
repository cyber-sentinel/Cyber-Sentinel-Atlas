#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


f = mod("p534_foundation_validator", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
p52 = mod("p534_canonical_validator", ROOT / "tools/validate_phase52.py")
d3n = mod("p534_d3_normalizer", ROOT / "ingestion/normalizers/mitre_d3fend.py")
carn = mod("p534_car_normalizer", ROOT / "ingestion/normalizers/mitre_car.py")
don = mod("p534_do_normalizer", ROOT / "ingestion/normalizers/defenseops_export.py")
dop = mod("p534_do_parser", ROOT / "ingestion/parsers/defenseops_export.py")
promo = mod("p534_promotion", ROOT / "tools/ingestion/phase534_promotion.py")


def load(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def validate_repository() -> list[str]:
    errors: list[str] = []
    d3_source = load("ingestion/source-profiles/mitre-d3fend-ontology.source.json")
    d3_release = load("ingestion/source-profiles/mitre-d3fend-ontology.release.json")
    d3_connector = load("ingestion/connectors/mitre-d3fend-ontology.json")
    car_source = load("ingestion/source-profiles/mitre-car.source.json")
    car_release = load("ingestion/source-profiles/mitre-car.release.json")
    car_connector = load("ingestion/connectors/mitre-car-sample.json")
    do_source = load("ingestion/source-profiles/cyber-sentinel-defenseops.source.json")
    do_release = load("ingestion/source-profiles/cyber-sentinel-defenseops.release.json")
    do_fixture = load("fixtures/phase-5.3/defenseops-export.synthetic.json")
    promotion_fixture = load("fixtures/phase-5.3/phase534-promotion-scenarios.json")

    for label, source in (("D3FEND", d3_source), ("CAR", car_source), ("DefenseOps", do_source)):
        if not p52.root_validator().is_valid(source):
            errors.append(f"{label} SourceRecord is not valid canonical v1")
    if (d3_source["license"]["status"], d3_source["redistribution"]["policy"]) != ("verified", "allowed"):
        errors.append("D3FEND source licensing must be verified/allowed")
    if (car_source["license"]["status"], car_source["redistribution"]["policy"]) != ("verified", "allowed"):
        errors.append("CAR source licensing must be verified/allowed")
    if (do_source["license"]["status"], do_source["redistribution"]["policy"]) != ("unknown", "unknown"):
        errors.append("DefenseOps repository licensing must remain fail-closed unknown/unknown")

    if d3_release["distribution_url"] != d3_connector["targets"][0]["resource_uri"]:
        errors.append("D3FEND connector does not match pinned official distribution")
    if not d3_release["distribution_sha256"].startswith("sha256-"):
        errors.append("D3FEND release profile is missing a pinned SHA-256")
    if car_release["upstream_commit_sha"] not in car_connector["targets"][0]["resource_uri"]:
        errors.append("CAR connector is not pinned to the declared commit")
    if "/master/" in car_connector["targets"][0]["resource_uri"]:
        errors.append("CAR production target must not use floating master")
    if do_release["repository_license_status"] != "unknown":
        errors.append("DefenseOps repository license must not be guessed")

    for path, module in (
        ("ingestion/mappings/mitre-d3fend-v1.json", d3n),
        ("ingestion/mappings/mitre-car-v1.json", carn),
        ("ingestion/mappings/defenseops-export-v1.json", don),
    ):
        profile = load(path)
        if profile["profile_digest"] != module.mapping_profile_digest(profile):
            errors.append(f"mapping profile digest mismatch: {path}")

    export_validator = f.ingestion_validator("extensions/defenseops-export.schema.json")
    export_schema_errors = sorted(export_validator.iter_errors(do_fixture), key=lambda error: list(error.path))
    errors.extend(f"DefenseOps export schema: {error.message}" for error in export_schema_errors)
    if do_fixture["export_digest"] != dop.export_digest(do_fixture):
        errors.append("DefenseOps synthetic export digest mismatch")

    generated = promo.scenarios()
    if promotion_fixture != generated:
        errors.append("Phase 5.3.4 promotion fixture is not reproducible from deterministic generator")

    review_validator = f.ingestion_validator("review-decision.schema.json")
    report_validator = f.ingestion_validator("build-validation-report.schema.json")
    manifest_validator = f.ingestion_validator("canonical-build-manifest.schema.json")
    for name, scenario in promotion_fixture.items():
        for label, validator, value in (
            ("review", review_validator, scenario["review"]),
            ("report", report_validator, scenario["report"]),
            ("manifest", manifest_validator, scenario["manifest"]),
        ):
            for error in validator.iter_errors(value):
                errors.append(f"{name} {label} schema: {error.message}")

    success = promotion_fixture["pack_ready_success"]
    blocked = promotion_fixture["defenseops_g14_block"]
    if success["manifest"]["state"] != "PACK_READY" or success["manifest"]["pack_ready"] is not True:
        errors.append("positive promotion scenario did not reach PACK_READY")
    if blocked["manifest"]["state"] != "REJECTED" or blocked["manifest"]["pack_ready"] is not False:
        errors.append("DefenseOps G14 failure did not fail closed")
    if blocked["manifest"]["last_known_good_preserved"] is not True:
        errors.append("DefenseOps G14 failure did not preserve Last Known Good")
    return errors


def main() -> int:
    errors = validate_repository()
    if errors:
        print("\n".join(errors))
        return 1
    print("Atlas Phase 5.3.4 D3FEND/CAR/DefenseOps/final-promotion validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
