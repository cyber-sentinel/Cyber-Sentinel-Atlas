#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def mod(name,path): s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
f=mod("p534f",ROOT/"tools/ingestion/validate_ingestion_foundation.py"); d3n=mod("p534d3",ROOT/"ingestion/normalizers/mitre_d3fend.py"); carn=mod("p534car",ROOT/"ingestion/normalizers/mitre_car.py"); don=mod("p534do",ROOT/"ingestion/normalizers/defenseops_export.py"); dop=mod("p534dop",ROOT/"ingestion/parsers/defenseops_export.py"); promo=mod("p534promo",ROOT/"tools/ingestion/phase534_promotion.py")
def load(path): return json.loads((ROOT/path).read_text())
def validate_repository():
    errors=[]; d3s=load("ingestion/source-profiles/mitre-d3fend-ontology.source.json"); cars=load("ingestion/source-profiles/mitre-car.source.json"); dos=load("ingestion/source-profiles/cyber-sentinel-defenseops.source.json")
    for src,name in [(d3s,"D3FEND"),(cars,"CAR"),(dos,"DefenseOps")]:
        if not f.canonical_validator("source.schema.json").is_valid(src): errors.append(f"{name} SourceRecord invalid")
    if (d3s["license"]["status"],d3s["redistribution"]["policy"]) != ("verified","allowed"): errors.append("D3FEND license boundary mismatch")
    if (cars["license"]["status"],cars["redistribution"]["policy"]) != ("verified","allowed"): errors.append("CAR license boundary mismatch")
    if (dos["license"]["status"],dos["redistribution"]["policy"]) != ("unknown","unknown"): errors.append("DefenseOps must remain fail-closed unknown/unknown")
    d3r=load("ingestion/source-profiles/mitre-d3fend-ontology.release.json"); d3c=load("ingestion/connectors/mitre-d3fend-ontology.json")
    if d3r["distribution_url"]!=d3c["targets"][0]["resource_uri"] or not d3r["distribution_sha256"].startswith("sha256-"): errors.append("D3FEND release/connector pin mismatch")
    carr=load("ingestion/source-profiles/mitre-car.release.json"); carc=load("ingestion/connectors/mitre-car-sample.json")
    if carr["upstream_commit_sha"] not in carc["targets"][0]["resource_uri"] or "/master/" in carc["targets"][0]["resource_uri"]: errors.append("CAR connector is not exact commit pinned")
    dor=load("ingestion/source-profiles/cyber-sentinel-defenseops.release.json")
    if dor["repository_license_status"]!="unknown": errors.append("DefenseOps repository license must not be guessed")
    for path,module in [("ingestion/mappings/mitre-d3fend-v1.json",d3n),("ingestion/mappings/mitre-car-v1.json",carn),("ingestion/mappings/defenseops-export-v1.json",don)]:
        p=load(path)
        if p["profile_digest"]!=module.mapping_profile_digest(p): errors.append(f"mapping digest mismatch: {path}")
    export=load("fixtures/phase-5.3/defenseops-export.synthetic.json"); v=f.ingestion_validator("extensions/defenseops-export.schema.json")
    if not v.is_valid(export): errors.append("DefenseOps synthetic export fails extension schema")
    if export["export_digest"]!=dop.export_digest(export): errors.append("DefenseOps synthetic export digest mismatch")
    scenarios=load("fixtures/phase-5.3/phase534-promotion-scenarios.json")
    if scenarios!=promo.scenarios(): errors.append("Phase 5.3.4 promotion fixture is not reproducible")
    rv=f.ingestion_validator("review-decision.schema.json"); br=f.ingestion_validator("build-validation-report.schema.json"); mv=f.ingestion_validator("canonical-build-manifest.schema.json")
    for name,s in scenarios.items():
        if not rv.is_valid(s["review"]): errors.append(f"{name} review schema invalid")
        if not br.is_valid(s["report"]): errors.append(f"{name} report schema invalid")
        if not mv.is_valid(s["manifest"]): errors.append(f"{name} manifest schema invalid")
    ok=scenarios["pack_ready_success"]; blocked=scenarios["defenseops_g14_block"]
    if ok["manifest"]["state"]!="PACK_READY" or not ok["manifest"]["pack_ready"]: errors.append("positive scenario did not reach PACK_READY")
    if blocked["manifest"]["state"]!="REJECTED" or blocked["manifest"]["pack_ready"] or not blocked["manifest"]["last_known_good_preserved"]: errors.append("G14 failure did not reject while preserving LKG")
    return errors
def main():
    e=validate_repository()
    if e: print("\n".join(e)); return 1
    print("Atlas Phase 5.3.4 D3FEND/CAR/DefenseOps/final-promotion validation passed."); return 0
if __name__=="__main__": raise SystemExit(main())
