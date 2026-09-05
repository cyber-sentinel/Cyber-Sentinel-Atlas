#!/usr/bin/env python3
from __future__ import annotations
import hashlib, importlib.util, json, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def mod(name,path): s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
p=mod("carp",ROOT/"ingestion/parsers/mitre_car_yaml.py"); n=mod("carn",ROOT/"ingestion/normalizers/mitre_car.py"); p52=mod("car52",ROOT/"tools/validate_phase52.py")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
def git_blob_sha1(raw): return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def fetch_exact(url,max_bytes):
    req=urllib.request.Request(url,headers={"User-Agent":"Cyber-Sentinel-Atlas/Phase5.3.4"}); r=urllib.request.build_opener(NoRedirect).open(req,timeout=30); data=r.read(max_bytes+1)
    if len(data)>max_bytes: raise RuntimeError("CAR live response exceeds connector bound")
    return data
def main():
    rel=json.loads((ROOT/"ingestion/source-profiles/mitre-car.release.json").read_text()); con=json.loads((ROOT/"ingestion/connectors/mitre-car-sample.json").read_text()); mp=json.loads((ROOT/"ingestion/mappings/mitre-car-v1.json").read_text()); raw=fetch_exact(con["targets"][0]["resource_uri"],con["security_policy"]["max_response_bytes"])
    actual=git_blob_sha1(raw)
    if actual!=rel["sample_git_blob_sha1"]: raise RuntimeError(f"CAR Git blob mismatch {actual}")
    psr=p.parse_bytes(raw,source_id=rel["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:car-live-canary")
    if len(psr)!=1 or psr[0]["native_key"]!=rel["sample_car_id"]: raise RuntimeError("CAR live canary identity mismatch")
    result=n.normalize_psr(psr,mapping_profile=mp,source_version=f"commit:{rel['upstream_commit_sha']}",retrieved_at="2026-09-05T16:30:00Z")
    bad=[r["id"] for r in result["records"] if not p52.root_validator().is_valid(r)]
    if bad: raise RuntimeError(f"CAR canonical validation failures: {bad}")
    print(f"CAR live canary PASS: bytes={len(raw)} id={psr[0]['native_key']} canonical={len(result['records'])} blob={actual}"); return 0
if __name__=="__main__": raise SystemExit(main())
