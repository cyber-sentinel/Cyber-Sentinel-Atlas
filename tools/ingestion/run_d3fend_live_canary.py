#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def mod(name,path): s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
p=mod("d3p",ROOT/"ingestion/parsers/mitre_d3fend_turtle.py"); n=mod("d3n",ROOT/"ingestion/normalizers/mitre_d3fend.py"); p52=mod("d352",ROOT/"tools/validate_phase52.py")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
def fetch_exact(url,max_bytes):
    req=urllib.request.Request(url,headers={"User-Agent":"Cyber-Sentinel-Atlas/Phase5.3.4"}); opener=urllib.request.build_opener(NoRedirect); r=opener.open(req,timeout=120); data=r.read(max_bytes+1)
    if len(data)>max_bytes: raise RuntimeError("D3FEND live response exceeds connector bound")
    return data
def main():
    rel=json.loads((ROOT/"ingestion/source-profiles/mitre-d3fend-ontology.release.json").read_text()); con=json.loads((ROOT/"ingestion/connectors/mitre-d3fend-ontology.json").read_text()); mp=json.loads((ROOT/"ingestion/mappings/mitre-d3fend-v1.json").read_text()); target=con["targets"][0]; raw=fetch_exact(target["resource_uri"],con["security_policy"]["max_response_bytes"])
    psr=p.parse_bytes(raw,source_id=rel["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:d3fend-live-canary",expected_sha256=rel["distribution_sha256"]); result=n.normalize_psr(psr,mapping_profile=mp,source_version=rel["ontology_version"],retrieved_at="2026-09-05T16:30:00Z")
    if result["identity_outcomes"]["AMBIGUOUS"] or result["quarantined"]: raise RuntimeError("D3FEND live canary produced identity ambiguity")
    bad=[r["id"] for r in result["records"] if not p52.root_validator().is_valid(r)]
    if bad: raise RuntimeError(f"D3FEND canonical validation failures: {bad[:5]}")
    print(f"D3FEND live canary PASS: bytes={len(raw)} psr={len(psr)} canonical={len(result['records'])} digest={p.sha256_digest(raw)}")
    return 0
if __name__=="__main__": raise SystemExit(main())
