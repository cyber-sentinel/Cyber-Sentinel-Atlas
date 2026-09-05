#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, json, re
from pathlib import Path
NORMALIZER_ID="atlas:normalizer:atlas.ingestion:defenseops-export"; NORMALIZER_VERSION="1.0.0"; CANONICAL_SCHEMA_VERSION="1.0.0"; INGESTION_CONTRACT_VERSION="1.0.0"
KEY_RE=re.compile(r"^[a-z0-9][a-z0-9._-]*$")
def canonical_json(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def sha256_digest(v):
    p=v if isinstance(v,bytes) else (v.encode() if isinstance(v,str) else canonical_json(v).encode()); return "sha256-"+hashlib.sha256(p).hexdigest()
def mapping_profile_digest(p): b=copy.deepcopy(p); b.pop("profile_digest",None); return sha256_digest(b)
def _lineage(out,psr,p,rules):
    b={"ingestion_contract_version":INGESTION_CONTRACT_VERSION,"output_record_id":out,"normalizer_id":NORMALIZER_ID,"normalizer_version":NORMALIZER_VERSION,"mapping_profile":{"id":p["profile_id"],"version":p["profile_version"],"digest":p["profile_digest"]},"parsed_record_ids":[psr["parsed_record_id"]],"source_snapshot_ids":[psr["source_snapshot_id"]],"mapping_rule_ids":rules}; d=sha256_digest(b); return {**b,"lineage_id":f"atlas:normalization-lineage:atlas.ingestion:{d}","lineage_digest":d}
def normalize_psr(psr_records,*,mapping_profile,source_version,retrieved_at):
    if mapping_profile.get("profile_digest")!=mapping_profile_digest(mapping_profile): raise ValueError("mapping profile digest mismatch")
    if mapping_profile.get("normalizer_id")!=NORMALIZER_ID or mapping_profile.get("source_version")!=source_version: raise ValueError("mapping profile binding mismatch")
    records=[]; lineage=[]; blockers=[]; quarantined=[]; seen=set(); outcomes={"CREATE":0,"MATCH":0,"AMBIGUOUS":0}
    for psr in sorted(psr_records,key=lambda x:x["parsed_record_id"]):
        if psr.get("source_id")!=mapping_profile.get("source_id"): raise ValueError("PSR source_id mismatch")
        native=psr.get("native_fields",{}); ctype=native.get("content_type"); cid=native.get("content_id")
        if ctype not in {"detection","hunt","engineering","response"} or not isinstance(cid,str): outcomes["AMBIGUOUS"]+=1; quarantined.append({"parsed_record_id":psr.get("parsed_record_id"),"reason":"invalid-defenseops-identity"}); continue
        key=cid.lower()
        if not KEY_RE.fullmatch(key): outcomes["AMBIGUOUS"]+=1; quarantined.append({"parsed_record_id":psr.get("parsed_record_id"),"reason":"content-id-not-canonical-key-safe"}); continue
        eid=f"atlas:{ctype}:defenseops:{key}"
        if eid in seen: outcomes["AMBIGUOUS"]+=1; quarantined.append({"parsed_record_id":psr.get("parsed_record_id"),"reason":"canonical-identity-collision"}); continue
        seen.add(eid); validation=native.get("validation",{}); license_meta=native.get("license",{}); item_blockers=[]
        if validation.get("review_status")!="validated": item_blockers.append("G15: DefenseOps item is not validated")
        if license_meta.get("status")!="verified": item_blockers.append("G14: DefenseOps item license is not verified")
        blockers.extend(f"{cid}: {x}" for x in item_blockers)
        entity={"schema_version":CANONICAL_SCHEMA_VERSION,"record_kind":"entity","id":eid,"record_revision":1,"created_at":retrieved_at,"updated_at":retrieved_at,"curation_status":"review" if validation.get("review_status")=="validated" else "draft","entity_type":ctype,"namespace":"defenseops","canonical_key":key,"title":cid,"native_identifiers":[{"type":"defenseops_content_id","value":cid,"namespace":"cyber-sentinel.defenseops","case_sensitive":True,"primary":True,"components":{"repository":native.get("repository"),"commit_sha":native.get("commit_sha"),"release_version":native.get("release_version"),"native_backend":native.get("native_backend"),"native_format":native.get("native_format"),"quality_level":validation.get("quality_level"),"review_status":validation.get("review_status"),"license_status":license_meta.get("status")}}]}
        records.append(entity); lineage.append(_lineage(eid,psr,mapping_profile,["defenseops.identity","defenseops.validation-metadata","defenseops.license-metadata"])); outcomes["CREATE"]+=1
    records.sort(key=lambda x:x["id"]); lineage.sort(key=lambda x:x["output_record_id"])
    return {"records":records,"lineage":lineage,"identity_outcomes":outcomes,"quarantined":quarantined,"promotion_blockers":sorted(blockers),"candidate_digest":sha256_digest(records)}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("psr",type=Path); ap.add_argument("--mapping-profile",type=Path,required=True); ap.add_argument("--source-version",required=True); ap.add_argument("--retrieved-at",required=True); ap.add_argument("--output",type=Path); a=ap.parse_args(); r=normalize_psr(json.loads(a.psr.read_text())["records"],mapping_profile=json.loads(a.mapping_profile.read_text()),source_version=a.source_version,retrieved_at=a.retrieved_at); s=json.dumps(r,sort_keys=True,indent=2)+"\n"; a.output.write_text(s) if a.output else print(s,end=""); return 0
if __name__=="__main__": raise SystemExit(main())
