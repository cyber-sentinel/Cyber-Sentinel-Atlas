#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path

NORMALIZER_ID = "atlas:normalizer:atlas.ingestion:mitre-car"
NORMALIZER_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
INGESTION_CONTRACT_VERSION = "1.0.0"
CAR_ID_RE = re.compile(r"^CAR-[0-9]{4}-[0-9]{2}-[0-9]{3}$")


def canonical_json(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def sha256_digest(value):
    payload = value if isinstance(value, bytes) else (value.encode("utf-8") if isinstance(value, str) else canonical_json(value).encode("utf-8"))
    return "sha256-" + hashlib.sha256(payload).hexdigest()
def mapping_profile_digest(profile):
    body = copy.deepcopy(profile); body.pop("profile_digest", None); return sha256_digest(body)


def _car_id(psr):
    values = sorted({x.get("value") for x in psr.get("native_identifiers", []) if x.get("type") == "car_id" and isinstance(x.get("value"), str)})
    return values[0] if len(values) == 1 else None


def _evidence_locator(psr):
    loc = psr.get("locator", {})
    if isinstance(loc.get("json_pointer"), str): return {"json_pointer": loc["json_pointer"]}
    if isinstance(loc.get("source_key"), str): return {"other": loc["source_key"]}
    return {"other": psr.get("native_key", "CAR source record")}


def _lineage(output_record_id, psr, profile, rules):
    body = {"ingestion_contract_version":INGESTION_CONTRACT_VERSION,"output_record_id":output_record_id,"normalizer_id":NORMALIZER_ID,"normalizer_version":NORMALIZER_VERSION,"mapping_profile":{"id":profile["profile_id"],"version":profile["profile_version"],"digest":profile["profile_digest"]},"parsed_record_ids":[psr["parsed_record_id"]],"source_snapshot_ids":[psr["source_snapshot_id"]],"mapping_rule_ids":rules}
    digest = sha256_digest(body)
    return {**body,"lineage_id":f"atlas:normalization-lineage:atlas.ingestion:{digest}","lineage_digest":digest}


def normalize_psr(psr_records, *, mapping_profile, source_version, retrieved_at):
    if mapping_profile.get("profile_digest") != mapping_profile_digest(mapping_profile): raise ValueError("mapping profile digest mismatch")
    if mapping_profile.get("normalizer_id") != NORMALIZER_ID or mapping_profile.get("normalizer_version") != NORMALIZER_VERSION: raise ValueError("mapping profile normalizer binding mismatch")
    if mapping_profile.get("source_version") != source_version: raise ValueError("mapping profile source_version mismatch")
    records=[]; lineage=[]; quarantined=[]; diagnostics=[]; seen=set(); outcomes={"CREATE":0,"MATCH":0,"AMBIGUOUS":0}
    for psr in sorted(psr_records,key=lambda x:x["parsed_record_id"]):
        if psr.get("source_id") != mapping_profile.get("source_id"): raise ValueError("PSR source_id mismatch")
        if psr.get("native_type") != "mitre-car-analytic": diagnostics.append(f"{psr.get('native_key')}: native type outside CAR scope"); continue
        cid=_car_id(psr); native=psr.get("native_fields",{}); title=native.get("title")
        if not cid or not CAR_ID_RE.fullmatch(cid) or not isinstance(title,str) or not title.strip(): outcomes["AMBIGUOUS"]+=1; quarantined.append({"parsed_record_id":psr.get("parsed_record_id"),"reason":"missing-or-invalid-car-identity"}); continue
        eid=f"atlas:analytic:mitre.car:{cid.lower()}"
        if eid in seen: outcomes["AMBIGUOUS"]+=1; quarantined.append({"parsed_record_id":psr.get("parsed_record_id"),"reason":"canonical-identity-collision"}); continue
        seen.add(eid)
        entity={"schema_version":CANONICAL_SCHEMA_VERSION,"record_kind":"entity","id":eid,"record_revision":1,"created_at":retrieved_at,"updated_at":retrieved_at,"curation_status":"draft","entity_type":"analytic","namespace":"mitre.car","canonical_key":cid.lower(),"title":title.strip(),"native_identifiers":[{"type":"car_id","value":cid,"namespace":"mitre.car","case_sensitive":True,"primary":True,"components":{"source_version":source_version}}]}
        records.append(entity); lineage.append(_lineage(eid,psr,mapping_profile,["car.identity"])); outcomes["CREATE"]+=1
        desc=native.get("description")
        if isinstance(desc,str) and desc.strip():
            obj={"kind":"literal","datatype":"string","value":desc.strip()}; semantic={"subject_id":eid,"predicate":mapping_profile["description_claim_predicate"],"object":obj}; key=sha256_digest(semantic)
            claim={"schema_version":CANONICAL_SCHEMA_VERSION,"record_kind":"claim","id":f"atlas:claim:atlas.claim:{key}","record_revision":1,"created_at":retrieved_at,"updated_at":retrieved_at,"curation_status":"draft","namespace":"atlas.claim","canonical_key":key,"subject_id":eid,"predicate":mapping_profile["description_claim_predicate"],"object":obj,"confidence":"high","evidence":[{"source_id":psr["source_id"],"source_snapshot_id":psr["source_snapshot_id"],"source_version":source_version,"retrieved_at":retrieved_at,"locator":_evidence_locator(psr),"transformation_type":"direct-structured-import","reviewer_status":"unreviewed"}]}
            records.append(claim); lineage.append(_lineage(claim["id"],psr,mapping_profile,["car.description-claim"]))
        if psr.get("unknown_fields"): diagnostics.append(f"{cid}: unknown YAML keys preserved for drift review")
    records.sort(key=lambda x:x["id"]); lineage.sort(key=lambda x:x["output_record_id"])
    return {"records":records,"lineage":lineage,"identity_outcomes":outcomes,"quarantined":quarantined,"diagnostics":diagnostics,"candidate_digest":sha256_digest(records)}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("psr",type=Path); ap.add_argument("--mapping-profile",type=Path,required=True); ap.add_argument("--source-version",required=True); ap.add_argument("--retrieved-at",required=True); ap.add_argument("--output",type=Path); a=ap.parse_args()
    result=normalize_psr(json.loads(a.psr.read_text())["records"],mapping_profile=json.loads(a.mapping_profile.read_text()),source_version=a.source_version,retrieved_at=a.retrieved_at); rendered=json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+"\n"
    a.output.write_text(rendered,encoding="utf-8") if a.output else print(rendered,end=""); return 0
if __name__=="__main__": raise SystemExit(main())
