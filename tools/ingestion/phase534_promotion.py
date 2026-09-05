#!/usr/bin/env python3
from __future__ import annotations
import copy, hashlib, json

def canonical_json(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def sha256_digest(v):
    p=v if isinstance(v,bytes) else (v.encode() if isinstance(v,str) else canonical_json(v).encode()); return "sha256-"+hashlib.sha256(p).hexdigest()
def digest_without(obj, field): b=copy.deepcopy(obj); b.pop(field,None); return sha256_digest(b)
def qualifying_approvals(review): return {a["actor_ref"] for a in review.get("approvals",[]) if a.get("status")=="approved"}
def review_is_qualifying(review): return review.get("outcome") in {"approved","approved-with-exceptions"} and len(qualifying_approvals(review))>=review.get("required_approvals",1) and (not review.get("high_risk") or len(qualifying_approvals(review))>=2)
def make_review(build_id,candidate_digest,diff_id,diff_digest,*,actors,high_risk=True,reviewed_at="2026-09-05T16:00:00Z"):
    approvals=[{"actor_ref":a,"approved_at":"2026-09-05T15:59:00Z","status":"approved"} for a in actors]
    r={"ingestion_contract_version":"1.0.0","review_decision_id":f"atlas:review-decision:atlas.ingestion:{build_id.split(':')[-1]}","candidate_build_id":build_id,"candidate_corpus_digest":candidate_digest,"inventory_diff_id":diff_id,"inventory_diff_digest":diff_digest,"review_policy_version":"1.0.0","outcome":"approved","reviewed_at":reviewed_at,"approvals":approvals,"findings":[],"exceptions":[],"high_risk":high_risk,"required_approvals":2 if high_risk else 1}
    r["review_digest"]=sha256_digest(r); return r
def make_report(build_id,review,*,g14=True,created_at="2026-09-05T16:01:00Z"):
    gates=[]
    for i in range(1,16):
        gate=f"G{i}"; ok=True; findings=[]
        if gate=="G14" and not g14: ok=False; findings=["License/redistribution gate failed closed"]
        if gate=="G15" and not review_is_qualifying(review): ok=False; findings=["Human review does not satisfy approval policy"]
        gates.append({"gate":gate,"mandatory":True,"result":"pass" if ok else "fail","findings":findings})
    failures=sum(g["result"]!="pass" for g in gates)
    r={"ingestion_contract_version":"1.0.0","validation_report_id":f"atlas:build-validation:atlas.ingestion:{build_id.split(':')[-1]}","build_id":build_id,"gates":gates,"mandatory_failures":failures,"publication_eligible":failures==0,"created_at":created_at}
    r["report_digest"]=sha256_digest(r); return r
def make_manifest(*,build_id,candidate_digest,diff_id,diff_digest,review,report,source_id,previous_lkg):
    review_digest_ok=review.get("review_digest")==digest_without(review,"review_digest"); report_digest_ok=report.get("report_digest")==digest_without(report,"report_digest")
    bindings_ok=review.get("candidate_build_id")==build_id and review.get("candidate_corpus_digest")==candidate_digest and review.get("inventory_diff_id")==diff_id and review.get("inventory_diff_digest")==diff_digest and report.get("build_id")==build_id
    gates_ok=len(report.get("gates",[]))==15 and all(g.get("mandatory") is True and g.get("result")=="pass" for g in report.get("gates",[])) and report.get("mandatory_failures")==0 and report.get("publication_eligible") is True
    eligible=review_is_qualifying(review) and review_digest_ok and report_digest_ok and bindings_ok and gates_ok
    state="PACK_READY" if eligible else "REJECTED"
    m={"ingestion_contract_version":"1.0.0","build_id":build_id,"state":state,"created_at":"2026-09-05T16:02:00Z","canonical_schema_version":"1.0.0","last_known_good_preserved":True,"pack_ready":eligible,"previous_last_known_good_build_id":previous_lkg}
    if eligible:
        m.update({"source_ids":[source_id],"acquisition_run_ids":["atlas:acquisition-run:atlas.ingestion:phase534-fixture"],"parser_run_ids":["atlas:parser-run:atlas.ingestion:phase534-fixture"],"normalization_run_ids":["atlas:normalization-run:atlas.ingestion:phase534-fixture"],"inventory_definition_ids":["atlas:inventory:atlas.ingestion:phase534-fixture"],"inventory_diff_id":diff_id,"inventory_diff_digest":diff_digest,"validation_report_id":report["validation_report_id"],"validation_report_digest":report["report_digest"],"review_decision_id":review["review_decision_id"],"review_decision_digest":review["review_digest"],"candidate_corpus_digest":candidate_digest})
    m["manifest_digest"]=sha256_digest(m); return m
def scenarios():
    cd="sha256-"+"1"*64; did="atlas:inventory-diff:atlas.ingestion:phase534-fixture"; dd="sha256-"+"2"*64; lkg="atlas:build:atlas.ingestion:phase533-lkg"
    bid="atlas:build:atlas.ingestion:phase534-pack-ready"; review=make_review(bid,cd,did,dd,actors=["reviewer-a","reviewer-b"]); report=make_report(bid,review,g14=True); manifest=make_manifest(build_id=bid,candidate_digest=cd,diff_id=did,diff_digest=dd,review=review,report=report,source_id="atlas:source:atlas.source:mitre-car",previous_lkg=lkg)
    bid2="atlas:build:atlas.ingestion:phase534-defenseops-g14-block"; review2=make_review(bid2,cd,did,dd,actors=["reviewer-a","reviewer-b"]); report2=make_report(bid2,review2,g14=False); manifest2=make_manifest(build_id=bid2,candidate_digest=cd,diff_id=did,diff_digest=dd,review=review2,report=report2,source_id="atlas:source:atlas.source:cyber-sentinel-defenseops",previous_lkg=lkg)
    return {"pack_ready_success":{"review":review,"report":report,"manifest":manifest},"defenseops_g14_block":{"review":review2,"report":report2,"manifest":manifest2}}
if __name__=="__main__": print(json.dumps(scenarios(),sort_keys=True,indent=2)+"\n",end="")
