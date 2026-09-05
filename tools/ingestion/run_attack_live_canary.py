#!/usr/bin/env python3
from __future__ import annotations
import copy, hashlib, importlib.util, ipaddress, json, socket, ssl, sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPSHandler,HTTPRedirectHandler,Request,build_opener
ROOT=Path(__file__).resolve().parents[2]

def mod(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);assert s.loader;s.loader.exec_module(m);return m
def load(p):return json.loads((ROOT/p).read_text(encoding="utf-8"))
def now():return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
def blob_sha1(raw):return hashlib.sha1(f"blob {len(raw)}\0".encode()+raw).hexdigest()
def public_dns(host):
 ips={x[4][0] for x in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)}
 if not ips or any(not ipaddress.ip_address(x).is_global for x in ips):raise RuntimeError(f"non-public DNS resolution for {host}: {sorted(ips)}")
def fetch(url,sec,f):
 errs=f.public_uri_errors(url,sec.get("allowed_hosts"),None)
 if errs:raise RuntimeError("unsafe URL: "+"; ".join(errs))
 if sec.get("tls_verify") is not True or sec.get("redirect_limit")!=0:raise RuntimeError("TLS verification + zero redirects required")
 public_dns(urlparse(url).hostname or "")
 op=build_opener(NoRedirect(),HTTPSHandler(context=ssl.create_default_context())); req=Request(url,headers={"User-Agent":"Cyber-Sentinel-Atlas/phase-5.3.2-canary","Accept":"application/json"})
 limit=int(sec["max_response_bytes"]); parts=[]; total=0
 with op.open(req,timeout=float(sec["read_timeout_seconds"])) as r:
  if r.status!=200 or r.geturl()!=url:raise RuntimeError(f"unexpected HTTP response {r.status} {r.geturl()}")
  if r.headers.get("Content-Length") and int(r.headers["Content-Length"])>limit:raise RuntimeError("response too large")
  while True:
   b=r.read(min(1048576,limit-total+1))
   if not b:break
   parts.append(b);total+=len(b)
   if total>limit:raise RuntimeError("stream exceeded max_response_bytes")
  h={"content_type":r.headers.get("Content-Type"),"content_length":total,"etag":r.headers.get("ETag"),"last_modified":r.headers.get("Last-Modified"),"date":r.headers.get("Date")}
 return b"".join(parts),{k:v for k,v in h.items() if v is not None}
def check(f,schema,x,label):
 e=list(f.ingestion_validator(schema).iter_errors(x))
 if e:raise RuntimeError(label+": "+"; ".join(z.message for z in e[:10]))
def semantic_view(records):
 out=copy.deepcopy(records)
 for _,r in out:
  for ev in r.get("evidence",[]):ev.pop("source_snapshot_id",None)
 return out

def main():
 source=load("ingestion/source-profiles/mitre-attack-enterprise.source.json"); rel=load("ingestion/source-profiles/mitre-attack-enterprise.release.json"); con=load("ingestion/connectors/mitre-attack-enterprise.json"); mapping=load("ingestion/mappings/mitre-attack-enterprise-v1.json")
 f=mod("live_f",ROOT/"tools/ingestion/validate_ingestion_foundation.py"); p52=mod("live_p52",ROOT/"tools/validate_phase52.py"); parser=mod("live_parser",ROOT/"ingestion/parsers/mitre_attack_stix.py"); norm=mod("live_norm",ROOT/"ingestion/normalizers/mitre_attack.py")
 start=now(); raw,headers=fetch(rel["bundle_url"],con["security_policy"],f); finish=now()
 if len(raw)!=rel["bundle_size_bytes"]:raise RuntimeError(f"byte size mismatch: {len(raw)}")
 g=blob_sha1(raw)
 if g!=rel["bundle_git_blob_sha1"]:raise RuntimeError(f"Git blob mismatch: {g}")
 rd=f.sha256_digest(raw); key=rd[7:31]; run_id=f"atlas:acquisition-run:atlas.ingestion:attack-v19.2-{key}"
 snap_id=f.stable_artifact_id("raw-snapshot",{"acquisition_run_id":run_id,"target_key":"enterprise-bundle","raw_blob_digest":rd})
 run={"ingestion_contract_version":"1.0.0","acquisition_run_id":run_id,"connector_id":con["connector_id"],"connector_version":con["connector_version"],"source_id":source["id"],"started_at":start,"finished_at":finish,"trigger":"test","execution_metadata":{"executor_ref":"github-actions-phase53-attack-canary","attempt":1,"environment_class":"ci"},"resource_results":[{"target_key":"enterprise-bundle","resource_key":rel["bundle_path"],"required":True,"status":"success","requested_uri":rel["bundle_url"],"resolved_uri":rel["bundle_url"],"snapshot_id":snap_id,"diagnostics":[]}],"metrics":{"resource_count":1,"success_count":1,"failed_count":0,"not_modified_count":0,"skipped_count":0,"bytes_received":len(raw)},"diagnostics":[],"result_status":"success","publication_eligible":True}
 snap={"ingestion_contract_version":"1.0.0","snapshot_id":snap_id,"source_id":source["id"],"source_version":rel["release_version"],"connector_id":con["connector_id"],"connector_version":con["connector_version"],"acquisition_run_id":run_id,"target_key":"enterprise-bundle","resource_key":rel["bundle_path"],"retrieved_at":finish,"requested_resource":{"uri":rel["bundle_url"],"media_type":"application/json","encoding":"utf-8"},"resolved_resource":{"uri":rel["bundle_url"],"media_type":"application/json","encoding":"utf-8"},"media_type":"application/json","encoding":"utf-8","byte_length":len(raw),"raw_content_digest":rd,"blob_ref":f"blob:{rd}","upstream_validators":{"publisher_version":rel["release_version"],"git_commit":rel["upstream_commit_sha"]},"transport_metadata":headers,"retention_mode":"transient","integrity_state":"verified"}
 check(f,"acquisition-run.schema.json",run,"AcquisitionRun");check(f,"raw-snapshot.schema.json",snap,"RawSnapshot")
 if f.acquisition_semantic_errors(con,run):raise RuntimeError("AcquisitionRun semantic failure")
 startp=now(); records=parser.parse_bytes(raw,source_id=source["id"],source_snapshot_id=snap_id); endp=now(); pd=parser.representation_digest(records)
 pr_id=f.stable_artifact_id("parser-run",{"snapshot_id":snap_id,"parser_id":parser.PARSER_ID,"parser_version":parser.PARSER_VERSION})
 pr={"ingestion_contract_version":"1.0.0","parser_run_id":pr_id,"source_snapshot_id":snap_id,"parser_id":parser.PARSER_ID,"parser_version":parser.PARSER_VERSION,"psr_version":parser.PSR_VERSION,"started_at":startp,"finished_at":endp,"result":"success","input_blob_digest":rd,"output_record_count":len(records),"representation_digest":pd,"diagnostics":[]};check(f,"parser-run.schema.json",pr,"ParserRun")
 pv=f.ingestion_validator("parsed-source-record.schema.json")
 for i,x in enumerate(records):
  z=list(pv.iter_errors(x))
  if z:raise RuntimeError(f"PSR[{i}] invalid: {z[0].message}")
 bundle=json.loads(raw.decode()); cols=[x for x in bundle.get("objects",[]) if x.get("type")=="x-mitre-collection" and x.get("id")==rel["collection_id"]]
 if len(cols)!=1 or cols[0].get("x_mitre_version")!=rel["release_version"]:raise RuntimeError("expected Enterprise collection/release absent")
 sn=now(); out=norm.normalize_psr(records,mapping_profile=mapping,source_version=rel["release_version"],retrieved_at=finish); en=now()
 if out["quarantined"] or out["identity_outcomes"]["AMBIGUOUS"]:raise RuntimeError(f"ambiguous ATT&CK identity: {out['quarantined'][:5]}")
 combined=[(ROOT/"ingestion/source-profiles/mitre-attack-enterprise.source.json",source)]+[(ROOT/f"live/attack/{i}.json",x) for i,x in enumerate(out["records"])]
 errs=p52.validate_schema_records(combined)+p52.validate_semantics(semantic_view(combined),p52.load_registries())
 for _,x in combined:
  for ev in x.get("evidence",[]):
   if ev.get("source_snapshot_id")!=snap_id:errs.append("cross-corpus snapshot mismatch")
 if errs:raise RuntimeError("canonical validation: "+"; ".join(errs[:20]))
 lv=f.ingestion_validator("normalization-lineage.schema.json")
 for x in out["lineage"]:
  z=list(lv.iter_errors(x))
  if z:raise RuntimeError("lineage invalid: "+z[0].message)
 cnt=Counter(x["record_kind"] for x in out["records"]); reg=f.sha256_digest([load(str(x.relative_to(ROOT))) for x in sorted((ROOT/"model/registries").glob("*.json"))])
 nr={"ingestion_contract_version":"1.0.0","normalization_run_id":f.stable_artifact_id("normalization-run",{"parser_run_id":pr_id,"candidate":out["candidate_digest"]}),"parser_run_id":pr_id,"normalizer_id":norm.NORMALIZER_ID,"normalizer_version":norm.NORMALIZER_VERSION,"psr_version":parser.PSR_VERSION,"mapping_profile":{"id":mapping["profile_id"],"version":mapping["profile_version"],"digest":mapping["profile_digest"]},"registry_bundle":{"version":"1.0.0","digest":reg},"canonical_schema_version":"1.0.0","started_at":sn,"finished_at":en,"result":"success","identity_outcomes":out["identity_outcomes"],"output_counts":{"EntityRecord":cnt["entity"],"ClaimRecord":cnt["claim"]},"canonical_candidate_digest":out["candidate_digest"],"publishable":True,"diagnostics":out["diagnostics"]};check(f,"normalization-run.schema.json",nr,"NormalizationRun")
 tech=[x for x in out["records"] if x.get("entity_type")=="attack-technique"]
 if not any(x["id"]=="atlas:attack-technique:mitre.attack:t1059.001" for x in tech):raise RuntimeError("T1059.001 missing")
 print(f"Phase 5.3.2 live ATT&CK canary PASSED: v{rel['release_version']} raw={len(raw)} sha256={rd} psr={len(records)} techniques={len(tech)} claims={cnt['claim']} candidate={out['candidate_digest']}");return 0
if __name__=="__main__":
 try:raise SystemExit(main())
 except Exception as e:print("Phase 5.3.2 live ATT&CK canary FAILED:",e,file=sys.stderr);raise SystemExit(1)
