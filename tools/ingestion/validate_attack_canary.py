#!/usr/bin/env python3
from __future__ import annotations
import copy, importlib.util, json, re, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SOURCE_ID="atlas:source:atlas.source:mitre-attack-enterprise-stix"
VERSION="19.2"; COMMIT="6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"; TREE="70b3126e8b7bc4fc59c4bd0ffde68564f34740a2"
BLOB="8b8a9c8cc9e553f96f963b91265f50ee0854636d"; SIZE=53835637
COLLECTION="x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
SNAPSHOT="atlas:raw-snapshot:atlas.ingestion:attack-canary-fixture-v19.2"; RETRIEVED="2026-09-05T00:00:00Z"
P={
 "source":ROOT/"ingestion/source-profiles/mitre-attack-enterprise.source.json",
 "release":ROOT/"ingestion/source-profiles/mitre-attack-enterprise.release.json",
 "connector":ROOT/"ingestion/connectors/mitre-attack-enterprise.json",
 "parser_def":ROOT/"ingestion/parsers/mitre-attack-stix21.definition.json",
 "parser":ROOT/"ingestion/parsers/mitre_attack_stix.py",
 "normalizer_def":ROOT/"ingestion/normalizers/mitre-attack-enterprise.definition.json",
 "normalizer":ROOT/"ingestion/normalizers/mitre_attack.py",
 "mapping":ROOT/"ingestion/mappings/mitre-attack-enterprise-v1.json",
 "fixture":ROOT/"fixtures/phase-5.3/attack-canary-stix.json",
}

def mod(name,path):
 s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); assert s.loader; s.loader.exec_module(m); return m

def load(k): return json.loads(P[k].read_text(encoding="utf-8"))
def serr(v,x,label): return [f"{label}:{'/'.join(map(str,e.absolute_path))}: {e.message}" for e in v.iter_errors(x)]
def lineage_digest(n,line):
 b=copy.deepcopy(line); b.pop("lineage_id",None); b.pop("lineage_digest",None); return n.sha256_digest(b)

def pin_errors(r,c):
 e=[]
 for k,w in (("release_version",VERSION),("upstream_commit_sha",COMMIT),("upstream_tree_sha",TREE),("bundle_git_blob_sha1",BLOB),("bundle_size_bytes",SIZE),("collection_id",COLLECTION)):
  if r.get(k)!=w:e.append(f"release pin mismatch: {k}")
 u=r.get("bundle_url","")
 if f"/{COMMIT}/enterprise-attack/enterprise-attack-{VERSION}.json" not in u:e.append("bundle URL is not exact-release pinned")
 if re.search(r"/(master|main|latest|HEAD)/",u,re.I):e.append("floating production bundle ref")
 if r.get("index",{}).get("discovery_only") is not True:e.append("floating index is not discovery-only")
 if len(c.get("targets",[]))!=1 or c["targets"][0].get("resource_uri")!=u:e.append("connector target is not pinned bundle")
 sec=c.get("security_policy",{})
 if sec.get("redirect_limit")!=0:e.append("pinned canary must use zero redirects")
 if min(sec.get("max_response_bytes",0),sec.get("max_decompressed_bytes",0))<SIZE:e.append("connector size bound below pinned bundle")
 return e

def security_errors():
 e=[]
 for label,k,tokens in (("parser","parser",["urllib","requests","socket","subprocess","os.system","eval(","exec("]),
                        ("normalizer","normalizer",["urllib","requests","socket","subprocess","os.system","eval(","exec(","openai","anthropic"])):
  text=P[k].read_text(encoding="utf-8")
  e += [f"{label} deterministic core contains forbidden capability: {x}" for x in tokens if x in text]
 return e

def semantic_view(records):
 out=copy.deepcopy(records)
 for _,r in out:
  for ev in r.get("evidence",[]):ev.pop("source_snapshot_id",None)
 return out

def validate_repository(root=ROOT):
 e=[]; f=mod("foundation_attack",ROOT/"tools/ingestion/validate_ingestion_foundation.py"); p52=mod("phase52_attack",ROOT/"tools/validate_phase52.py")
 parser=mod("attack_parser",P["parser"]); norm=mod("attack_norm",P["normalizer"])
 s,r,c,pd,nd,m,fixture=[load(k) for k in ("source","release","connector","parser_def","normalizer_def","mapping","fixture")]
 e+=serr(p52.root_validator(),s,"SourceRecord")
 for schema,x,label in (("connector-definition.schema.json",c,"Connector"),("parser-definition.schema.json",pd,"ParserDefinition"),("normalizer-definition.schema.json",nd,"NormalizerDefinition")):
  e+=serr(f.ingestion_validator(schema),x,label)
 e+=pin_errors(r,c)+security_errors()+f.validate_json_secret_surface([s,r,c,pd,nd,m,fixture])
 if s.get("id")!=SOURCE_ID or c.get("source_id")!=SOURCE_ID or m.get("source_id")!=SOURCE_ID:e.append("source identity binding mismatch")
 if s.get("source_class")!="tier-a-authoritative" or s.get("official_status")!="official":e.append("MITRE source authority classification mismatch")
 if s.get("license",{}).get("status")!="verified" or s.get("redistribution",{}).get("policy")!="allowed":e.append("MITRE license disposition missing")
 if m.get("profile_digest")!=norm.mapping_profile_digest(m):e.append("mapping profile digest mismatch")
 if pd.get("parser_id")!=parser.PARSER_ID or nd.get("normalizer_id")!=norm.NORMALIZER_ID:e.append("definition/implementation identity mismatch")
 if P["fixture"].stat().st_size>32768:e.append("committed ATT&CK fixture too large")
 attacks=[x for x in fixture.get("objects",[]) if x.get("type")=="attack-pattern"]; cols=[x for x in fixture.get("objects",[]) if x.get("type")=="x-mitre-collection"]
 if len(attacks)!=1 or "description" in attacks[0]:e.append("fixture must contain one prose-free attack-pattern")
 if len(cols)!=1 or cols[0].get("id")!=COLLECTION or cols[0].get("x_mitre_version")!=VERSION:e.append("fixture collection/release mismatch")
 a=parser.parse_bundle(copy.deepcopy(fixture),source_id=SOURCE_ID,source_snapshot_id=SNAPSHOT); b=parser.parse_bundle(copy.deepcopy(fixture),source_id=SOURCE_ID,source_snapshot_id=SNAPSHOT)
 if a!=b or parser.representation_digest(a)!=parser.representation_digest(b):e.append("parser replay is non-deterministic")
 pv=f.ingestion_validator("parsed-source-record.schema.json")
 for i,x in enumerate(a):e+=serr(pv,x,f"PSR[{i}]")
 tech=next(x for x in a if x["native_type"]=="attack-pattern")
 if tech.get("unknown_fields",{}).get("x_mitre_future_field")!="preserve-me":e.append("unknown source field not preserved")
 ra=norm.normalize_psr(a,mapping_profile=m,source_version=VERSION,retrieved_at=RETRIEVED); rb=norm.normalize_psr(b,mapping_profile=m,source_version=VERSION,retrieved_at=RETRIEVED)
 if ra!=rb:e.append("normalizer replay is non-deterministic")
 ent=next((x for x in ra["records"] if x.get("record_kind")=="entity"),None)
 if not ent or ent.get("id")!="atlas:attack-technique:mitre.attack:t1059.001" or ent.get("lifecycle",{}).get("state")!="current":e.append("T1059.001 canonical/lifecycle mapping mismatch")
 if ra["quarantined"]:e.append("valid canary technique quarantined")
 t=copy.deepcopy(tech); t["native_fields"]["description"]="Synthetic ATT&CK description for provenance testing only."
 cr=norm.normalize_psr([t],mapping_profile=m,source_version=VERSION,retrieved_at=RETRIEVED); claims=[x for x in cr["records"] if x["record_kind"]=="claim"]
 if len(claims)!=1 or claims[0]["confidence"]=="authoritative" or claims[0]["evidence"][0].get("source_snapshot_id")!=SNAPSHOT:e.append("claim provenance/trust mapping mismatch")
 combined=[(P["source"],s)]+[(ROOT/f"generated/attack/{i}.json",x) for i,x in enumerate(cr["records"])]
 e+=p52.validate_schema_records(combined)+p52.validate_semantics(semantic_view(combined),p52.load_registries())
 lv=f.ingestion_validator("normalization-lineage.schema.json")
 for i,line in enumerate(ra["lineage"]):
  e+=serr(lv,line,f"Lineage[{i}]"); d=lineage_digest(norm,line)
  if line.get("lineage_digest")!=d or line.get("lineage_id")!=f"atlas:normalization-lineage:atlas.ingestion:{d}":e.append("lineage digest/id mismatch")
 return e

def main():
 e=validate_repository()
 if e:
  print("Phase 5.3.2 ATT&CK canary validation FAILED"); [print("- "+x) for x in e]; return 1
 print(f"Phase 5.3.2 ATT&CK canary validation PASSED: Enterprise {VERSION} @ {COMMIT}"); return 0
if __name__=="__main__":raise SystemExit(main())
