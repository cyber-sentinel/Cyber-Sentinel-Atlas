from __future__ import annotations
import copy, importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def mod(name,path): s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
f=mod("t534f",ROOT/"tools/ingestion/validate_ingestion_foundation.py"); p52=mod("t53452",ROOT/"tools/validate_phase52.py"); d3p=mod("t534d3p",ROOT/"ingestion/parsers/mitre_d3fend_turtle.py"); d3n=mod("t534d3n",ROOT/"ingestion/normalizers/mitre_d3fend.py"); carp=mod("t534carp",ROOT/"ingestion/parsers/mitre_car_yaml.py"); carn=mod("t534carn",ROOT/"ingestion/normalizers/mitre_car.py"); dop=mod("t534dop",ROOT/"ingestion/parsers/defenseops_export.py"); don=mod("t534don",ROOT/"ingestion/normalizers/defenseops_export.py"); promo=mod("t534promo",ROOT/"tools/ingestion/phase534_promotion.py"); livecar=mod("t534lc",ROOT/"tools/ingestion/run_car_live_canary.py"); val=mod("t534v",ROOT/"tools/ingestion/validate_phase534.py")
def load(path): return json.loads((ROOT/path).read_text())
class Phase534Tests(unittest.TestCase):
    def setUp(self):
        self.d3rel=load("ingestion/source-profiles/mitre-d3fend-ontology.release.json"); self.d3map=load("ingestion/mappings/mitre-d3fend-v1.json"); self.carmap=load("ingestion/mappings/mitre-car-v1.json"); self.domap=load("ingestion/mappings/defenseops-export-v1.json"); self.do=load("fixtures/phase-5.3/defenseops-export.synthetic.json")
    def test_01_repository_validator(self): self.assertEqual([],val.validate_repository())
    def test_02_license_boundaries(self):
        self.assertEqual("verified",load("ingestion/source-profiles/mitre-d3fend-ontology.source.json")["license"]["status"]); self.assertEqual("verified",load("ingestion/source-profiles/mitre-car.source.json")["license"]["status"]); self.assertEqual("unknown",load("ingestion/source-profiles/cyber-sentinel-defenseops.source.json")["license"]["status"])
    def test_03_d3_pins(self): self.assertEqual("1.6.0",self.d3rel["ontology_version"]); self.assertRegex(self.d3rel["distribution_sha256"],r"^sha256-[a-f0-9]{64}$")
    def test_04_car_commit_pin(self): self.assertIn(load("ingestion/source-profiles/mitre-car.release.json")["upstream_commit_sha"],load("ingestion/connectors/mitre-car-sample.json")["targets"][0]["resource_uri"])
    def test_05_d3_parser_replay_and_unknown(self):
        raw=(ROOT/"fixtures/phase-5.3/d3fend-ontology.synthetic.ttl").read_bytes(); a=d3p.parse_bytes(raw,source_id=self.d3rel["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:d3synthetic"); b=d3p.parse_bytes(raw,source_id=self.d3rel["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:d3synthetic"); self.assertEqual(a,b); self.assertTrue(any(x["unknown_fields"] for x in a))
    def test_06_d3_digest_mismatch_fails(self):
        raw=(ROOT/"fixtures/phase-5.3/d3fend-ontology.synthetic.ttl").read_bytes(); self.assertRaises(ValueError,d3p.parse_bytes,raw,source_id=self.d3rel["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:d3synthetic",expected_sha256="sha256-"+"0"*64)
    def test_07_d3_psr_schema(self):
        raw=(ROOT/"fixtures/phase-5.3/d3fend-ontology.synthetic.ttl").read_bytes(); rows=d3p.parse_bytes(raw,source_id=self.d3rel["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:d3synthetic"); v=f.ingestion_validator("parsed-source-record.schema.json"); self.assertTrue(all(v.is_valid(x) for x in rows))
    def test_08_car_parser_unknown_and_schema(self):
        raw=(ROOT/"fixtures/phase-5.3/mitre-car.synthetic.yaml").read_bytes(); rows=carp.parse_bytes(raw,source_id="atlas:source:atlas.source:mitre-car",source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:carsynthetic"); self.assertEqual("preserve-me",rows[0]["unknown_fields"]["future_field"]); self.assertTrue(f.ingestion_validator("parsed-source-record.schema.json").is_valid(rows[0]))
    def test_09_defenseops_export_schema_digest(self): self.assertTrue(f.ingestion_validator("extensions/defenseops-export.schema.json").is_valid(self.do)); self.assertEqual(self.do["export_digest"],dop.export_digest(self.do))
    def test_10_defenseops_tamper_fails(self):
        x=copy.deepcopy(self.do); x["records"][0]["native_backend"]="tampered"; self.assertRaises(ValueError,dop.parse_bytes,json.dumps(x).encode(),source_id=x["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:dosynthetic",expected_commit_sha=x["commit_sha"])
    def test_11_mapping_digests(self): self.assertEqual(self.d3map["profile_digest"],d3n.mapping_profile_digest(self.d3map)); self.assertEqual(self.carmap["profile_digest"],carn.mapping_profile_digest(self.carmap)); self.assertEqual(self.domap["profile_digest"],don.mapping_profile_digest(self.domap))
    def test_12_d3_canonical_and_claim_evidence(self):
        raw=(ROOT/"fixtures/phase-5.3/d3fend-ontology.synthetic.ttl").read_bytes(); psr=d3p.parse_bytes(raw,source_id=self.d3rel["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:d3synthetic"); r=d3n.normalize_psr(psr,mapping_profile=self.d3map,source_version="1.6.0",retrieved_at="2026-09-05T16:00:00Z"); self.assertTrue(all(p52.root_validator().is_valid(x) for x in r["records"])); claim=next(x for x in r["records"] if x["record_kind"]=="claim"); self.assertEqual("high",claim["confidence"]); self.assertIn("other",claim["evidence"][0]["locator"])
    def test_13_car_canonical_claim(self):
        psr=carp.parse_bytes((ROOT/"fixtures/phase-5.3/mitre-car.synthetic.yaml").read_bytes(),source_id="atlas:source:atlas.source:mitre-car",source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:carsynthetic"); r=carn.normalize_psr(psr,mapping_profile=self.carmap,source_version=self.carmap["source_version"],retrieved_at="2026-09-05T16:00:00Z"); self.assertTrue(all(p52.root_validator().is_valid(x) for x in r["records"])); self.assertTrue(any(x["record_kind"]=="claim" for x in r["records"]))
    def test_14_lineage_schemas(self):
        psr=carp.parse_bytes((ROOT/"fixtures/phase-5.3/mitre-car.synthetic.yaml").read_bytes(),source_id="atlas:source:atlas.source:mitre-car",source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:carsynthetic"); r=carn.normalize_psr(psr,mapping_profile=self.carmap,source_version=self.carmap["source_version"],retrieved_at="2026-09-05T16:00:00Z"); v=f.ingestion_validator("normalization-lineage.schema.json"); self.assertTrue(all(v.is_valid(x) for x in r["lineage"]))
    def test_15_defenseops_g14_blocker(self):
        psr=dop.parse_bytes(json.dumps(self.do).encode(),source_id=self.do["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:dosynthetic",expected_commit_sha=self.do["commit_sha"]); r=don.normalize_psr(psr,mapping_profile=self.domap,source_version=self.domap["source_version"],retrieved_at="2026-09-05T16:00:00Z"); self.assertTrue(any("G14" in x for x in r["promotion_blockers"])); self.assertTrue(all(p52.root_validator().is_valid(x) for x in r["records"]))
    def test_16_verified_license_removes_item_g14_blocker(self):
        x=copy.deepcopy(self.do); x["records"][0]["license"]={"status":"verified","identifier":"Synthetic-License"}; x["export_digest"]=dop.export_digest(x); psr=dop.parse_bytes(json.dumps(x).encode(),source_id=x["source_id"],source_snapshot_id="atlas:raw-snapshot:atlas.ingestion:dosynthetic",expected_commit_sha=x["commit_sha"]); r=don.normalize_psr(psr,mapping_profile=self.domap,source_version=self.domap["source_version"],retrieved_at="2026-09-05T16:00:00Z"); self.assertFalse(any("G14" in y for y in r["promotion_blockers"]))
    def test_17_promotion_fixture_reproducible(self): self.assertEqual(load("fixtures/phase-5.3/phase534-promotion-scenarios.json"),promo.scenarios())
    def test_18_promotion_schemas(self):
        for s in promo.scenarios().values(): self.assertTrue(f.ingestion_validator("review-decision.schema.json").is_valid(s["review"])); self.assertTrue(f.ingestion_validator("build-validation-report.schema.json").is_valid(s["report"])); self.assertTrue(f.ingestion_validator("canonical-build-manifest.schema.json").is_valid(s["manifest"]))
    def test_19_pack_ready_requires_all_gates_and_four_eyes(self):
        s=promo.scenarios()["pack_ready_success"]; self.assertEqual("PACK_READY",s["manifest"]["state"]); self.assertTrue(s["manifest"]["pack_ready"]); self.assertEqual(2,len(promo.qualifying_approvals(s["review"]))); self.assertTrue(all(g["result"]=="pass" for g in s["report"]["gates"]))
    def test_20_g14_nonwaivable_and_lkg(self):
        s=promo.scenarios()["defenseops_g14_block"]; self.assertEqual("fail",next(g for g in s["report"]["gates"] if g["gate"]=="G14")["result"]); self.assertFalse(s["manifest"]["pack_ready"]); self.assertTrue(s["manifest"]["last_known_good_preserved"])
    def test_21_stale_review_binding_prevents_promotion(self):
        s=promo.scenarios()["pack_ready_success"]; review=copy.deepcopy(s["review"]); review["candidate_corpus_digest"]="sha256-"+"9"*64; review["review_digest"]=promo.digest_without(review,"review_digest"); m=promo.make_manifest(build_id=s["manifest"]["build_id"],candidate_digest=s["manifest"]["candidate_corpus_digest"],diff_id=s["manifest"]["inventory_diff_id"],diff_digest=s["manifest"]["inventory_diff_digest"],review=review,report=s["report"],source_id=s["manifest"]["source_ids"][0],previous_lkg=s["manifest"]["previous_last_known_good_build_id"]); self.assertEqual("REJECTED",m["state"])
    def test_22_car_git_blob_helper(self): self.assertEqual("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",livecar.git_blob_sha1(b""))
if __name__=="__main__": unittest.main()
