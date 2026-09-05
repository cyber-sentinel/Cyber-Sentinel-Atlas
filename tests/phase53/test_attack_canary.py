from __future__ import annotations
import copy, importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def mod(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);assert s.loader;s.loader.exec_module(m);return m
iv=mod("acv",ROOT/"tools/ingestion/validate_attack_canary.py"); p=mod("acp",ROOT/"ingestion/parsers/mitre_attack_stix.py"); n=mod("acn",ROOT/"ingestion/normalizers/mitre_attack.py"); f=mod("acf",ROOT/"tools/ingestion/validate_ingestion_foundation.py"); p52=mod("ac52",ROOT/"tools/validate_phase52.py")
class AttackCanaryTests(unittest.TestCase):
 @classmethod
 def setUpClass(c):
  c.fix=json.loads((ROOT/"fixtures/phase-5.3/attack-canary-stix.json").read_text()); c.map=json.loads((ROOT/"ingestion/mappings/mitre-attack-enterprise-v1.json").read_text()); c.rel=json.loads((ROOT/"ingestion/source-profiles/mitre-attack-enterprise.release.json").read_text()); c.con=json.loads((ROOT/"ingestion/connectors/mitre-attack-enterprise.json").read_text()); c.src=json.loads((ROOT/"ingestion/source-profiles/mitre-attack-enterprise.source.json").read_text())
 def parse(self,b=None,s=iv.SNAPSHOT):return p.parse_bundle(copy.deepcopy(b or self.fix),source_id=iv.SOURCE_ID,source_snapshot_id=s)
 def tech(self):return next(x for x in self.parse() if x["native_type"]=="attack-pattern")
 def norm(self,psr=None,m=None):return n.normalize_psr(psr or self.parse(),mapping_profile=copy.deepcopy(m or self.map),source_version=iv.VERSION,retrieved_at=iv.RETRIEVED)
 def test_01_repository_validator(self):self.assertEqual([],iv.validate_repository(ROOT))
 def test_02_release_pins(self):self.assertEqual([],iv.pin_errors(self.rel,self.con))
 def test_03_source_authority_license(self):self.assertEqual(("tier-a-authoritative","official","verified","allowed"),(self.src["source_class"],self.src["official_status"],self.src["license"]["status"],self.src["redistribution"]["policy"]))
 def test_04_no_floating_production_url(self):self.assertIn(iv.COMMIT,self.rel["bundle_url"]);self.assertNotIn("/master/",self.rel["bundle_url"]);self.assertTrue(self.rel["index"]["discovery_only"])
 def test_05_bundle_bound_fits_connector(self):self.assertGreaterEqual(self.con["security_policy"]["max_response_bytes"],iv.SIZE);self.assertEqual(0,self.con["security_policy"]["redirect_limit"])
 def test_06_fixture_small_prose_free(self):
  self.assertLess((ROOT/"fixtures/phase-5.3/attack-canary-stix.json").stat().st_size,32768);self.assertNotIn("description",next(x for x in self.fix["objects"] if x["type"]=="attack-pattern"))
 def test_07_parser_replay(self):
  a,b=self.parse(),self.parse();self.assertEqual(a,b);self.assertEqual(p.representation_digest(a),p.representation_digest(b))
 def test_08_parser_snapshot_identity_binding(self):self.assertNotEqual(self.parse(s="atlas:raw-snapshot:atlas.ingestion:a")[0]["parsed_record_id"],self.parse(s="atlas:raw-snapshot:atlas.ingestion:b")[0]["parsed_record_id"])
 def test_09_duplicate_stix_rejected(self):
  b=copy.deepcopy(self.fix);b["objects"].append(copy.deepcopy(b["objects"][1]));self.assertRaises(ValueError,self.parse,b)
 def test_10_conflicting_attack_ids_rejected(self):
  b=copy.deepcopy(self.fix);b["objects"][1]["external_references"].append({"source_name":"mitre-attack","external_id":"T9999"});self.assertRaises(ValueError,self.parse,b)
 def test_11_unknown_preserved_reported(self):
  t=self.tech();self.assertEqual("preserve-me",t["unknown_fields"]["x_mitre_future_field"]);self.assertTrue(t["diagnostics"])
 def test_12_psr_schema(self):self.assertTrue(all(f.ingestion_validator("parsed-source-record.schema.json").is_valid(x) for x in self.parse()))
 def test_13_mapping_digest(self):self.assertEqual(self.map["profile_digest"],n.mapping_profile_digest(self.map))
 def test_14_mapping_tamper_rejected(self):
  m=copy.deepcopy(self.map);m["domain"]="tampered";self.assertRaises(ValueError,self.norm,None,m)
 def test_15_source_mismatch_rejected(self):
  x=self.parse();x[0]["source_id"]="atlas:source:atlas.source:other";self.assertRaises(ValueError,self.norm,x)
 def test_16_t1059_identity(self):
  e=next(x for x in self.norm()["records"] if x["record_kind"]=="entity");self.assertEqual("atlas:attack-technique:mitre.attack:t1059.001",e["id"]);self.assertEqual("T1059.001",e["native_identifiers"][0]["value"])
 def test_17_current_lifecycle(self):self.assertEqual("current",next(x for x in self.norm()["records"] if x["record_kind"]=="entity")["lifecycle"]["state"])
 def test_18_revoked_retired(self):
  x=[self.tech()];x[0]["native_fields"]["revoked"]=True;self.assertEqual("retired",next(y for y in self.norm(x)["records"] if y["record_kind"]=="entity")["lifecycle"]["state"])
 def test_19_deprecated(self):
  x=[self.tech()];x[0]["native_fields"]["x_mitre_deprecated"]=True;self.assertEqual("deprecated",next(y for y in self.norm(x)["records"] if y["record_kind"]=="entity")["lifecycle"]["state"])
 def test_20_missing_flag_not_removal(self):
  x=[self.tech()];x[0]["native_fields"].pop("revoked");r=self.norm(x);self.assertNotIn("lifecycle",next(y for y in r["records"] if y["record_kind"]=="entity"));self.assertTrue(any("not inferred" in z for z in r["diagnostics"]))
 def test_21_missing_id_quarantine(self):
  x=[self.tech()];x[0]["native_identifiers"]=[z for z in x[0]["native_identifiers"] if z["type"]!="attack_id"];r=self.norm(x);self.assertEqual(1,r["identity_outcomes"]["AMBIGUOUS"]);self.assertEqual([],r["records"])
 def test_22_normalizer_replay(self):self.assertEqual(self.norm(),self.norm())
 def test_23_fixture_makes_no_description_claim(self):self.assertFalse(any(x["record_kind"]=="claim" for x in self.norm()["records"]))
 def test_24_synthetic_claim_provenance(self):
  x=[self.tech()];x[0]["native_fields"]["description"]="Synthetic test description.";c=next(y for y in self.norm(x)["records"] if y["record_kind"]=="claim");self.assertEqual("high",c["confidence"]);self.assertEqual("unreviewed",c["evidence"][0]["reviewer_status"]);self.assertEqual(iv.SNAPSHOT,c["evidence"][0]["source_snapshot_id"])
 def test_25_canonical_schema_and_claim_identity(self):
  x=[self.tech()];x[0]["native_fields"]["description"]="Synthetic test description.";r=self.norm(x);self.assertTrue(all(p52.root_validator().is_valid(y) for y in r["records"]));c=next(y for y in r["records"] if y["record_kind"]=="claim");self.assertEqual(p52.sha_key(p52.claim_semantic_payload(c)),c["canonical_key"])
 def test_26_lineage(self):
  v=f.ingestion_validator("normalization-lineage.schema.json")
  for x in self.norm()["lineage"]:self.assertTrue(v.is_valid(x));d=iv.lineage_digest(n,x);self.assertEqual(d,x["lineage_digest"]);self.assertEqual(f"atlas:normalization-lineage:atlas.ingestion:{d}",x["lineage_id"])
 def test_27_core_no_network_ai(self):self.assertEqual([],iv.security_errors())
 def test_28_subtechnique_native_component(self):self.assertIs(True,next(x for x in self.norm()["records"] if x["record_kind"]=="entity")["native_identifiers"][0]["components"]["is_subtechnique"])
if __name__=="__main__":unittest.main()
