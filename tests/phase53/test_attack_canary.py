from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


iv = mod("acv", ROOT / "tools/ingestion/validate_attack_canary.py")
p = mod("acp", ROOT / "ingestion/parsers/mitre_attack_stix.py")
n = mod("acn", ROOT / "ingestion/normalizers/mitre_attack.py")
f = mod("acf", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
p52 = mod("ac52", ROOT / "tools/validate_phase52.py")
live = mod("acl", ROOT / "tools/ingestion/run_attack_live_canary.py")


class AttackCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fix = json.loads((ROOT / "fixtures/phase-5.3/attack-canary-stix.json").read_text())
        cls.map = json.loads((ROOT / "ingestion/mappings/mitre-attack-enterprise-v1.json").read_text())
        cls.rel = json.loads((ROOT / "ingestion/source-profiles/mitre-attack-enterprise.release.json").read_text())
        cls.con = json.loads((ROOT / "ingestion/connectors/mitre-attack-enterprise.json").read_text())
        cls.src = json.loads((ROOT / "ingestion/source-profiles/mitre-attack-enterprise.source.json").read_text())

    def parse(self, bundle=None, snapshot_id=iv.SNAPSHOT):
        return p.parse_bundle(
            copy.deepcopy(bundle or self.fix),
            source_id=iv.SOURCE_ID,
            source_snapshot_id=snapshot_id,
        )

    def tech(self):
        return next(record for record in self.parse() if record["native_type"] == "attack-pattern")

    def norm(self, psr=None, mapping=None):
        return n.normalize_psr(
            psr or self.parse(),
            mapping_profile=copy.deepcopy(mapping or self.map),
            source_version=iv.VERSION,
            retrieved_at=iv.RETRIEVED,
        )

    def test_01_repository_validator(self):
        self.assertEqual([], iv.validate_repository(ROOT))

    def test_02_release_pins(self):
        self.assertEqual([], iv.pin_errors(self.rel, self.con))

    def test_03_source_authority_license(self):
        self.assertEqual(
            ("tier-a-authoritative", "official", "verified", "allowed"),
            (
                self.src["source_class"],
                self.src["official_status"],
                self.src["license"]["status"],
                self.src["redistribution"]["policy"],
            ),
        )

    def test_04_no_floating_production_url(self):
        self.assertIn(iv.COMMIT, self.rel["bundle_url"])
        self.assertNotIn("/master/", self.rel["bundle_url"])
        self.assertTrue(self.rel["index"]["discovery_only"])

    def test_05_bundle_bound_fits_connector(self):
        self.assertGreaterEqual(self.con["security_policy"]["max_response_bytes"], iv.SIZE)
        self.assertEqual(0, self.con["security_policy"]["redirect_limit"])

    def test_06_fixture_small_prose_free(self):
        self.assertLess((ROOT / "fixtures/phase-5.3/attack-canary-stix.json").stat().st_size, 32768)
        self.assertNotIn(
            "description",
            next(record for record in self.fix["objects"] if record["type"] == "attack-pattern"),
        )

    def test_07_parser_replay(self):
        first, second = self.parse(), self.parse()
        self.assertEqual(first, second)
        self.assertEqual(p.representation_digest(first), p.representation_digest(second))

    def test_08_parser_snapshot_identity_binding(self):
        self.assertNotEqual(
            self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:a")[0]["parsed_record_id"],
            self.parse(snapshot_id="atlas:raw-snapshot:atlas.ingestion:b")[0]["parsed_record_id"],
        )

    def test_09_duplicate_stix_rejected(self):
        bundle = copy.deepcopy(self.fix)
        bundle["objects"].append(copy.deepcopy(bundle["objects"][1]))
        self.assertRaises(ValueError, self.parse, bundle)

    def test_10_conflicting_attack_ids_rejected(self):
        bundle = copy.deepcopy(self.fix)
        bundle["objects"][1]["external_references"].append(
            {"source_name": "mitre-attack", "external_id": "T9999"}
        )
        self.assertRaises(ValueError, self.parse, bundle)

    def test_11_unknown_preserved_reported(self):
        technique = self.tech()
        self.assertEqual("preserve-me", technique["unknown_fields"]["x_mitre_future_field"])
        self.assertTrue(technique["diagnostics"])

    def test_12_psr_schema(self):
        validator = f.ingestion_validator("parsed-source-record.schema.json")
        self.assertTrue(all(validator.is_valid(record) for record in self.parse()))

    def test_13_mapping_digest(self):
        self.assertEqual(self.map["profile_digest"], n.mapping_profile_digest(self.map))

    def test_14_mapping_tamper_rejected(self):
        mapping = copy.deepcopy(self.map)
        mapping["domain"] = "tampered"
        self.assertRaises(ValueError, self.norm, None, mapping)

    def test_15_source_mismatch_rejected(self):
        records = self.parse()
        records[0]["source_id"] = "atlas:source:atlas.source:other"
        self.assertRaises(ValueError, self.norm, records)

    def test_16_t1059_identity(self):
        entity = next(record for record in self.norm()["records"] if record["record_kind"] == "entity")
        self.assertEqual("atlas:attack-technique:mitre.attack:t1059.001", entity["id"])
        self.assertEqual("T1059.001", entity["native_identifiers"][0]["value"])

    def test_17_current_lifecycle(self):
        entity = next(record for record in self.norm()["records"] if record["record_kind"] == "entity")
        self.assertEqual("current", entity["lifecycle"]["state"])

    def test_18_revoked_retired(self):
        records = [self.tech()]
        records[0]["native_fields"]["revoked"] = True
        entity = next(record for record in self.norm(records)["records"] if record["record_kind"] == "entity")
        self.assertEqual("retired", entity["lifecycle"]["state"])

    def test_19_deprecated(self):
        records = [self.tech()]
        records[0]["native_fields"]["x_mitre_deprecated"] = True
        entity = next(record for record in self.norm(records)["records"] if record["record_kind"] == "entity")
        self.assertEqual("deprecated", entity["lifecycle"]["state"])

    def test_20_missing_flag_not_removal(self):
        records = [self.tech()]
        records[0]["native_fields"].pop("revoked")
        result = self.norm(records)
        entity = next(record for record in result["records"] if record["record_kind"] == "entity")
        self.assertNotIn("lifecycle", entity)
        self.assertTrue(any("not inferred" in diagnostic for diagnostic in result["diagnostics"]))

    def test_21_missing_id_quarantine(self):
        records = [self.tech()]
        records[0]["native_identifiers"] = [
            item for item in records[0]["native_identifiers"] if item["type"] != "attack_id"
        ]
        result = self.norm(records)
        self.assertEqual(1, result["identity_outcomes"]["AMBIGUOUS"])
        self.assertEqual([], result["records"])

    def test_22_normalizer_replay(self):
        self.assertEqual(self.norm(), self.norm())

    def test_23_fixture_makes_no_description_claim(self):
        self.assertFalse(any(record["record_kind"] == "claim" for record in self.norm()["records"]))

    def test_24_synthetic_claim_provenance(self):
        records = [self.tech()]
        records[0]["native_fields"]["description"] = "Synthetic test description."
        claim = next(record for record in self.norm(records)["records"] if record["record_kind"] == "claim")
        self.assertEqual("high", claim["confidence"])
        self.assertEqual("unreviewed", claim["evidence"][0]["reviewer_status"])
        self.assertEqual(iv.SNAPSHOT, claim["evidence"][0]["source_snapshot_id"])

    def test_25_canonical_schema_and_claim_identity(self):
        records = [self.tech()]
        records[0]["native_fields"]["description"] = "Synthetic test description."
        result = self.norm(records)
        self.assertTrue(all(p52.root_validator().is_valid(record) for record in result["records"]))
        claim = next(record for record in result["records"] if record["record_kind"] == "claim")
        self.assertEqual(p52.sha_key(p52.claim_semantic_payload(claim)), claim["canonical_key"])

    def test_26_lineage(self):
        validator = f.ingestion_validator("normalization-lineage.schema.json")
        for lineage in self.norm()["lineage"]:
            self.assertTrue(validator.is_valid(lineage))
            digest = iv.lineage_digest(n, lineage)
            self.assertEqual(digest, lineage["lineage_digest"])
            self.assertEqual(
                f"atlas:normalization-lineage:atlas.ingestion:{digest}",
                lineage["lineage_id"],
            )

    def test_27_core_no_network_ai(self):
        self.assertEqual([], iv.security_errors())

    def test_28_subtechnique_native_component(self):
        entity = next(record for record in self.norm()["records"] if record["record_kind"] == "entity")
        self.assertIs(True, entity["native_identifiers"][0]["components"]["is_subtechnique"])

    def test_29_psr_record_digest_matches_phase531_contract(self):
        for record in self.parse():
            payload = {
                key: record.get(key)
                for key in (
                    "native_type",
                    "native_key",
                    "native_identifiers",
                    "native_fields",
                    "unknown_fields",
                    "locator",
                )
            }
            self.assertEqual(f.sha256_digest(payload), record["record_digest"])

    def test_30_psr_identity_matches_phase531_contract(self):
        records = self.parse()
        self.assertEqual([], iv.psr_contract_errors(f, records))
        for record in records:
            expected = f.stable_artifact_id(
                "parsed-source-record",
                {
                    "source_snapshot_id": record["source_snapshot_id"],
                    "parser_id": record["parser_id"],
                    "parser_version": record["parser_version"],
                    "psr_version": record["psr_version"],
                    "native_type": record["native_type"],
                    "native_key": record.get("native_key"),
                    "record_digest": record["record_digest"],
                },
            )
            self.assertEqual(expected, record["parsed_record_id"])

    def test_31_live_raw_snapshot_identity_matches_phase531_contract(self):
        digest = "sha256-" + "a" * 64
        run_id = "atlas:acquisition-run:atlas.ingestion:test-run"
        resource_key = "enterprise-attack/enterprise-attack-19.2.json"
        expected = f.stable_artifact_id(
            "raw-snapshot",
            {
                "acquisition_run_id": run_id,
                "target_key": "enterprise-bundle",
                "resource_key": resource_key,
                "raw_content_digest": digest,
            },
        )
        actual = live.raw_snapshot_id(
            f,
            acquisition_run_id=run_id,
            target_key="enterprise-bundle",
            resource_key=resource_key,
            raw_content_digest=digest,
        )
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
