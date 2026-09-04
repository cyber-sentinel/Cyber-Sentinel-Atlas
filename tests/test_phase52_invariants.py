from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import copy
import json
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import validate_phase52 as m  # noqa: E402


class Phase52InvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = m.load_fixture_records()
        cls.regs = m.load_registries()
        cls.by_id = {record["id"]: record for _, record in cls.records}

    def mutated(self, predicate):
        records = copy.deepcopy(self.records)
        for index, (path, record) in enumerate(records):
            if predicate(record):
                return records, index, record
        self.fail("fixture record not found")

    def errors(self, records):
        return m.validate_semantics(records, self.regs)

    def rehash_relationship(self, record):
        record["canonical_key"] = m.sha_key(m.relationship_semantic_payload(record))
        record["id"] = f"atlas:relationship:atlas.graph:{record['canonical_key']}"

    def rehash_claim(self, record):
        record["canonical_key"] = m.sha_key(m.claim_semantic_payload(record))
        record["id"] = f"atlas:claim:atlas.claim:{record['canonical_key']}"

    def first_id(self, kind=None, entity_type=None):
        for _, record in self.records:
            if ((kind is None or record["record_kind"] == kind) and
                    (entity_type is None or record.get("entity_type") == entity_type)):
                return record["id"]
        self.fail(f"missing fixture {kind=} {entity_type=}")

    def test_platform_ids_reject_claim(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record["applicability"] = {"platform_ids": [self.first_id("claim")]}
        self.assertTrue(any("applicability.platform_ids" in e for e in self.errors(records)))

    def test_product_ids_reject_wrong_entity_type(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record["applicability"] = {"product_ids": [self.first_id("entity", "platform")]}
        self.assertTrue(any("applicability.product_ids" in e for e in self.errors(records)))

    def test_provider_ids_reject_non_provider(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record["applicability"] = {"provider_ids": [self.first_id("entity", "product")]}
        self.assertTrue(any("applicability.provider_ids" in e for e in self.errors(records)))

    def test_version_ids_require_version_record(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record["applicability"] = {"version_ids": [self.first_id("entity", "platform")]}
        self.assertTrue(any("applicability.version_ids" in e for e in self.errors(records)))

    def test_explanatory_claim_ids_require_claim(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record["applicability"] = {"explanatory_claim_ids": [self.first_id("source")]}
        self.assertTrue(any("applicability.explanatory_claim_ids" in e for e in self.errors(records)))

    def test_lifecycle_reason_claim_ids_require_claim(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record["lifecycle"]["reason_claim_ids"] = [self.first_id("source")]
        self.assertTrue(any("lifecycle.reason_claim_ids" in e for e in self.errors(records)))

    def test_alias_provider_scope_requires_telemetry_provider(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record.setdefault("aliases", []).append({"value":"scoped","kind":"common","case_sensitive":False,"scope":{"provider_id":self.first_id("entity","product")}})
        self.assertTrue(any("alias.scope.provider_id" in e for e in self.errors(records)))

    def test_claim_entity_ref_requires_entity(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "claim")
        record["object"] = {"kind":"entity-ref","entity_id":self.first_id("source")}
        self.rehash_claim(record)
        self.assertTrue(any("claim.object.entity_id" in e for e in self.errors(records)))

    def test_version_subject_rejects_claim_family(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "version")
        record["subject_id"] = self.first_id("claim")
        self.assertTrue(any("version.subject_id" in e for e in self.errors(records)))

    def test_coverage_scope_subjects_require_entities(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "coverage-snapshot")
        record["scope"]["subject_ids"] = [self.first_id("source")]
        self.assertTrue(any("coverage.scope.subject_ids" in e for e in self.errors(records)))

    def test_version_constraint_subject_requires_versionable_entity(self):
        records, _, record = self.mutated(lambda x: x.get("entity_type") == "event")
        record["applicability"] = {"version_constraints":[{"subject_id":self.first_id("entity","event"),"version_scheme":"build","expression":">=1"}]}
        self.assertTrue(any("version_constraint.subject_id" in e for e in self.errors(records)))

    def test_evidence_source_requires_source_record(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "claim")
        record["evidence"][0]["source_id"] = self.first_id("claim")
        self.assertTrue(any("evidence.source_id" in e for e in self.errors(records)))

    def test_supporting_claim_ids_require_claim(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "relationship")
        record["relationship_type"] = "RELATED_TO"
        record["supporting_claim_ids"] = [self.first_id("source")]
        self.rehash_relationship(record)
        self.assertTrue(any("relationship.supporting_claim_ids" in e for e in self.errors(records)))

    def test_has_telemetry_provider_endpoint_types(self):
        records, _, record = self.mutated(lambda x: x.get("relationship_type") == "HAS_TELEMETRY_PROVIDER")
        record["from"] = self.first_id("entity","event")
        self.rehash_relationship(record)
        self.assertTrue(any("relationship.from" in e and "product" in e for e in self.errors(records)))

    def test_has_telemetry_source_endpoint_types(self):
        records, _, record = self.mutated(lambda x: x.get("relationship_type") == "HAS_TELEMETRY_SOURCE")
        record["from"] = self.first_id("entity","product")
        self.rehash_relationship(record)
        self.assertTrue(any("relationship.from" in e and "telemetry-provider" in e for e in self.errors(records)))

    def test_emits_destination_is_telemetry_record(self):
        records, _, record = self.mutated(lambda x: x.get("relationship_type") == "EMITS")
        record["to"] = self.first_id("entity","field")
        self.rehash_relationship(record)
        self.assertTrue(any("relationship.to" in e for e in self.errors(records)))

    def test_has_field_destination_is_field(self):
        records, _, record = self.mutated(lambda x: x.get("relationship_type") == "HAS_FIELD")
        record["to"] = self.first_id("entity","event")
        self.rehash_relationship(record)
        self.assertTrue(any("relationship.to" in e and "field" in e for e in self.errors(records)))

    def test_runs_on_rejects_non_entity_endpoint(self):
        records, _, record = self.mutated(lambda x: x.get("relationship_type") == "RUNS_ON")
        record["to"] = self.first_id("source")
        self.rehash_relationship(record)
        self.assertTrue(any("relationship.to" in e and "entity record" in e.lower() for e in self.errors(records)))

    def _sequence_without_support_fails(self, relationship_type):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "relationship")
        record["relationship_type"] = relationship_type
        record.pop("supporting_claim_ids", None)
        self.rehash_relationship(record)
        return any(relationship_type in e and "supporting_claim_ids" in e for e in self.errors(records))

    def test_precedes_without_support_fails(self):
        self.assertTrue(self._sequence_without_support_fails("PRECEDES"))

    def test_follows_without_support_fails(self):
        self.assertTrue(self._sequence_without_support_fails("FOLLOWS"))

    def test_unregistered_extension_rejected_on_non_entity_families(self):
        for kind in ("claim","source","coverage-snapshot"):
            records, _, record = self.mutated(lambda x, expected=kind: x["record_kind"] == expected)
            record.setdefault("extensions", []).append({"namespace":"not.registered","schema_version":"1.0.0","data":{}})
            self.assertTrue(any("unregistered extension namespace" in e for e in self.errors(records)), kind)

    def test_duplicate_extension_identity_rejected(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "claim")
        record["extensions"] = [{"namespace":"atlas.schema","schema_version":"1.0.0","data":{"a":1}},{"namespace":"atlas.schema","schema_version":"1.0.0","data":{"b":2}}]
        self.assertTrue(any("duplicate extension identity" in e for e in self.errors(records)))

    def test_coverage_numerator_basis_matches_state(self):
        coverage = next(r for _, r in self.records if r["record_kind"] == "coverage-snapshot")
        self.assertEqual("validated", coverage["numerator_basis"])
        self.assertEqual(coverage["numerator_count"], coverage["state_counts"][coverage["numerator_basis"]])
        self.assertNotIn("coverage_percent", coverage)

    def test_coverage_numerator_mismatch_rejected(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "coverage-snapshot")
        record["numerator_count"] = record["state_counts"][record["numerator_basis"]] - 1
        self.assertTrue(any("numerator_count must equal" in e for e in self.errors(records)))

    def test_overlapping_alias_scope_collision_rejected(self):
        records = copy.deepcopy(self.records)
        entities = [r for _, r in records if r["record_kind"] == "entity"][:2]
        for record in entities:
            record.setdefault("aliases", []).append({"value":"collision","kind":"common","case_sensitive":False,"scope":{"namespace":"microsoft.windows.security"}})
        self.assertTrue(any("ambiguous alias overlapping scope" in e for e in self.errors(records)))

    def test_disjoint_alias_namespace_reuse_allowed(self):
        records = copy.deepcopy(self.records)
        entities = [r for _, r in records if r["record_kind"] == "entity"][:2]
        entities[0].setdefault("aliases", []).append({"value":"shared","kind":"common","case_sensitive":False,"scope":{"namespace":"microsoft.windows.security"}})
        entities[1].setdefault("aliases", []).append({"value":"shared","kind":"common","case_sensitive":False,"scope":{"namespace":"microsoft.sysmon"}})
        self.assertFalse(any("ambiguous alias overlapping scope: 'shared'" in e for e in self.errors(records)))

    def test_duplicate_native_identifier_rejected(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "entity" and x.get("native_identifiers"))
        record["native_identifiers"].append(copy.deepcopy(record["native_identifiers"][0]))
        self.assertTrue(any("duplicate native identifier semantic tuple" in e for e in self.errors(records)))

    def test_native_identifiers_require_primary(self):
        records, _, record = self.mutated(lambda x: x["record_kind"] == "entity" and x.get("native_identifiers"))
        for native in record["native_identifiers"]:
            native["primary"] = False
        self.assertTrue(any("primary=true" in e for e in self.errors(records)))

    def test_authoritative_claim_tier_a_approved_passes(self):
        claim = next(r for _, r in self.records if r["record_kind"] == "claim" and r.get("confidence") == "authoritative")
        by_id = {r["id"]:(p,r) for p,r in self.records}
        self.assertTrue(m.authoritative_claim_ok(claim, by_id))

    def test_authoritative_claim_tier_c_only_rejected(self):
        records, _, source = self.mutated(lambda x: x["record_kind"] == "source" and x.get("source_class") == "tier-a-authoritative")
        source["source_class"] = "tier-c-secondary-research"
        self.assertTrue(any("authoritative claim requires" in e for e in self.errors(records)))

    def test_https_source_url_passes(self):
        source = next(r for _, r in self.records if r["record_kind"] == "source")
        errors=[]
        m.validate_source_urls(source, errors)
        self.assertEqual([], errors)

    def test_non_https_source_urls_rejected(self):
        for url in ("http://example.invalid/x","file:///tmp/x","ftp://example.invalid/x","data:text/plain,x","javascript:alert(1)"):
            source = copy.deepcopy(next(r for _, r in self.records if r["record_kind"] == "source"))
            source["canonical_urls"]=[url]
            errors=[]
            m.validate_source_urls(source,errors)
            self.assertTrue(errors,url)

    def test_signed_or_tokenized_https_source_url_rejected(self):
        for url in ("https://example.invalid/x?token=secret","https://example.invalid/x?X-Amz-Signature=abc"):
            source = copy.deepcopy(next(r for _, r in self.records if r["record_kind"] == "source"))
            source["canonical_urls"]=[url]
            errors=[]
            m.validate_source_urls(source,errors)
            self.assertTrue(errors,url)

    def test_datetime_order_uses_offset_aware_semantics(self):
        record = copy.deepcopy(next(r for _, r in self.records if r["record_kind"] == "entity"))
        record["created_at"]="2026-09-04T10:00:00+02:00"
        record["updated_at"]="2026-09-04T09:30:00+00:00"
        self.assertLess(record["updated_at"],record["created_at"])
        errors=[]
        m.validate_time(record,errors)
        self.assertEqual([],errors)

    def test_invalid_registry_version_rejected(self):
        with TemporaryDirectory() as temp:
            directory=Path(temp)
            for path in m.REGISTRY_DIR.glob("*.json"):
                shutil.copy2(path,directory/path.name)
            target=directory/"entity-types.json"
            data=json.loads(target.read_text())
            data["registry_version"]="v1"
            target.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"invalid registry_version"):
                m.load_registries(directory)

    def test_duplicate_registry_identity_rejected(self):
        with TemporaryDirectory() as temp:
            directory=Path(temp)
            for path in m.REGISTRY_DIR.glob("*.json"):
                shutil.copy2(path,directory/path.name)
            data=json.loads((directory/"entity-types.json").read_text())
            (directory/"zzz-duplicate.json").write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"duplicate registry identity"):
                m.load_registries(directory)

    def test_registry_versions_are_independent_of_schema_version(self):
        with TemporaryDirectory() as temp:
            directory=Path(temp)
            for path in m.REGISTRY_DIR.glob("*.json"):
                data=json.loads(path.read_text())
                if data["registry"]=="alias-kinds":
                    data["registry_version"]="1.1.0"
                (directory/path.name).write_text(json.dumps(data))
            self.assertIn("alias-kinds",m.load_registries(directory))

    def test_schema_uri_base_is_repository_controlled(self):
        self.assertEqual("https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/",m.SCHEMA_URI_BASE)
        errors=[]
        m.validate_schema_uri_policy(errors)
        self.assertEqual([],errors)

    def test_full_fixture_corpus_satisfies_permanent_invariants(self):
        self.assertEqual([],self.errors(self.records))


if __name__ == "__main__":
    unittest.main(verbosity=2)
