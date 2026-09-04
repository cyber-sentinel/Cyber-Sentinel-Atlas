from __future__ import annotations

from pathlib import Path
import copy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import validate_phase52 as model  # noqa: E402

class Phase52CanonicalModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = model.load_fixture_records()
        cls.registries = model.load_registries()
        cls.validator = model.root_validator()
        cls.by_id = {r["id"]: r for _, r in cls.records}

    def assertSchemaValid(self, record):
        errors = list(self.validator.iter_errors(record))
        self.assertEqual([], errors, "\n".join(e.message for e in errors))

    def test_root_atlas_record_validates_all_record_families(self):
        kinds = {r["record_kind"] for _, r in self.records}
        self.assertEqual({"entity","claim","relationship","source","validation","version","coverage-snapshot"}, kinds)
        for _, record in self.records:
            self.assertSchemaValid(record)

    def test_registries_have_required_values(self):
        self.assertTrue({"event","audit-record","audit-action","operation","activity","finding","flow-record","telemetry-provider","telemetry-source","field","tool"}.issubset(self.registries["entity-types"]))
        self.assertTrue({"microsoft.windows.security","microsoft.sysmon","linux.audit","aws.cloudtrail.iam","microsoft.azure.activity","gcp.audit","kubernetes.audit","docker.events","mongodb.audit","mitre.attack"}.issubset(self.registries["namespaces"]))
        self.assertIn("HAS_TELEMETRY_PROVIDER", self.registries["relationship-types"])
        self.assertIn("HAS_TELEMETRY_SOURCE", self.registries["relationship-types"])

    def test_canonical_ids_match_record_components(self):
        errors=[]
        for _, record in self.records:
            model.validate_id_component_consistency(record, self.registries, errors)
        self.assertEqual([], errors)

    def test_claim_and_relationship_ids_are_deterministic(self):
        errors=[]
        for _, record in self.records:
            model.validate_deterministic_identity(record, errors)
        self.assertEqual([], errors)

    def test_claim_evidence_is_source_backed(self):
        claims=[r for _,r in self.records if r["record_kind"]=="claim"]
        self.assertGreaterEqual(len(claims), 3)
        for claim in claims:
            self.assertTrue(claim["evidence"])
            for evidence in claim["evidence"]:
                src=self.by_id[evidence["source_id"]]
                self.assertEqual("source", src["record_kind"])

    def test_claim_object_supports_entity_literal_and_json(self):
        kinds={r["object"]["kind"] for _,r in self.records if r["record_kind"]=="claim"}
        self.assertTrue({"entity-ref","literal","json"}.issubset(kinds))

    def test_referential_integrity_is_clean(self):
        errors=model.validate_semantics(self.records, self.registries)
        self.assertEqual([], [e for e in errors if "unresolved" in e])

    def test_broken_reference_fails(self):
        mutated=copy.deepcopy(self.records)
        _, rel=next((p,r) for p,r in mutated if r["record_kind"]=="relationship")
        rel["to"]="atlas:event:microsoft.windows.security:does-not-exist"
        errors=model.validate_semantics(mutated,self.registries)
        self.assertTrue(any("unresolved relationship.to" in e for e in errors))

    def test_semantic_relationship_requires_supporting_claim(self):
        base=next(r for _,r in self.records if r["record_kind"]=="relationship")
        rel=copy.deepcopy(base)
        rel["relationship_type"]="RELATED_TO"
        rel["canonical_key"]=model.sha_key(model.relationship_semantic_payload(rel))
        rel["id"]=f"atlas:relationship:atlas.graph:{rel['canonical_key']}"
        rel.pop("supporting_claim_ids",None)
        errors=model.validate_semantics(self.records+[(Path("<semantic-rel>"),rel)],self.registries)
        self.assertTrue(any("requires supporting_claim_ids" in e for e in errors))

    def test_lifecycle_and_curation_are_independent(self):
        entity=copy.deepcopy(self.by_id["atlas:event:microsoft.windows.security:4688"])
        entity["lifecycle"]["state"]="legacy"
        entity["curation_status"]="published"
        self.assertSchemaValid(entity)
        self.assertNotEqual(entity["lifecycle"]["state"], entity["curation_status"])

    def test_phase51_deprecated_status_is_not_auto_migrated(self):
        migration=model.load_json(model.MIGRATION_MAP)
        self.assertIs(migration["deprecated_status_auto_migration"], False)

    def test_applicability_supports_distinct_version_schemes(self):
        entity=copy.deepcopy(self.by_id["atlas:event:microsoft.windows.security:4688"])
        entity["applicability"]={"version_constraints":[{"subject_id":"atlas:technology:atlas.schema:canonical-data-model","version_scheme":"semver","expression":">=1.0.0"},{"subject_id":"atlas:platform:microsoft.windows:windows","version_scheme":"build","expression":">=19041"},{"subject_id":"atlas:product:microsoft.windows.security:windows-security","version_scheme":"vendor-native","expression":"supported"}]}
        self.assertSchemaValid(entity)

    def test_namespaced_extension_does_not_change_identity(self):
        entity=copy.deepcopy(self.by_id["atlas:operation:microsoft.azure.activity:microsoft.compute.virtualmachines.write"])
        original=entity["id"]
        entity["extensions"][0]["data"]["another_fixture_value"]="x"
        self.assertSchemaValid(entity)
        self.assertEqual(original, entity["id"])

    def test_vendor_specific_root_property_is_rejected(self):
        entity=copy.deepcopy(self.by_id["atlas:operation:aws.cloudtrail.iam:createaccesskey"])
        entity["aws_event_name"]="CreateAccessKey"
        self.assertTrue(list(self.validator.iter_errors(entity)))

    def test_native_identifier_case_fidelity(self):
        aws=self.by_id["atlas:operation:aws.cloudtrail.iam:createaccesskey"]
        self.assertEqual("CreateAccessKey",aws["native_identifiers"][0]["value"])
        self.assertTrue(aws["native_identifiers"][0]["case_sensitive"])
        gcp=self.by_id["atlas:operation:gcp.audit:google.iam.admin.v1.createserviceaccount"]
        self.assertEqual("google.iam.admin.v1.CreateServiceAccount",gcp["native_identifiers"][0]["value"])

    def test_alias_ambiguity_requires_scope(self):
        a=copy.deepcopy(self.by_id["atlas:event:microsoft.windows.security:4688"])
        b=copy.deepcopy(self.by_id["atlas:event:microsoft.sysmon:1"])
        a["aliases"].append({"value":"ambiguous-fixture","kind":"common","case_sensitive":False})
        b["aliases"].append({"value":"ambiguous-fixture","kind":"common","case_sensitive":False})
        errors=model.validate_semantics([(Path("<a>"),a),(Path("<b>"),b)],self.registries)
        self.assertTrue(any("ambiguous alias without scope" in e for e in errors))

    def test_exact_resolution_cases(self):
        self.assertEqual([], model.validate_exact_resolution(self.records))

    def test_bare_native_collision_is_not_canonical_collision(self):
        sysmon=copy.deepcopy(self.by_id["atlas:event:microsoft.sysmon:1"])
        sysmon["id"]="atlas:event:microsoft.sysmon:4688"
        sysmon["canonical_key"]="4688"
        sysmon["native_identifiers"][0]["value"]="4688"
        sysmon["aliases"]=[{"value":"4688","kind":"native","case_sensitive":False,"scope":{"namespace":"microsoft.sysmon"}}]
        records=self.records+[(Path("<synthetic-sysmon-4688>"),sysmon)]
        self.assertEqual({"atlas:event:microsoft.windows.security:4688","atlas:event:microsoft.sysmon:4688"},set(model.resolve_query(records,"4688")))
        self.assertEqual(["atlas:event:microsoft.windows.security:4688"],model.resolve_query(records,"4688","microsoft.windows.security"))

    def test_coverage_has_explicit_denominator_and_no_percent(self):
        coverage=next(r for _,r in self.records if r["record_kind"]=="coverage-snapshot")
        for key in ("denominator_definition","denominator_count","inventory_version","measured_at"):
            self.assertIn(key,coverage)
        self.assertNotIn("coverage_percent",coverage)
        self.assertLessEqual(coverage["numerator_count"],coverage["denominator_count"])

    def test_coverage_invalid_numerator_is_rejected_semantically(self):
        mutated=copy.deepcopy(self.records)
        _,coverage=next((p,r) for p,r in mutated if r["record_kind"]=="coverage-snapshot")
        coverage["numerator_count"]=coverage["denominator_count"]+1
        self.assertTrue(any("numerator_count exceeds denominator_count" in e for e in model.validate_semantics(mutated,self.registries)))

    def test_source_urls_reject_credential_parameters(self):
        source=copy.deepcopy(next(r for _,r in self.records if r["record_kind"]=="source"))
        source["canonical_urls"]=["https://example.invalid/docs?token=secret"]
        errors=[]
        model.validate_source_urls(source,errors)
        self.assertTrue(errors)

    def test_migration_inventory_and_legacy_aliases(self):
        self.assertEqual([],model.validate_migration(self.records))

    def test_phase51_schemas_are_preserved(self):
        self.assertEqual([],model.validate_legacy_schema_preservation())

    def test_schema_and_product_versions_are_independent(self):
        for _,record in self.records:
            self.assertEqual("1.0.0",record["schema_version"])
            self.assertGreaterEqual(record["record_revision"],1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
