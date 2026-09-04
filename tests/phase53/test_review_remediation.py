from __future__ import annotations

from pathlib import Path
import copy
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("iv", ROOT / "tools" / "ingestion" / "validate_ingestion_foundation.py")
iv = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(iv)


class Phase53ArchitectureReviewRemediationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = iv.load_fixture_bundle()
        cls.a = iv.bundle_artifacts(cls.bundle)

    def acq_errors(self, mutate_connector=None, mutate_run=None):
        connector = copy.deepcopy(self.a["connector-definition.json"])
        run = copy.deepcopy(self.a["acquisition-run.json"])
        if mutate_connector:
            mutate_connector(connector)
        if mutate_run:
            mutate_run(run)
        return iv.acquisition_semantic_errors(connector, run)

    def ri_errors(self, mutator):
        bundle = copy.deepcopy(self.bundle)
        mutator(bundle)
        return iv.cross_stage_ri_errors(bundle)

    def review_errors(self, mutator):
        review = copy.deepcopy(self.a["review-decision.json"])
        mutator(review)
        review["review_digest"] = iv.digest_without_field(review, "review_digest")
        return iv.review_decision_errors(review)

    def inventory_digest_breaks(self, mutator):
        inventory = copy.deepcopy(self.a["inventory-definition.json"])
        diff = copy.deepcopy(self.a["inventory-diff.json"])
        mutator(inventory)
        errors = iv.inventory_guardrail_errors(inventory, diff)
        self.assertTrue(any("complete semantic definition" in e for e in errors), errors)

    def build_schema(self):
        return iv.ingestion_validator("canonical-build-manifest.schema.json")

    def manifest(self, state, **fields):
        m = {
            "ingestion_contract_version": "1.0.0",
            "build_id": "atlas:build:atlas.ingestion:test-state",
            "state": state,
            "created_at": "2026-09-04T15:00:00Z",
            "canonical_schema_version": "1.0.0",
            "last_known_good_preserved": True,
            "pack_ready": state == "PACK_READY",
            "manifest_digest": "sha256-" + "0" * 64,
        }
        m.update(fields)
        return m

    # R53-001 — required target accounting and status coherence
    def test_r53001_01_valid_single_required_target(self):
        self.assertEqual([], self.acq_errors())

    def test_r53001_02_duplicate_connector_target_keys_rejected(self):
        def mc(c):
            second = copy.deepcopy(c["targets"][0]); second["resource_uri"] = "https://example.com/atlas-fixture/other.json"
            c["targets"].append(second)
        self.assertTrue(any("unique" in e for e in self.acq_errors(mc)))

    def test_r53001_03_unknown_resource_target_rejected(self):
        self.assertTrue(any("unknown" in e for e in self.acq_errors(mutate_run=lambda r: r["resource_results"][0].__setitem__("target_key", "undeclared"))))

    def test_r53001_04_required_target_absent_rejected(self):
        def mr(r):
            r["resource_results"] = [{"target_key":"optional","resource_key":"x","required":False,"status":"failed","requested_uri":"https://example.com/x","resolved_uri":"https://example.com/x","diagnostics":[]}]
            r["metrics"].update({"resource_count":1,"success_count":0,"failed_count":1,"not_modified_count":0,"skipped_count":0})
            r["result_status"]="failed"; r["publication_eligible"]=False
        def mc(c):
            c["targets"].append({"target_key":"optional","required":False,"resource_uri":"https://example.com/x","discovery":{"dynamic":False,"max_resources":1,"max_depth":0}})
        self.assertTrue(any("required connector target absent" in e for e in self.acq_errors(mc,mr)))

    def test_r53001_05_required_target_all_failed_cannot_publish(self):
        def mr(r):
            rr=r["resource_results"][0]; rr["status"]="failed"; rr.pop("snapshot_id",None)
            r["metrics"].update({"success_count":0,"failed_count":1}); r["result_status"]="failed"; r["publication_eligible"]=True
        self.assertTrue(any("non-publishable" in e for e in self.acq_errors(mutate_run=mr)))

    def test_r53001_06_dynamic_target_multiple_resources_allowed(self):
        def mc(c):
            c["targets"][0]["discovery"].update({"dynamic":True,"max_resources":10})
        def mr(r):
            second=copy.deepcopy(r["resource_results"][0]); second["resource_key"]="second.json"; second["snapshot_id"]="atlas:raw-snapshot:atlas.ingestion:second"
            r["resource_results"].append(second); r["metrics"].update({"resource_count":2,"success_count":2})
        self.assertEqual([], self.acq_errors(mc,mr))

    def test_r53001_07_success_cannot_conceal_failed_resource(self):
        def mr(r):
            bad=copy.deepcopy(r["resource_results"][0]); bad["resource_key"]="bad"; bad["status"]="failed"; bad.pop("snapshot_id",None)
            r["resource_results"].append(bad); r["metrics"].update({"resource_count":2,"success_count":1,"failed_count":1})
        self.assertTrue(any("success status is incoherent" in e for e in self.acq_errors(mutate_run=mr)))

    def test_r53001_08_failed_status_not_publication_eligible(self):
        def mr(r):
            rr=r["resource_results"][0]; rr["status"]="failed"; rr.pop("snapshot_id",None)
            r["metrics"].update({"success_count":0,"failed_count":1}); r["result_status"]="failed"; r["publication_eligible"]=True
        self.assertTrue(any("failed AcquisitionRun must not" in e for e in self.acq_errors(mutate_run=mr)))

    def test_r53001_09_partial_requires_mixed_completion(self):
        def mr(r): r["result_status"]="partial"
        self.assertTrue(any("mixed" in e for e in self.acq_errors(mutate_run=mr)))

    def test_r53001_10_not_modified_forbids_new_snapshot(self):
        def mr(r):
            rr=r["resource_results"][0]; rr["status"]="not-modified"; rr["previous_snapshot_id"]=rr["snapshot_id"]
            r["metrics"].update({"success_count":0,"not_modified_count":1}); r["result_status"]="not-modified"
        self.assertTrue(any("fake new snapshot" in e for e in self.acq_errors(mutate_run=mr)))

    def test_r53001_11_metrics_include_skipped_coherently(self):
        def mr(r): r["metrics"]["skipped_count"]=1
        self.assertTrue(any("skipped_count" in e for e in self.acq_errors(mutate_run=mr)))

    # R53-002 — cross-stage RI
    def test_r53002_01_connector_source_resolves(self):
        self.assertTrue(any("SourceRecord" in e for e in self.ri_errors(lambda b: b["artifacts"]["connector-definition"].__setitem__("source_id","atlas:source:atlas.source:missing"))))

    def test_r53002_02_refresh_policy_binding(self):
        self.assertTrue(any("freshness" in e for e in self.ri_errors(lambda b: b["artifacts"]["connector-definition"].__setitem__("refresh_policy_ref","arbitrary"))))

    def test_r53002_03_change_policy_binding(self):
        self.assertTrue(any("change_detection" in e for e in self.ri_errors(lambda b: b["artifacts"]["connector-definition"].__setitem__("change_detection_policy_ref","arbitrary"))))

    def test_r53002_04_acquisition_connector_id(self):
        self.assertTrue(any("AcquisitionRun.connector_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["acquisition-run"].__setitem__("connector_id","atlas:connector:atlas.ingestion:other"))))

    def test_r53002_05_acquisition_connector_version(self):
        self.assertTrue(any("connector_version" in e for e in self.ri_errors(lambda b: b["artifacts"]["acquisition-run"].__setitem__("connector_version","9.9.9"))))

    def test_r53002_06_acquisition_source_id(self):
        self.assertTrue(any("AcquisitionRun.source_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["acquisition-run"].__setitem__("source_id","atlas:source:atlas.source:other"))))

    def test_r53002_07_success_snapshot_resolves(self):
        self.assertTrue(any("snapshot_id does not resolve" in e for e in self.ri_errors(lambda b: b["artifacts"]["acquisition-run"]["resource_results"][0].__setitem__("snapshot_id","atlas:raw-snapshot:atlas.ingestion:missing"))))

    def test_r53002_08_raw_source_matches_run(self):
        self.assertTrue(any("RawSnapshot.source_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["raw-snapshot"].__setitem__("source_id","atlas:source:atlas.source:other"))))

    def test_r53002_09_raw_connector_matches_run(self):
        self.assertTrue(any("RawSnapshot.connector_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["raw-snapshot"].__setitem__("connector_id","atlas:connector:atlas.ingestion:other"))))

    def test_r53002_10_raw_connector_version_matches_run(self):
        self.assertTrue(any("RawSnapshot.connector_version" in e for e in self.ri_errors(lambda b: b["artifacts"]["raw-snapshot"].__setitem__("connector_version","9.9.9"))))

    def test_r53002_11_raw_target_resolves(self):
        self.assertTrue(any("target_key" in e for e in self.ri_errors(lambda b: b["artifacts"]["raw-snapshot"].__setitem__("target_key","missing"))))

    def test_r53002_12_raw_resource_identity_matches_result(self):
        self.assertTrue(any("target/resource identity" in e for e in self.ri_errors(lambda b: b["artifacts"]["raw-snapshot"].__setitem__("resource_key","different.json"))))

    def test_r53002_13_parser_run_definition_binding(self):
        self.assertTrue(any("ParserRun parser_id/version" in e for e in self.ri_errors(lambda b: b["artifacts"]["parser-run"].__setitem__("parser_version","9.9.9"))))

    def test_r53002_14_psr_parser_definition_binding(self):
        self.assertTrue(any("ParsedSourceRecord parser_id/version" in e for e in self.ri_errors(lambda b: b["artifacts"]["parsed-source-record"].__setitem__("parser_version","9.9.9"))))

    def test_r53002_15_psr_version_contract(self):
        self.assertTrue(any("psr_version" in e for e in self.ri_errors(lambda b: b["artifacts"]["parsed-source-record"].__setitem__("psr_version","9.9.9"))))

    def test_r53002_16_parser_input_digest(self):
        self.assertTrue(any("input_blob_digest" in e for e in self.ri_errors(lambda b: b["artifacts"]["parser-run"].__setitem__("input_blob_digest","sha256-"+"0"*64))))

    def test_r53002_17_parser_output_count(self):
        self.assertTrue(any("output_record_count" in e for e in self.ri_errors(lambda b: b["artifacts"]["parser-run"].__setitem__("output_record_count",2))))

    def test_r53002_18_parser_representation_digest(self):
        self.assertTrue(any("representation_digest" in e for e in self.ri_errors(lambda b: b["artifacts"]["parser-run"].__setitem__("representation_digest","sha256-"+"0"*64))))

    def test_r53002_19_normalization_parser_run_binding(self):
        self.assertTrue(any("NormalizationRun.parser_run_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-run"].__setitem__("parser_run_id","atlas:parser-run:atlas.ingestion:other"))))

    def test_r53002_20_normalizer_binding(self):
        self.assertTrue(any("normalizer_id/version" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-run"].__setitem__("normalizer_version","9.9.9"))))

    def test_r53002_21_lineage_normalizer_binding(self):
        self.assertTrue(any("Lineage normalizer" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-lineage"].__setitem__("normalizer_version","9.9.9"))))

    def test_r53002_22_lineage_mapping_binding(self):
        self.assertTrue(any("mapping_profile" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-lineage"]["mapping_profile"].__setitem__("version","9.9.9"))))

    def test_r53002_23_lineage_psr_resolution(self):
        self.assertTrue(any("unresolved PSR" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-lineage"].__setitem__("parsed_record_ids",["atlas:parsed-source-record:atlas.ingestion:missing"]))))

    def test_r53002_24_lineage_snapshot_resolution(self):
        self.assertTrue(any("unresolved RawSnapshot" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-lineage"].__setitem__("source_snapshot_ids",["atlas:raw-snapshot:atlas.ingestion:missing"]))))

    def test_r53002_25_lineage_output_resolution(self):
        self.assertTrue(any("output_record_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-lineage"].__setitem__("output_record_id","atlas:event:microsoft.windows.security:missing"))))

    def test_r53002_26_normalization_output_counts(self):
        self.assertTrue(any("output_counts" in e for e in self.ri_errors(lambda b: b["artifacts"]["normalization-run"]["output_counts"].__setitem__("EntityRecord",99))))

    def test_r53002_27_build_report_id_binding(self):
        self.assertTrue(any("BuildValidationReport.build_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["build-validation-report"].__setitem__("build_id","atlas:build:atlas.ingestion:other"))))

    def test_r53002_28_build_inventory_diff_binding(self):
        self.assertTrue(any("inventory_diff_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["canonical-build-manifest"].__setitem__("inventory_diff_id","atlas:inventory-diff:atlas.ingestion:other"))))

    def test_r53002_29_build_validation_report_binding(self):
        self.assertTrue(any("validation_report_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["canonical-build-manifest"].__setitem__("validation_report_id","atlas:build-validation:atlas.ingestion:other"))))

    def test_r53002_30_build_review_binding(self):
        self.assertTrue(any("review_decision_id" in e for e in self.ri_errors(lambda b: b["artifacts"]["canonical-build-manifest"].__setitem__("review_decision_id","atlas:review-decision:atlas.ingestion:other"))))

    def test_r53002_31_build_source_ids_exact(self):
        self.assertTrue(any("source_ids" in e for e in self.ri_errors(lambda b: b["artifacts"]["canonical-build-manifest"].__setitem__("source_ids",["atlas:source:atlas.source:other"]))))

    def test_r53002_32_build_run_ids_exact(self):
        self.assertTrue(any("parser_run_ids" in e for e in self.ri_errors(lambda b: b["artifacts"]["canonical-build-manifest"].__setitem__("parser_run_ids",["atlas:parser-run:atlas.ingestion:other"]))))

    def test_r53002_33_internal_timestamp_ordering(self):
        self.assertTrue(any("finish precedes start" in e for e in self.ri_errors(lambda b: b["artifacts"]["parser-run"].__setitem__("finished_at","2026-09-04T14:00:00Z"))))

    # R53-003 — complete inventory/diff immutability
    def test_r53003_01_declared_scope_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("declared_scope","changed"))
    def test_r53003_02_inventory_kind_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("inventory_kind","documentation"))
    def test_r53003_03_source_ids_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("source_ids",["atlas:source:atlas.source:other"]))
    def test_r53003_04_inventory_method_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("inventory_method","api"))
    def test_r53003_05_source_version_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("inventory_source_version","v2"))
    def test_r53003_06_expected_count_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("expected_identity_count",2))
    def test_r53003_07_identity_dimensions_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("identity_dimensions",["native-id"]))
    def test_r53003_08_scope_metadata_bound(self): self.inventory_digest_breaks(lambda i: i["scope_metadata"].__setitem__("provider","changed"))
    def test_r53003_09_guardrails_bound(self): self.inventory_digest_breaks(lambda i: i["guardrails"].__setitem__("max_unexplained_shrink_percent",99))
    def test_r53003_10_contract_version_bound(self): self.inventory_digest_breaks(lambda i: i.__setitem__("inventory_contract_version","2.0.0"))

    def test_r53003_11_diff_digest_binds_layer_audit_refs(self):
        diff=copy.deepcopy(self.a["inventory-diff.json"]); diff["canonical"]["baseline_ref"]="changed"
        self.assertTrue(any("digest mismatch" in e for e in iv.inventory_guardrail_errors(self.a["inventory-definition.json"],diff)))

    def test_r53003_12_canonical_candidate_diff_binding(self):
        self.assertTrue(any("canonical candidate audit" in e for e in self.ri_errors(lambda b: b["artifacts"]["inventory-diff"]["canonical"].__setitem__("candidate_digest","sha256-"+"0"*64))))

    def test_r53003_13_canonical_lkg_baseline_binding(self):
        self.assertTrue(any("Last Known Good" in e for e in self.ri_errors(lambda b: b["artifacts"]["inventory-diff"]["canonical"].__setitem__("baseline_ref","atlas:build:atlas.ingestion:other"))))

    # R53-004 — review/gate authority
    def test_r53004_01_high_risk_one_reviewer_rejected(self):
        def m(r): r["high_risk"]=True; r["required_approvals"]=2
        self.assertTrue(any("four-eyes" in e for e in self.review_errors(m)))

    def test_r53004_02_required_two_one_actor_rejected(self):
        self.assertTrue(any("required_approvals" in e for e in self.review_errors(lambda r: r.__setitem__("required_approvals",2))))

    def test_r53004_03_duplicate_actor_not_double_counted(self):
        def m(r):
            r["required_approvals"]=2; r["approvals"].append(copy.deepcopy(r["approvals"][0]))
        errors=self.review_errors(m)
        self.assertTrue(any("duplicate" in e for e in errors) and any("required_approvals" in e for e in errors),errors)

    def test_r53004_04_schema_forbids_mandatory_false(self):
        report=copy.deepcopy(self.a["build-validation-report.json"]); report["gates"][0]["mandatory"]=False
        self.assertFalse(iv.ingestion_validator("build-validation-report.schema.json").is_valid(report))

    def test_r53004_05_g15_pass_requires_review(self):
        self.assertTrue(any("G15 PASS requires" in e for e in iv.validation_report_errors(self.a["build-validation-report.json"],None)))

    def test_r53004_06_g15_failed_review_rejected(self):
        review=copy.deepcopy(self.a["review-decision.json"]); review["outcome"]="rejected"; review["approvals"][0]["status"]="rejected"; review["review_digest"]=iv.digest_without_field(review,"review_digest")
        self.assertTrue(any("G15 PASS is inconsistent" in e for e in iv.validation_report_errors(self.a["build-validation-report.json"],review)))

    def test_r53004_07_review_report_temporal_inversion_rejected(self):
        report=copy.deepcopy(self.a["build-validation-report.json"]); report["created_at"]="2026-09-04T15:03:00Z"; report["report_digest"]=iv.digest_without_field(report,"report_digest")
        self.assertTrue(any("temporal inversion" in e for e in iv.validation_report_errors(report,self.a["review-decision.json"])))

    def test_r53004_08_approved_with_exceptions_cannot_waive_gate(self):
        review=copy.deepcopy(self.a["review-decision.json"]); review["outcome"]="approved-with-exceptions"; review["review_digest"]=iv.digest_without_field(review,"review_digest")
        report=copy.deepcopy(self.a["build-validation-report.json"]); report["gates"][0]["result"]="fail"; report["mandatory_failures"]=1; report["publication_eligible"]=False; report["report_digest"]=iv.digest_without_field(report,"report_digest")
        actual=iv.sha256_digest(sorted(self.bundle["canonical_candidates"],key=lambda r:r["id"]))
        errors=iv.review_and_pack_ready_errors(self.a["canonical-build-manifest.json"],report,review,self.a["inventory-diff.json"],[self.a["normalization-run.json"]],actual)
        self.assertTrue(any("blocks PACK_READY" in e for e in errors),errors)

    # R53-005 — build-state contract
    def test_r53005_01_draft_valid_without_future_refs(self):
        self.assertTrue(self.build_schema().is_valid(self.manifest("DRAFT")))

    def test_r53005_02_acquired_valid(self):
        self.assertTrue(self.build_schema().is_valid(self.manifest("ACQUIRED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"])))

    def test_r53005_03_parsed_valid(self):
        self.assertTrue(self.build_schema().is_valid(self.manifest("PARSED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"],parser_run_ids=["atlas:parser-run:atlas.ingestion:x"])))

    def test_r53005_04_normalized_valid(self):
        self.assertTrue(self.build_schema().is_valid(self.manifest("NORMALIZED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"],parser_run_ids=["atlas:parser-run:atlas.ingestion:x"],normalization_run_ids=["atlas:normalization-run:atlas.ingestion:x"],candidate_corpus_digest="sha256-"+"1"*64)))

    def test_r53005_05_review_required_does_not_require_review(self):
        m=self.manifest("REVIEW_REQUIRED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"],parser_run_ids=["atlas:parser-run:atlas.ingestion:x"],normalization_run_ids=["atlas:normalization-run:atlas.ingestion:x"],candidate_corpus_digest="sha256-"+"1"*64,inventory_definition_ids=["atlas:inventory:atlas.ingestion:x"],inventory_diff_id="atlas:inventory-diff:atlas.ingestion:x",inventory_diff_digest="sha256-"+"2"*64,validation_report_id="atlas:build-validation:atlas.ingestion:x",validation_report_digest="sha256-"+"3"*64)
        self.assertTrue(self.build_schema().is_valid(m))

    def test_r53005_06_approved_requires_review(self):
        m=self.manifest("APPROVED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"],parser_run_ids=["atlas:parser-run:atlas.ingestion:x"],normalization_run_ids=["atlas:normalization-run:atlas.ingestion:x"],candidate_corpus_digest="sha256-"+"1"*64,inventory_definition_ids=["atlas:inventory:atlas.ingestion:x"],inventory_diff_id="atlas:inventory-diff:atlas.ingestion:x",inventory_diff_digest="sha256-"+"2"*64,validation_report_id="atlas:build-validation:atlas.ingestion:x",validation_report_digest="sha256-"+"3"*64)
        self.assertFalse(self.build_schema().is_valid(m))

    def test_r53005_07_pack_ready_full_fixture_valid(self):
        self.assertTrue(self.build_schema().is_valid(self.a["canonical-build-manifest.json"]))

    def test_r53005_08_draft_rejects_future_review_ref(self):
        self.assertFalse(self.build_schema().is_valid(self.manifest("DRAFT",review_decision_id="atlas:review-decision:atlas.ingestion:x")))

    def test_r53005_09_acquired_rejects_parser_ref(self):
        self.assertFalse(self.build_schema().is_valid(self.manifest("ACQUIRED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"],parser_run_ids=["atlas:parser-run:atlas.ingestion:x"])))

    def test_r53005_10_parsed_rejects_normalization_ref(self):
        self.assertFalse(self.build_schema().is_valid(self.manifest("PARSED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"],parser_run_ids=["atlas:parser-run:atlas.ingestion:x"],normalization_run_ids=["atlas:normalization-run:atlas.ingestion:x"])))

    def test_r53005_11_review_required_rejects_completed_review(self):
        m=self.manifest("REVIEW_REQUIRED",source_ids=["atlas:source:atlas.source:x"],acquisition_run_ids=["atlas:acquisition-run:atlas.ingestion:x"],parser_run_ids=["atlas:parser-run:atlas.ingestion:x"],normalization_run_ids=["atlas:normalization-run:atlas.ingestion:x"],candidate_corpus_digest="sha256-"+"1"*64,inventory_definition_ids=["atlas:inventory:atlas.ingestion:x"],inventory_diff_id="atlas:inventory-diff:atlas.ingestion:x",inventory_diff_digest="sha256-"+"2"*64,validation_report_id="atlas:build-validation:atlas.ingestion:x",validation_report_digest="sha256-"+"3"*64,review_decision_id="atlas:review-decision:atlas.ingestion:x")
        self.assertFalse(self.build_schema().is_valid(m))

    def test_r53005_12_failed_state_preserves_lkg(self):
        self.assertTrue(self.build_schema().is_valid(self.manifest("FAILED")))

    def test_r53005_13_failed_state_rejects_forward_dependency_semantically(self):
        m=self.manifest("FAILED",normalization_run_ids=["atlas:normalization-run:atlas.ingestion:x"])
        m["manifest_digest"]=iv.digest_without_field(m,"manifest_digest")
        self.assertTrue(any("forward reference" in e for e in iv.build_state_errors(m)))


if __name__ == "__main__":
    unittest.main()
