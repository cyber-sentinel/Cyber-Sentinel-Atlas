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


class Phase53SecurityInvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = iv.load_fixture_bundle()
        cls.artifacts = iv.bundle_artifacts(cls.bundle)

    def schema_rejects(self, fixture, schema, mutator):
        value = copy.deepcopy(self.artifacts[fixture])
        mutator(value)
        self.assertFalse(iv.ingestion_validator(schema).is_valid(value))

    def repo_rejects(self, mutator, phrase):
        bad = copy.deepcopy(self.bundle)
        mutator(bad)
        original = iv.load_fixture_bundle
        try:
            iv.load_fixture_bundle = lambda: bad
            errors = iv.validate_repository(ROOT)
        finally:
            iv.load_fixture_bundle = original
        self.assertTrue(any(phrase in error for error in errors), errors)

    def test_01_api_key_field_detected(self):
        self.assertTrue(iv.validate_json_secret_surface({"api_key": "synthetic"}))

    def test_02_token_field_detected(self):
        self.assertTrue(iv.validate_json_secret_surface({"access_token": "synthetic"}))

    def test_03_password_field_detected(self):
        self.assertTrue(iv.validate_json_secret_surface({"password": "synthetic"}))

    def test_04_uri_embedded_credentials_rejected(self):
        self.assertTrue(any("userinfo" in e for e in iv.public_uri_errors("https://user:pass@example.com/x", ["example.com"])))

    def test_05_signed_temporary_query_rejected(self):
        self.assertTrue(any("credential query" in e for e in iv.public_uri_errors("https://example.com/x?X-Amz-Signature=deadbeef", ["example.com"])))

    def test_06_loopback_redirect_rejected(self):
        self.assertTrue(any("private/link-local/loopback" in e for e in iv.public_uri_errors("https://127.0.0.1/x", ["127.0.0.1"])))

    def test_07_private_rfc1918_redirect_rejected(self):
        for host in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            with self.subTest(host=host):
                self.assertTrue(iv.public_uri_errors(f"https://{host}/x", [host]))

    def test_08_link_local_redirect_rejected(self):
        self.assertTrue(iv.public_uri_errors("https://169.254.169.254/latest/meta-data", ["169.254.169.254"]))

    def test_09_ipv6_loopback_redirect_rejected(self):
        self.assertTrue(iv.public_uri_errors("https://[::1]/x", ["::1"]))

    def test_10_non_allowlisted_host_rejected(self):
        self.assertTrue(any("not allowlisted" in e for e in iv.public_uri_errors("https://other.example/x", ["example.com"])))

    def test_11_tls_verification_disabled_rejected(self):
        self.schema_rejects("connector-definition.json", "connector-definition.schema.json", lambda x: x["security_policy"].__setitem__("tls_verify", False))

    def test_12_archive_path_traversal_rejected(self):
        self.assertTrue(iv.archive_entry_errors("../../escape.txt"))

    def test_13_archive_absolute_path_rejected(self):
        self.assertTrue(iv.archive_entry_errors("/etc/passwd"))

    def test_14_symlink_escape_rejected(self):
        self.assertTrue(iv.archive_entry_errors("safe/link", is_symlink=True, symlink_target="../../escape"))

    def test_15_device_file_rejected(self):
        self.assertTrue(iv.archive_entry_errors("devnode", is_device=True))

    def test_16_unbounded_acquisition_policy_rejected(self):
        self.schema_rejects("connector-definition.json", "connector-definition.schema.json", lambda x: x["security_policy"].__setitem__("max_response_bytes", 0))

    def test_17_parser_network_access_rejected(self):
        self.schema_rejects("parser-definition.json", "parser-definition.schema.json", lambda x: x["security_policy"].__setitem__("network_access", True))

    def test_18_parser_external_entity_resolution_rejected(self):
        self.schema_rejects("parser-definition.json", "parser-definition.schema.json", lambda x: x["security_policy"].__setitem__("xml_external_entities", True))

    def test_19_parser_source_execution_rejected(self):
        self.schema_rejects("parser-definition.json", "parser-definition.schema.json", lambda x: x["security_policy"].__setitem__("source_execution", True))

    def test_20_unknown_fields_silent_drop_rejected(self):
        self.schema_rejects("parser-definition.json", "parser-definition.schema.json", lambda x: x.__setitem__("unknown_field_policy", "drop"))

    def test_21_duplicate_ingestion_identity_detected(self):
        connector = self.artifacts["connector-definition.json"]
        errors = iv.duplicate_identity_errors([("a", connector, "connector_id"), ("b", copy.deepcopy(connector), "connector_id")])
        self.assertTrue(errors)

    def test_22_malformed_digest_rejected(self):
        self.schema_rejects("raw-snapshot.json", "raw-snapshot.schema.json", lambda x: x.__setitem__("raw_content_digest", "sha256-invalid"))

    def test_23_snapshot_without_acquisition_run_detected(self):
        self.repo_rejects(lambda b: b["artifacts"]["raw-snapshot"].__setitem__("acquisition_run_id", "atlas:acquisition-run:atlas.ingestion:missing"), "RawSnapshot.acquisition_run_id does not resolve AcquisitionRun")

    def test_24_psr_without_snapshot_linkage_detected(self):
        self.repo_rejects(lambda b: b["artifacts"]["parsed-source-record"].__setitem__("source_snapshot_id", "atlas:raw-snapshot:atlas.ingestion:missing"), "ParsedSourceRecord source_snapshot_id does not resolve")

    def test_25_psr_without_parser_linkage_detected(self):
        self.repo_rejects(lambda b: b["artifacts"]["parsed-source-record"].__setitem__("parser_id", "atlas:parser:atlas.ingestion:missing"), "ParsedSourceRecord parser_id/version do not resolve ParserDefinition")

    def test_26_normalization_without_mapping_digest_rejected(self):
        self.schema_rejects("normalization-run.json", "normalization-run.schema.json", lambda x: x["mapping_profile"].pop("digest"))

    def test_27_normalization_without_registry_context_rejected(self):
        self.schema_rejects("normalization-run.json", "normalization-run.schema.json", lambda x: x.pop("registry_bundle"))

    def test_28_ambiguous_normalization_cannot_publish(self):
        def mutate(b):
            b["artifacts"]["normalization-run"]["identity_outcomes"]["AMBIGUOUS"] = 1
            b["artifacts"]["normalization-run"]["publishable"] = True
        self.repo_rejects(mutate, "AMBIGUOUS normalization cannot be publishable")

    def test_29_semantic_relationship_without_claim_evidence_rejected(self):
        relationship = {"record_kind": "relationship", "id": "synthetic", "relationship_type": "RELATED_TO"}
        self.assertTrue(any("lacks supporting" in e for e in iv.relationship_provenance_errors([relationship])))

    def test_30_missing_source_snapshot_target_detected(self):
        def mutate(b):
            claim = next(r for r in b["canonical_candidates"] if r["record_kind"] == "claim")
            claim["evidence"][0]["source_snapshot_id"] = "atlas:raw-snapshot:atlas.ingestion:missing"
        self.repo_rejects(mutate, "source_snapshot_id does not resolve")

    def test_31_unexplained_inventory_mass_shrink_blocked(self):
        inventory = copy.deepcopy(self.artifacts["inventory-definition.json"])
        diff = copy.deepcopy(self.artifacts["inventory-diff.json"])
        diff["canonical"]["before_count"], diff["canonical"]["after_count"] = 100, 10
        diff["guardrail_evaluation"].update({"shrink_explained": False, "blocked": False})
        diff["diff_digest"] = iv.digest_without_field(diff, "diff_digest")
        self.assertTrue(any("mass shrink" in e for e in iv.inventory_guardrail_errors(inventory, diff)))

    def test_32_unexplained_inventory_explosion_blocked(self):
        inventory = copy.deepcopy(self.artifacts["inventory-definition.json"])
        diff = copy.deepcopy(self.artifacts["inventory-diff.json"])
        diff["canonical"]["before_count"], diff["canonical"]["after_count"] = 10, 100
        diff["guardrail_evaluation"].update({"growth_explained": False, "blocked": False})
        diff["diff_digest"] = iv.digest_without_field(diff, "diff_digest")
        self.assertTrue(any("explosion" in e for e in iv.inventory_guardrail_errors(inventory, diff)))

    def test_33_not_observed_is_not_removed(self):
        self.schema_rejects("inventory-diff.json", "inventory-diff.schema.json", lambda x: x.__setitem__("not_observed_is_removed", True))

    def test_34_candidate_change_invalidates_approval(self):
        build = self.artifacts["canonical-build-manifest.json"]
        report = self.artifacts["build-validation-report.json"]
        review = self.artifacts["review-decision.json"]
        diff = self.artifacts["inventory-diff.json"]
        errors = iv.review_and_pack_ready_errors(build, report, review, diff, [self.artifacts["normalization-run.json"]], iv.sha256_digest([{"changed": True}]))
        self.assertTrue(any("candidate changed after approval" in e for e in errors))

    def test_35_mandatory_validation_failure_cannot_pack_ready(self):
        report = copy.deepcopy(self.artifacts["build-validation-report.json"])
        report["gates"][0]["result"] = "fail"
        report["mandatory_failures"] = 1
        report["publication_eligible"] = True
        report["report_digest"] = iv.digest_without_field(report, "report_digest")
        self.assertTrue(any("cannot be waived" in e for e in iv.validation_report_errors(report)))

    def test_36_failed_build_preserves_last_known_good(self):
        build = copy.deepcopy(self.artifacts["canonical-build-manifest.json"])
        build["state"], build["pack_ready"], build["last_known_good_preserved"] = "FAILED", False, False
        build["manifest_digest"] = iv.digest_without_field(build, "manifest_digest")
        actual = iv.sha256_digest(sorted(self.bundle["canonical_candidates"], key=lambda r: r["id"]))
        errors = iv.review_and_pack_ready_errors(build, self.artifacts["build-validation-report.json"], self.artifacts["review-decision.json"], self.artifacts["inventory-diff.json"], [self.artifacts["normalization-run.json"]], actual)
        self.assertTrue(any("Last Known Good" in e for e in errors))

    def test_37_ingestion_artifact_is_not_atlas_record(self):
        self.assertFalse(iv.canonical_root_validator().is_valid(self.artifacts["raw-snapshot.json"]))

    def test_38_numeric_event_collision_across_providers_not_merged(self):
        bad = copy.deepcopy(self.bundle["search_readiness"])
        bad[1]["id"] = bad[0]["id"]
        self.assertTrue(iv.search_readiness_errors(bad))

    def test_39_legacy_current_identity_not_collapsed_to_alias(self):
        bad = copy.deepcopy(self.bundle["search_readiness"])
        bad[0]["aliases"] = [{"value": "592", "kind": "display", "case_sensitive": False}]
        self.assertTrue(any("collapse into aliases" in e for e in iv.search_readiness_errors(bad)))

    def test_40_git_source_execution_forbidden(self):
        self.schema_rejects("connector-definition.json", "connector-definition.schema.json", lambda x: x["security_policy"]["git_safety"].__setitem__("execute_source", True))

    def test_41_required_target_failure_non_publishable(self):
        connector = copy.deepcopy(self.artifacts["connector-definition.json"])
        run = copy.deepcopy(self.artifacts["acquisition-run.json"])
        run["resource_results"][0]["status"] = "failed"
        run["resource_results"][0].pop("snapshot_id", None)
        run["result_status"], run["publication_eligible"] = "partial", True
        run["metrics"].update({"success_count": 0, "failed_count": 1})
        self.assertTrue(any("required target failure" in e for e in iv.acquisition_semantic_errors(connector, run)))

    def test_42_not_modified_does_not_create_fake_raw_content(self):
        connector = copy.deepcopy(self.artifacts["connector-definition.json"])
        run = copy.deepcopy(self.artifacts["acquisition-run.json"])
        rr = run["resource_results"][0]
        rr["status"] = "not-modified"
        rr["previous_snapshot_id"] = rr["snapshot_id"]
        run["result_status"] = "not-modified"
        run["metrics"].update({"success_count": 0, "not_modified_count": 1, "bytes_received": 0})
        self.assertTrue(any("fake new snapshot" in e for e in iv.acquisition_semantic_errors(connector, run)))

    def test_43_untracked_runtime_bytecode_does_not_fail_validator(self):
        runtime_dir = ROOT / "tools" / "__pycache__"
        probe = runtime_dir / "phase53_runtime_probe.pyc"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"synthetic-runtime-bytecode")
        try:
            self.assertEqual(iv.validate_repository(ROOT), [])
        finally:
            probe.unlink(missing_ok=True)
            try:
                runtime_dir.rmdir()
            except OSError:
                pass

    def test_44_tracked_pycache_artifact_rejected(self):
        errors = iv.repository_hygiene_errors(["tools/__pycache__/validator.cpython-313.pyc"])
        self.assertTrue(any("tracked temporary/generated" in e for e in errors), errors)

    def test_45_tracked_standalone_pyc_rejected(self):
        errors = iv.repository_hygiene_errors(["tools/generated.pyc"])
        self.assertTrue(any("tracked temporary/checkpoint" in e for e in errors), errors)

    def test_46_tracked_temp_checkpoint_artifact_rejected(self):
        errors = iv.repository_hygiene_errors(["fixtures/phase-5.3/checkpoint.tmp", "docs/state.bak"])
        self.assertEqual(sum("tracked temporary/checkpoint" in e for e in errors), 2, errors)


if __name__ == "__main__":
    unittest.main()
