from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "tools" / "search" / "reference_search.py"
FIXTURE = ROOT / "fixtures" / "phase-5.4.1" / "acceptance-corpus.json"

spec = importlib.util.spec_from_file_location("atlas_phase541_reference_tests", MODULE)
assert spec and spec.loader
search = importlib.util.module_from_spec(spec)
spec.loader.exec_module(search)


class Phase541ReferenceSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.bundle = search.build_projection_bundle(cls.fixture)
        cls.resolver = search.ReferenceResolver(cls.bundle)

    def target_ids(self, result):
        return [item["target_id"] for item in result["matches"]]

    def test_projection_build_is_order_independent(self):
        reversed_fixture = copy.deepcopy(self.fixture)
        reversed_fixture["records"] = list(reversed(reversed_fixture["records"]))
        rebuilt = search.build_projection_bundle(reversed_fixture)
        self.assertEqual(self.bundle, rebuilt)
        self.assertEqual(self.bundle["bundle_digest"], rebuilt["bundle_digest"])

    def test_projection_has_no_engine_binding_in_541(self):
        binding = self.bundle["build_binding"]
        self.assertNotIn("index_adapter_id", binding)
        self.assertNotIn("index_adapter_version", binding)

    def test_exact_windows_4688(self):
        result = self.resolver.resolve("4688")
        self.assertEqual("direct", result["status"])
        self.assertEqual("native_identifier", result["match_stage"])
        self.assertEqual(["atlas:event:microsoft.windows.security:4688"], self.target_ids(result))

    def test_event_id_hint_keeps_exact_semantics(self):
        result = self.resolver.resolve("Event ID 4688")
        self.assertEqual("native_identifier", result["match_stage"])
        self.assertEqual(["atlas:event:microsoft.windows.security:4688"], self.target_ids(result))

    def test_windows_scoped_exact(self):
        result = self.resolver.resolve("windows 4688")
        self.assertEqual("scoped_identifier", result["match_stage"])
        self.assertEqual(["atlas:event:microsoft.windows.security:4688"], self.target_ids(result))

    def test_sysmon_scoped_exact(self):
        result = self.resolver.resolve("SYSMon   1")
        self.assertEqual("scoped_identifier", result["match_stage"])
        self.assertEqual(["atlas:event:microsoft.sysmon:1"], self.target_ids(result))

    def test_bare_one_disambiguates_deterministically(self):
        expected = [
            "atlas:event:synthetic.test.provider:1",
            "atlas:event:microsoft.sysmon:1",
        ]
        first = self.resolver.resolve("1")
        reversed_fixture = copy.deepcopy(self.fixture)
        reversed_fixture["records"] = list(reversed(reversed_fixture["records"]))
        second = search.ReferenceResolver(search.build_projection_bundle(reversed_fixture)).resolve("1")
        self.assertEqual("disambiguation", first["status"])
        self.assertEqual("native_identifier", first["match_stage"])
        self.assertEqual(set(expected), set(self.target_ids(first)))
        self.assertEqual(first, second)

    def test_legacy_592_is_first_class(self):
        result = self.resolver.resolve("592")
        self.assertEqual(["atlas:event:microsoft.windows.security:592"], self.target_ids(result))
        self.assertEqual("legacy", result["matches"][0]["lifecycle"])

    def test_attack_ids_are_exact(self):
        for query, target in [
            ("T1059", "atlas:attack-technique:mitre.attack:t1059"),
            ("t1059.001", "atlas:attack-technique:mitre.attack:t1059.001"),
        ]:
            with self.subTest(query=query):
                result = self.resolver.resolve(query)
                self.assertEqual("native_identifier", result["match_stage"])
                self.assertEqual([target], self.target_ids(result))

    def test_cross_domain_native_identifiers(self):
        cases = {
            "CreateAccessKey": "atlas:operation:aws.cloudtrail.iam:createaccesskey",
            "EXECVE": "atlas:audit-record:linux.audit:execve",
            "exec_start": "atlas:activity:docker.events:container.exec-start",
            "FileAccessed": "atlas:activity:microsoft.m365.audit:fileaccessed",
        }
        for query, target in cases.items():
            with self.subTest(query=query):
                result = self.resolver.resolve(query)
                self.assertEqual("direct", result["status"])
                self.assertEqual("native_identifier", result["match_stage"])
                self.assertEqual([target], self.target_ids(result))

    def test_exact_alias_precedes_reference_lexical(self):
        result = self.resolver.resolve("kubectl exec")
        self.assertEqual("alias", result["match_stage"])
        self.assertEqual(["atlas:activity:kubernetes.audit:create.pods.exec"], self.target_ids(result))

    def test_canonical_id_is_highest_priority(self):
        target = "atlas:event:microsoft.sysmon:1"
        result = self.resolver.resolve(target)
        self.assertEqual("canonical_identifier", result["match_stage"])
        self.assertEqual([target], self.target_ids(result))

    def test_structured_filter_limits_scope(self):
        result = self.resolver.resolve("provider:aws-iam CreateAccessKey")
        self.assertEqual(["atlas:operation:aws.cloudtrail.iam:createaccesskey"], self.target_ids(result))
        mismatch = self.resolver.resolve("provider:not-aws CreateAccessKey")
        self.assertEqual("no_match", mismatch["status"])

    def test_numeric_browse_is_numeric_not_lexical(self):
        rows = self.resolver.numeric_browse(namespace="microsoft.windows.security")
        self.assertEqual([592, 4688], [row["derived_numeric_value"] for row in rows])
        self.assertEqual(["592", "4688"], [row["value"] for row in rows])

    def test_query_bounds_fail_closed(self):
        cases = [
            lambda: search.parse_query("x" * 513),
            lambda: search.parse_query(" ".join(["x"] * 33)),
            lambda: search.parse_query(" ".join([f"platform:x{i}" for i in range(17)])),
            lambda: search.parse_query("x", graph_depth=3),
            lambda: search.parse_query("\ud800"),
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(search.QueryValidationError):
                    case()

    def test_injection_like_text_is_data_not_engine_syntax(self):
        result = self.resolver.resolve('" OR *')
        self.assertIn(result["status"], {"no_match", "direct", "disambiguation"})
        self.assertIn(result["match_stage"], {"none", "lexical_reference"})

    def test_duplicate_target_fails_closed(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["records"].append(copy.deepcopy(fixture["records"][0]))
        with self.assertRaises(ValueError):
            search.build_projection_bundle(fixture)

    def test_non_decimal_numeric_projection_fails_closed(self):
        fixture = copy.deepcopy(self.fixture)
        fixture["records"][0]["native_identifiers"][0]["value"] = "0x1250"
        with self.assertRaises(ValueError):
            search.build_projection_bundle(fixture)

    def test_case_sensitive_native_identifier_is_not_folded(self):
        self.assertEqual("direct", self.resolver.resolve("CreateAccessKey")["status"])
        lower = self.resolver.resolve("createaccesskey")
        self.assertNotEqual("native_identifier", lower["match_stage"])

    def test_empty_query_is_bounded_no_match(self):
        result = self.resolver.resolve("   ")
        self.assertEqual("no_match", result["status"])
        self.assertEqual("none", result["match_stage"])


if __name__ == "__main__":
    unittest.main()
