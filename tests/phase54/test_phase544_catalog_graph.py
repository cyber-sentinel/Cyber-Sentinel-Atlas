from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "tools" / "search" / "catalog_graph.py"
FIXTURE = ROOT / "fixtures" / "phase-5.4.4" / "catalog-graph-corpus.json"

spec = importlib.util.spec_from_file_location("atlas_phase544_catalog_graph_tests", MODULE)
assert spec and spec.loader
catalog_graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog_graph)


class Phase544CatalogGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.bundle = catalog_graph.build_phase544_bundle(cls.fixture)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "atlas-phase544.sqlite3"
        catalog_graph.search.build_index(self.bundle, self.path)
        self.core = catalog_graph.search.SQLiteSearchCore.open(
            self.path, expected_bundle=self.bundle
        )
        self.addCleanup(self.core.close)
        self.runtime = catalog_graph.CatalogGraphRuntime(self.core, self.bundle)

    def target_ids(self, result):
        return [item["target_id"] for item in result]

    def test_final_required_search_acceptance_cases_remain_stable(self):
        expected = {
            "4688": ["atlas:event:microsoft.windows.security:4688"],
            "windows 4688": ["atlas:event:microsoft.windows.security:4688"],
            "sysmon 1": ["atlas:event:microsoft.sysmon:1"],
            "592": ["atlas:event:microsoft.windows.security:592"],
            "T1059": ["atlas:attack-technique:mitre.attack:t1059"],
            "T1059.001": ["atlas:attack-technique:mitre.attack:t1059.001"],
            "CreateAccessKey": ["atlas:operation:aws.cloudtrail.iam:createaccesskey"],
            "EXECVE": ["atlas:audit-record:linux.audit:execve"],
            "exec_start": ["atlas:activity:docker.events:container.exec-start"],
            "kubectl exec": ["atlas:activity:kubernetes.audit:create.pods.exec"],
            "FileAccessed": ["atlas:activity:microsoft.m365.audit:fileaccessed"],
        }
        for query, target_ids in expected.items():
            with self.subTest(query=query):
                result = self.core.resolve(query)
                self.assertEqual(target_ids, self.target_ids(result["matches"]))
        collision = self.core.resolve("1")
        self.assertEqual("disambiguation", collision["status"])
        self.assertEqual(2, len(collision["matches"]))

    def test_provider_source_catalog_browse_is_deterministic(self):
        rows = self.runtime.browse(
            filters={"provider": "MICROSOFT-WINDOWS-SECURITY-AUDITING"}
        )
        self.assertEqual(
            [
                "atlas:event:microsoft.windows.security:4688",
                "atlas:event:microsoft.windows.security:592",
            ],
            self.target_ids(rows),
        )
        again = self.runtime.browse(
            filters={"provider": "microsoft-windows-security-auditing"}
        )
        self.assertEqual(rows, again)

    def test_lifecycle_and_version_browse_preserve_legacy(self):
        legacy = self.runtime.browse(filters={"lifecycle": "legacy"})
        self.assertIn(
            "atlas:event:microsoft.windows.security:592", self.target_ids(legacy)
        )
        version = self.runtime.browse(filters={"version": "windows-legacy"})
        self.assertEqual(
            ["atlas:event:microsoft.windows.security:592"], self.target_ids(version)
        )
        retired = self.runtime.browse(filters={"lifecycle": "retired"})
        self.assertEqual(
            ["atlas:activity:synthetic.graph:c"], self.target_ids(retired)
        )

    def test_facet_catalog_counts_are_stable(self):
        providers = self.runtime.facet_values("provider", filters={"platform": "windows"})
        values = {item["value"]: item["item_count"] for item in providers}
        self.assertEqual(2, values["microsoft-windows-security-auditing"])
        self.assertEqual(1, values["microsoft-windows-sysmon"])

    def test_numeric_event_id_browse_is_provider_scoped_and_numeric(self):
        rows = self.runtime.numeric_event_ids(namespace="microsoft.windows.security")
        self.assertEqual([592, 4688], [row["derived_numeric_value"] for row in rows])
        sysmon = self.runtime.numeric_event_ids(namespace="microsoft.sysmon")
        self.assertEqual([1], [row["derived_numeric_value"] for row in sysmon])

    def test_graph_depth_one_and_two_are_bounded_and_deterministic(self):
        seed = "atlas:activity:synthetic.graph:a"
        depth1 = self.runtime.graph_expand([seed], depth=1, direction="outgoing")
        self.assertEqual(["atlas:activity:synthetic.graph:b"], self.target_ids(depth1))
        depth2 = self.runtime.graph_expand([seed], depth=2, direction="outgoing")
        self.assertEqual(
            [
                "atlas:activity:synthetic.graph:b",
                "atlas:activity:synthetic.graph:c",
            ],
            self.target_ids(depth2),
        )
        self.assertEqual(depth2, self.runtime.graph_expand([seed], depth=2, direction="outgoing"))

    def test_graph_cycle_deduplicates_seed_and_nodes(self):
        rows = self.runtime.graph_expand(
            ["atlas:activity:synthetic.graph:a"], depth=2, direction="both"
        )
        ids = self.target_ids(rows)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn("atlas:activity:synthetic.graph:a", ids)

    def test_graph_cannot_outrank_search_stage(self):
        composed = self.runtime.resolve_with_graph(
            "atlas:activity:synthetic.graph:a", graph_depth=2
        )
        self.assertEqual("canonical_identifier", composed["search"]["match_stage"])
        self.assertEqual(
            ["atlas:activity:synthetic.graph:a"],
            self.target_ids(composed["search"]["matches"]),
        )
        self.assertEqual(
            [
                "atlas:activity:synthetic.graph:c",
                "atlas:activity:synthetic.graph:b",
            ],
            self.target_ids(composed["graph_pivots"]),
        )

    def test_graph_and_catalog_inputs_fail_closed(self):
        with self.assertRaises(catalog_graph.contract.QueryValidationError):
            self.runtime.graph_expand(["atlas:activity:synthetic.graph:a"], depth=3)
        with self.assertRaises(catalog_graph.contract.QueryValidationError):
            self.runtime.graph_expand(
                ["atlas:activity:synthetic.graph:a"],
                allowed_relationship_types={"NOT_REGISTERED"},
            )
        with self.assertRaises(catalog_graph.contract.QueryValidationError):
            self.runtime.browse(filters={"not-a-facet": "x"})
        with self.assertRaises(catalog_graph.contract.QueryValidationError):
            self.runtime.browse(filters={"provider": "\ud800"})

    def test_invalid_edge_target_and_duplicate_edge_fail_closed(self):
        invalid = copy.deepcopy(self.fixture)
        invalid["edges"][0]["target_id"] = "atlas:activity:synthetic.graph:missing"
        with self.assertRaises(catalog_graph.CatalogGraphValidationError):
            catalog_graph.build_phase544_bundle(invalid)

        duplicate = copy.deepcopy(self.fixture)
        duplicate["edges"].append(copy.deepcopy(duplicate["edges"][0]))
        with self.assertRaises(catalog_graph.CatalogGraphValidationError):
            catalog_graph.build_phase544_bundle(duplicate)

    def test_graph_content_is_bound_by_bundle_digest(self):
        changed = copy.deepcopy(self.fixture)
        changed["edges"][0]["relationship_type"] = "SUPERSEDES"
        changed_bundle = catalog_graph.build_phase544_bundle(changed)
        self.assertNotEqual(self.bundle["bundle_digest"], changed_bundle["bundle_digest"])
        with self.assertRaises(catalog_graph.search.SearchIndexValidationError):
            catalog_graph.search.SQLiteSearchCore.open(
                self.path, expected_bundle=changed_bundle
            )


if __name__ == "__main__":
    unittest.main()
