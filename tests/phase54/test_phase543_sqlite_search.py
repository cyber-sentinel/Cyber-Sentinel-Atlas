from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "tools" / "search" / "sqlite_search.py"
REFERENCE = ROOT / "tools" / "search" / "reference_search.py"
FIXTURE = ROOT / "fixtures" / "phase-5.4.1" / "acceptance-corpus.json"

ref_spec = importlib.util.spec_from_file_location("atlas_phase541_reference_for_543", REFERENCE)
assert ref_spec and ref_spec.loader
reference = importlib.util.module_from_spec(ref_spec)
ref_spec.loader.exec_module(reference)

spec = importlib.util.spec_from_file_location("atlas_phase543_sqlite_tests", MODULE)
assert spec and spec.loader
search = importlib.util.module_from_spec(spec)
spec.loader.exec_module(search)


class Phase543SQLiteSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.bundle = reference.build_projection_bundle(cls.fixture)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "atlas-search.sqlite3"
        self.metadata = search.build_index(self.bundle, self.path)
        self.core = search.SQLiteSearchCore.open(self.path, expected_bundle=self.bundle)
        self.addCleanup(self.core.close)

    def target_ids(self, result):
        return [item["target_id"] for item in result["matches"]]

    def test_index_binding_and_manifest_are_verified(self):
        manifest = self.core.manifest()
        self.assertEqual("sqlite-fts5", manifest["index_adapter_id"])
        self.assertEqual("1.0.0", manifest["index_schema_version"])
        self.assertEqual(self.bundle["bundle_digest"], manifest["bundle_digest"])
        self.assertEqual(str(len(self.bundle["documents"])), manifest["document_count"])
        self.assertTrue(manifest["logical_content_digest"].startswith("sha256-"))

    def test_runtime_requires_external_expected_spc_binding(self):
        self.core.close()
        with self.assertRaises(TypeError):
            search.SQLiteSearchCore.open(self.path)
        with self.assertRaises(search.SearchIndexValidationError):
            search.SQLiteSearchCore.open(self.path, expected_bundle=None)

    def test_required_exact_resolution_cases_match_reference_contract(self):
        queries = [
            "4688",
            "Event ID 4688",
            "windows 4688",
            "sysmon 1",
            "1",
            "592",
            "T1059",
            "T1059.001",
            "CreateAccessKey",
            "EXECVE",
            "exec_start",
            "kubectl exec",
            "FileAccessed",
        ]
        reference_core = reference.ReferenceResolver(self.bundle)
        for query in queries:
            with self.subTest(query=query):
                expected = reference_core.resolve(query)
                actual = self.core.resolve(query)
                self.assertEqual(expected["status"], actual["status"])
                self.assertEqual(expected["match_stage"], actual["match_stage"])
                self.assertEqual(self.target_ids(expected), self.target_ids(actual))

    def test_production_lexical_stage_uses_fts5(self):
        result = self.core.resolve("PowerShell")
        self.assertEqual("direct", result["status"])
        self.assertEqual("lexical", result["match_stage"])
        self.assertEqual(["atlas:attack-technique:mitre.attack:t1059.001"], self.target_ids(result))
        self.assertEqual("bounded SQLite FTS5 lexical match", result["matches"][0]["match_reason"])

    def test_structured_filters_are_bound_and_case_insensitive(self):
        result = self.core.resolve("provider:MITRE PowerShell")
        self.assertEqual(["atlas:attack-technique:mitre.attack:t1059.001"], self.target_ids(result))
        mismatch = self.core.resolve("provider:not-mitre PowerShell")
        self.assertEqual("no_match", mismatch["status"])

    def test_case_sensitive_identifier_falls_back_without_identity_collapse(self):
        exact = self.core.resolve("CreateAccessKey")
        self.assertEqual("native_identifier", exact["match_stage"])
        lower = self.core.resolve("createaccesskey")
        self.assertNotEqual("native_identifier", lower["match_stage"])
        self.assertIn("atlas:operation:aws.cloudtrail.iam:createaccesskey", self.target_ids(lower))

    def test_query_and_limit_bounds_fail_closed(self):
        cases = [
            lambda: self.core.resolve("x" * 513),
            lambda: self.core.resolve(" ".join(["x"] * 33)),
            lambda: self.core.resolve("x", limit=0),
            lambda: self.core.resolve("x", limit=101),
            lambda: self.core.resolve("\ud800"),
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(search.contract.QueryValidationError):
                    case()

    def test_fts_injection_like_text_is_data(self):
        result = self.core.resolve('PowerShell" OR provider:*')
        self.assertEqual("no_match", result["status"])
        result = self.core.resolve('" OR *')
        self.assertIn(result["status"], {"no_match", "direct", "disambiguation"})

    def test_numeric_browse_is_stably_numeric(self):
        rows = self.core.numeric_browse(namespace="microsoft.windows.security")
        self.assertEqual([592, 4688], [row["derived_numeric_value"] for row in rows])
        self.assertEqual(["592", "4688"], [row["value"] for row in rows])

    def test_index_is_query_only_at_runtime(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.core.conn.execute("DELETE FROM documents")

    def test_stale_metadata_fails_closed(self):
        self.core.close()
        conn = sqlite3.connect(self.path)
        conn.execute("UPDATE metadata SET value=? WHERE key='bundle_digest'", ("sha256-stale",))
        conn.commit()
        conn.close()
        with self.assertRaises(search.SearchIndexValidationError):
            search.SQLiteSearchCore.open(self.path, expected_bundle=self.bundle)

    def test_logical_content_tamper_fails_closed_even_when_sqlite_is_valid(self):
        self.core.close()
        conn = sqlite3.connect(self.path)
        conn.execute(
            "UPDATE documents SET title=? WHERE target_id=?",
            ("Tampered Title", "atlas:attack-technique:mitre.attack:t1059.001"),
        )
        conn.commit()
        self.assertEqual("ok", conn.execute("PRAGMA quick_check").fetchone()[0])
        conn.close()
        with self.assertRaises(search.SearchIndexValidationError):
            search.SQLiteSearchCore.open(self.path, expected_bundle=self.bundle)

    def test_corrupt_database_fails_closed(self):
        self.core.close()
        self.path.write_bytes(b"not-a-sqlite-database")
        with self.assertRaises(search.SearchIndexValidationError):
            search.SQLiteSearchCore.open(self.path, expected_bundle=self.bundle)

    def test_invalid_rebuild_does_not_replace_last_good_index(self):
        self.core.close()
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        invalid = copy.deepcopy(self.bundle)
        invalid["documents"][0]["title"] = "tampered without digest update"
        with self.assertRaises(search.SearchIndexValidationError):
            search.build_index(invalid, self.path)
        after = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        reopened = search.SQLiteSearchCore.open(self.path, expected_bundle=self.bundle)
        reopened.close()

    def test_rebuilds_are_logically_reproducible(self):
        self.core.close()
        other = Path(self.temp.name) / "atlas-search-2.sqlite3"
        search.build_index(self.bundle, other)
        first = search.SQLiteSearchCore.open(self.path, expected_bundle=self.bundle)
        second = search.SQLiteSearchCore.open(other, expected_bundle=self.bundle)
        try:
            self.assertEqual(first.manifest(), second.manifest())
            for query in ("1", "PowerShell", "process creation", "kubectl exec"):
                self.assertEqual(first.resolve(query), second.resolve(query))
        finally:
            first.close()
            second.close()

    def test_projection_bundle_digest_is_enforced(self):
        invalid = copy.deepcopy(self.bundle)
        invalid["bundle_digest"] = "sha256-bad"
        with self.assertRaises(search.SearchIndexValidationError):
            search.build_index(invalid, Path(self.temp.name) / "bad.sqlite3")


if __name__ == "__main__":
    unittest.main()
