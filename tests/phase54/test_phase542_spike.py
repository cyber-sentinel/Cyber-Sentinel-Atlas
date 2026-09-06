from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / "benchmarks" / "search" / "phase542"
BENCH = BENCH_DIR / "benchmark.py"
SUITE = BENCH_DIR / "query-suite.json"
TANTIVY = BENCH_DIR / "tantivy_adapter.py"


def load_benchmark_module():
    sys.path.insert(0, str(BENCH_DIR))
    spec = importlib.util.spec_from_file_location("p542", BENCH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Phase 5.4.2 benchmark module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Phase542SpikeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bench = load_benchmark_module()
        cls.suite = json.loads(SUITE.read_text(encoding="utf-8"))

    def test_query_suite_is_versioned_and_unique(self):
        self.assertEqual(self.suite["version"], "1.1.0")
        ids = [item["id"] for item in self.suite["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue({"exact", "lexical", "numeric_browse"}.issuperset(
            {item["kind"] for item in self.suite["cases"]}
        ))
        self.assertIn("lexical-high-fanout-deterministic-ties", ids)

    def test_tantivy_uses_programmatic_queries(self):
        source = TANTIVY.read_text(encoding="utf-8")
        self.assertNotIn(".parse_query(", source)
        self.assertIn("Query.term_query", source)
        self.assertIn("Query.exists_query", source)
        self.assertIn("self.document_count", source)

    def test_lexical_tokenizer_neutralizes_backend_syntax(self):
        tokens = self.bench._tokenize_lexical('PowerShell" OR provider:*')
        self.assertEqual(tokens, ["powershell", "or", "provider"])
        self.assertEqual(
            self.bench._sqlite_fts_expression(tokens),
            '"powershell" OR "or" OR "provider"',
        )
        with self.assertRaises(ValueError):
            self.bench._tokenize_lexical(" ".join(f"t{i}" for i in range(33)))

    def test_lexical_query_scalar_and_unicode_bounds(self):
        self.assertEqual(self.bench._tokenize_lexical("A" * 512), ["a" * 512])
        with self.assertRaises(ValueError):
            self.bench._tokenize_lexical("A" * 513)
        with self.assertRaises(ValueError):
            self.bench._tokenize_lexical("\ud800")

    def test_noise_has_no_native_identifiers_and_varied_text(self):
        base, _ = self.bench.load_base_documents()
        expanded = self.bench.expand_documents(base, 250)
        noise = expanded[len(base):]
        self.assertEqual(expanded[:len(base)], base)
        self.assertTrue(all(item.native_ids == "" for item in noise))
        self.assertEqual(len({item.target_id for item in expanded}), 250)
        self.assertGreater(len({item.body for item in noise}), 200)
        self.assertGreater(sum("benchmarkfanout" in item.body for item in noise), 40)

    def test_sqlite_smoke_acceptance(self):
        base, _ = self.bench.load_base_documents()
        docs = self.bench.expand_documents(base, 500)
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self.bench.SQLiteAdapter(Path(tmp), docs)
            try:
                self.assertEqual(
                    adapter.exact("atlas:event:microsoft.windows.security:4688"),
                    ["atlas:event:microsoft.windows.security:4688"],
                )
                self.assertIn(
                    "atlas:attack-technique:mitre.attack:t1059.001",
                    adapter.lexical("PowerShell"),
                )
                self.assertIn(
                    "atlas:activity:kubernetes.audit:create.pods.exec",
                    adapter.lexical("kubectl exec"),
                )
                self.assertEqual(
                    adapter.numeric_browse("microsoft-windows-security-auditing")[:2],
                    [
                        (592, "atlas:event:microsoft.windows.security:592"),
                        (4688, "atlas:event:microsoft.windows.security:4688"),
                    ],
                )
                self.assertEqual(
                    adapter.lexical("benchmarkfanout"),
                    [f"atlas:benchmark-noise:{i:08d}" for i in range(0, 50, 5)],
                )
                self.assertEqual(adapter.lexical('" OR provider:*'), ["atlas:benchmark-noise:00000000"] if False else [])
            finally:
                adapter.close()

    @unittest.skipUnless(importlib.util.find_spec("tantivy") is not None, "tantivy binding not installed")
    def test_tantivy_high_fanout_total_order(self):
        base, _ = self.bench.load_base_documents()
        docs = self.bench.expand_documents(base, 500)
        with tempfile.TemporaryDirectory() as tmp:
            adapter = self.bench.TantivyAdapter(Path(tmp), docs)
            try:
                expected = [f"atlas:benchmark-noise:{i:08d}" for i in range(0, 50, 5)]
                first = adapter.lexical("benchmarkfanout")
                second = adapter.lexical("benchmarkfanout")
                self.assertEqual(first, expected)
                self.assertEqual(second, expected)
            finally:
                adapter.close()


if __name__ == "__main__":
    unittest.main()
