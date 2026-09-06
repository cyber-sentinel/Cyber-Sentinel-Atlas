from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

from common import BenchDoc, TOP_K, directory_size, tokenize_lexical


class TantivyAdapter:
    engine_id = "tantivy"

    def __init__(self, root: Path, docs: Sequence[BenchDoc]):
        import tantivy

        self.tantivy = tantivy
        self.path = root / "tantivy-index"
        self.path.mkdir()
        start = time.perf_counter()
        builder = tantivy.SchemaBuilder()
        builder.add_text_field("target_id", stored=True, tokenizer_name="raw", index_option="basic")
        for field in ("namespace", "platform", "product", "provider", "channel", "lifecycle"):
            builder.add_text_field(field, stored=True, tokenizer_name="raw", index_option="basic")
        for field in ("title", "aliases", "native_ids", "body"):
            builder.add_text_field(field, stored=True)
        builder.add_unsigned_field("numeric_event_id", stored=True, indexed=True, fast=True)
        self.schema = builder.build()
        self.index = tantivy.Index(self.schema, path=str(self.path))
        writer = self.index.writer()
        for doc in docs:
            values = {
                "target_id": doc.target_id,
                "namespace": doc.namespace,
                "platform": doc.platform,
                "product": doc.product,
                "provider": doc.provider,
                "channel": doc.channel,
                "lifecycle": doc.lifecycle,
                "title": doc.title,
                "aliases": doc.aliases,
                "native_ids": doc.native_ids,
                "body": doc.body,
            }
            if doc.numeric_event_id is not None:
                values["numeric_event_id"] = doc.numeric_event_id
            writer.add_document(tantivy.Document.from_dict(values, self.schema))
        writer.commit()
        writer.wait_merging_threads()
        self.index.reload()
        self.searcher = self.index.searcher()
        self.build_seconds = time.perf_counter() - start

    @property
    def version(self):
        return str(getattr(self.tantivy, "__version__", "0.26.0"))

    @property
    def index_bytes(self):
        return directory_size(self.path)

    def _ids(self, result: Any):
        rows = []
        for score, address in result.hits:
            doc = self.searcher.doc(address)
            rows.append((float(score), str(doc["target_id"][0])))
        rows.sort(key=lambda item: (-item[0], item[1]))
        return [item[1] for item in rows[:TOP_K]]

    def exact(self, target_id):
        query = self.tantivy.Query.term_query(self.schema, "target_id", target_id, "basic")
        return self._ids(self.searcher.search(query, TOP_K))

    def _or(self, queries):
        return self.tantivy.Query.boolean_query([
            (self.tantivy.Occur.Should, query) for query in queries
        ])

    def _and(self, queries):
        return self.tantivy.Query.boolean_query([
            (self.tantivy.Occur.Must, query) for query in queries
        ])

    def _lexical_query(self, text):
        terms = tokenize_lexical(text)
        if not terms:
            return self.tantivy.Query.empty_query()
        queries = [
            self.tantivy.Query.term_query(self.schema, field, term, "position")
            for term in terms
            for field in ("title", "aliases", "native_ids", "body")
        ]
        return self._or(queries)

    def lexical(self, text, provider=None):
        query = self._lexical_query(text)
        if provider:
            provider_query = self.tantivy.Query.term_query(self.schema, "provider", provider, "basic")
            query = self._and([query, provider_query])
        return self._ids(self.searcher.search(query, TOP_K))

    def numeric_browse(self, provider):
        provider_query = self.tantivy.Query.term_query(self.schema, "provider", provider, "basic")
        numeric_exists = self.tantivy.Query.exists_query("numeric_event_id")
        query = self._and([provider_query, numeric_exists])
        result = self.searcher.search(
            query,
            TOP_K,
            order_by_field="numeric_event_id",
            order=self.tantivy.Order.Asc,
        )
        rows = []
        for _, address in result.hits:
            doc = self.searcher.doc(address)
            rows.append((int(doc["numeric_event_id"][0]), str(doc["target_id"][0])))
        return sorted(rows)[:TOP_K]

    def close(self):
        self.searcher = None
        self.index = None
