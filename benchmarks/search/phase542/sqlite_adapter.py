from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Sequence

from common import BenchDoc, TOP_K, sqlite_fts_expression, tokenize_lexical


class SQLiteAdapter:
    engine_id = "sqlite-fts5"

    def __init__(self, root: Path, docs: Sequence[BenchDoc]):
        self.path = root / "atlas-search-spike.sqlite3"
        start = time.perf_counter()
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("PRAGMA synchronous=FULL")
        try:
            self.conn.execute("CREATE VIRTUAL TABLE __probe USING fts5(value)")
            self.conn.execute("DROP TABLE __probe")
        except sqlite3.OperationalError as exc:
            raise RuntimeError("SQLite build lacks FTS5") from exc
        self.conn.executescript("""
        CREATE TABLE docs(
          target_id TEXT PRIMARY KEY,title TEXT,aliases TEXT,native_ids TEXT,body TEXT,
          namespace TEXT,platform TEXT,product TEXT,provider TEXT,channel TEXT,lifecycle TEXT,
          numeric_event_id INTEGER
        );
        CREATE INDEX idx_scope ON docs(provider,platform,product,channel,lifecycle,target_id);
        CREATE INDEX idx_numeric ON docs(provider,numeric_event_id,target_id) WHERE numeric_event_id IS NOT NULL;
        CREATE VIRTUAL TABLE docs_fts USING fts5(
          target_id UNINDEXED,title,aliases,native_ids,body,tokenize='unicode61'
        );
        """)
        rows = [(
            d.target_id,d.title,d.aliases,d.native_ids,d.body,d.namespace,d.platform,
            d.product,d.provider,d.channel,d.lifecycle,d.numeric_event_id,
        ) for d in docs]
        self.conn.executemany("INSERT INTO docs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self.conn.executemany(
            "INSERT INTO docs_fts VALUES(?,?,?,?,?)",
            [(d.target_id,d.title,d.aliases,d.native_ids,d.body) for d in docs],
        )
        self.conn.commit()
        self.build_seconds = time.perf_counter() - start

    @property
    def version(self):
        return sqlite3.sqlite_version

    @property
    def index_bytes(self):
        return self.path.stat().st_size

    def exact(self, target_id):
        return [r[0] for r in self.conn.execute(
            "SELECT target_id FROM docs WHERE target_id=?", (target_id,)
        ).fetchall()]

    def lexical(self, text, provider=None):
        terms = tokenize_lexical(text)
        if not terms:
            return []
        expr = sqlite_fts_expression(terms)
        sql = "SELECT f.target_id,bm25(docs_fts) score FROM docs_fts f JOIN docs d ON d.target_id=f.target_id WHERE docs_fts MATCH ?"
        params = [expr]
        if provider:
            sql += " AND d.provider=?"
            params.append(provider)
        sql += " ORDER BY score ASC,f.target_id ASC LIMIT ?"
        params.append(TOP_K)
        return [r[0] for r in self.conn.execute(sql, params).fetchall()]

    def numeric_browse(self, provider):
        return [(int(n), tid) for n, tid in self.conn.execute(
            "SELECT numeric_event_id,target_id FROM docs WHERE provider=? AND numeric_event_id IS NOT NULL ORDER BY numeric_event_id,target_id LIMIT ?",
            (provider, TOP_K),
        ).fetchall()]

    def close(self):
        self.conn.close()
