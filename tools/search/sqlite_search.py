#!/usr/bin/env python3
"""Atlas Phase 5.4.3 production deterministic search core on SQLite + FTS5.

The SQLite database is disposable derived state. Canonical records and the Search
Projection Corpus (SPC) remain authoritative. Runtime activation always requires the
expected SPC and fails closed on schema, binding, logical-content, or SQLite integrity
mismatch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import reference_search as contract  # noqa: E402

INDEX_SCHEMA_VERSION = "1.0.0"
INDEX_ADAPTER_ID = "sqlite-fts5"
INDEX_ADAPTER_VERSION = "1.0.0"
DEFAULT_TOP_K = 20
MAX_TOP_K = 100
LEXICAL_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


class SearchIndexError(RuntimeError):
    """Base error for production search-index failures."""


class SearchIndexValidationError(SearchIndexError):
    """Raised when an index or projection binding is corrupt, stale, or incompatible."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256-" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _nfkc(value: str) -> str:
    return unicodedata.normalize("NFKC", value)


def _fold(value: str) -> str:
    return _nfkc(value).casefold()


def _fts_tokens(text: str) -> list[str]:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        raise contract.QueryValidationError("query contains an invalid Unicode surrogate")
    if len(text) > contract.MAX_QUERY_SCALARS:
        raise contract.QueryValidationError(
            f"query exceeds {contract.MAX_QUERY_SCALARS} Unicode scalar values"
        )
    tokens = [_fold(token) for token in LEXICAL_TOKEN_RE.findall(_nfkc(text))]
    if len(tokens) > contract.MAX_TERMS:
        raise contract.QueryValidationError(
            f"query exceeds {contract.MAX_TERMS} lexical terms"
        )
    return tokens


def _fts_expression(tokens: Sequence[str]) -> str:
    # Caller text never reaches MATCH. Only bounded tokenizer output is quoted.
    return " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens)


def _validate_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise contract.QueryValidationError("limit must be an integer")
    if limit < 1 or limit > MAX_TOP_K:
        raise contract.QueryValidationError(f"limit must be between 1 and {MAX_TOP_K}")
    return limit


def validate_projection_bundle(bundle: Mapping[str, Any]) -> None:
    if not isinstance(bundle, Mapping):
        raise SearchIndexValidationError("projection bundle must be an object")
    if bundle.get("search_contract_version") != contract.SEARCH_CONTRACT_VERSION:
        raise SearchIndexValidationError("unsupported search contract version")

    claimed = bundle.get("bundle_digest")
    if not isinstance(claimed, str):
        raise SearchIndexValidationError("projection bundle is missing bundle_digest")
    unsigned = {key: value for key, value in bundle.items() if key != "bundle_digest"}
    if _digest(unsigned) != claimed:
        raise SearchIndexValidationError("projection bundle digest mismatch")

    binding = bundle.get("build_binding")
    required_binding = {
        "canonical_corpus_id",
        "canonical_corpus_digest",
        "canonical_schema_version",
        "registry_bundle_version",
        "registry_bundle_digest",
        "projection_profile_version",
        "projection_profile_digest",
    }
    if not isinstance(binding, Mapping) or not required_binding.issubset(binding):
        raise SearchIndexValidationError("projection build binding is incomplete")

    documents = bundle.get("documents")
    identifiers = bundle.get("identifiers")
    aliases = bundle.get("aliases")
    filters = bundle.get("filters")
    if not isinstance(documents, list) or not documents:
        raise SearchIndexValidationError("projection bundle has no documents")
    if not isinstance(identifiers, list) or not isinstance(aliases, list) or not isinstance(filters, list):
        raise SearchIndexValidationError("projection bundle collections are malformed")

    target_ids = [doc.get("target_id") for doc in documents]
    if any(not isinstance(target_id, str) or not target_id.startswith("atlas:") for target_id in target_ids):
        raise SearchIndexValidationError("all projected documents require an Atlas target_id")
    if len(set(target_ids)) != len(target_ids):
        raise SearchIndexValidationError("duplicate SearchDocument target_id")
    target_set = set(target_ids)

    for doc in documents:
        claimed_doc = doc.get("projection_digest")
        unsigned_doc = {key: value for key, value in doc.items() if key != "projection_digest"}
        if not isinstance(claimed_doc, str) or _digest(unsigned_doc) != claimed_doc:
            raise SearchIndexValidationError(
                f"SearchDocument digest mismatch: {doc.get('target_id')}"
            )

    for collection_name, collection in (
        ("identifier", identifiers),
        ("alias", aliases),
        ("filter", filters),
    ):
        for row in collection:
            if row.get("target_id") not in target_set:
                raise SearchIndexValidationError(
                    f"{collection_name} references missing target: {row.get('target_id')}"
                )


def _base_metadata_for_bundle(bundle: Mapping[str, Any]) -> dict[str, str]:
    binding = bundle["build_binding"]
    return {
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "index_adapter_id": INDEX_ADAPTER_ID,
        "index_adapter_version": INDEX_ADAPTER_VERSION,
        "sqlite_build_version": sqlite3.sqlite_version,
        "search_contract_version": str(bundle["search_contract_version"]),
        "bundle_digest": str(bundle["bundle_digest"]),
        "canonical_corpus_id": str(binding["canonical_corpus_id"]),
        "canonical_corpus_digest": str(binding["canonical_corpus_digest"]),
        "canonical_schema_version": str(binding["canonical_schema_version"]),
        "registry_bundle_version": str(binding["registry_bundle_version"]),
        "registry_bundle_digest": str(binding["registry_bundle_digest"]),
        "projection_profile_version": str(binding["projection_profile_version"]),
        "projection_profile_digest": str(binding["projection_profile_digest"]),
        "document_count": str(len(bundle["documents"])),
        "identifier_count": str(len(bundle["identifiers"])),
        "alias_count": str(len(bundle["aliases"])),
        "filter_projection_count": str(len(bundle["filters"])),
    }


def _probe_fts5(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("CREATE VIRTUAL TABLE __atlas_fts5_probe USING fts5(value)")
        conn.execute("DROP TABLE __atlas_fts5_probe")
    except sqlite3.DatabaseError as exc:
        raise SearchIndexValidationError("SQLite runtime does not provide FTS5") from exc


def _rows(conn: sqlite3.Connection, sql: str) -> list[list[Any]]:
    return [list(row) for row in conn.execute(sql).fetchall()]


def _logical_content_digest(conn: sqlite3.Connection) -> str:
    """Digest all logical rows used by exact, facet, numeric and lexical retrieval."""
    payload = {
        "documents": _rows(
            conn,
            """SELECT target_id,entity_type,title,title_norm,namespace,platform,product,
                      provider,channel,lifecycle,description
               FROM documents ORDER BY target_id""",
        ),
        "identifiers": _rows(
            conn,
            """SELECT target_id,identifier_type,value,match_value,namespace,
                      case_sensitive,primary_flag,numeric_semantics,derived_numeric_value
               FROM identifiers
               ORDER BY target_id,identifier_type,namespace,value""",
        ),
        "aliases": _rows(
            conn,
            """SELECT target_id,value,match_value,kind,case_sensitive,scope_json
               FROM aliases ORDER BY target_id,value,kind""",
        ),
        "facets": _rows(
            conn,
            """SELECT target_id,facet_key,facet_value,facet_value_norm
               FROM facets ORDER BY target_id,facet_key,facet_value""",
        ),
        "fts": _rows(
            conn,
            """SELECT target_id,title,aliases,native_identifiers,description
               FROM documents_fts ORDER BY target_id""",
        ),
    }
    return _digest(payload)


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE metadata(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE documents(
            target_id TEXT PRIMARY KEY,
            entity_type TEXT NOT NULL,
            title TEXT NOT NULL,
            title_norm TEXT NOT NULL,
            namespace TEXT,
            platform TEXT,
            product TEXT,
            provider TEXT,
            channel TEXT,
            lifecycle TEXT,
            description TEXT NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE identifiers(
            target_id TEXT NOT NULL REFERENCES documents(target_id),
            identifier_type TEXT NOT NULL,
            value TEXT NOT NULL,
            match_value TEXT NOT NULL,
            namespace TEXT NOT NULL,
            case_sensitive INTEGER NOT NULL CHECK(case_sensitive IN (0,1)),
            primary_flag INTEGER NOT NULL CHECK(primary_flag IN (0,1)),
            numeric_semantics INTEGER NOT NULL CHECK(numeric_semantics IN (0,1)),
            derived_numeric_value INTEGER,
            PRIMARY KEY(target_id, identifier_type, value, namespace)
        ) WITHOUT ROWID;

        CREATE TABLE aliases(
            target_id TEXT NOT NULL REFERENCES documents(target_id),
            value TEXT NOT NULL,
            match_value TEXT NOT NULL,
            kind TEXT NOT NULL,
            case_sensitive INTEGER NOT NULL CHECK(case_sensitive IN (0,1)),
            scope_json TEXT NOT NULL,
            PRIMARY KEY(target_id, value, kind)
        ) WITHOUT ROWID;

        CREATE TABLE facets(
            target_id TEXT NOT NULL REFERENCES documents(target_id),
            facet_key TEXT NOT NULL,
            facet_value TEXT NOT NULL,
            facet_value_norm TEXT NOT NULL,
            PRIMARY KEY(target_id, facet_key, facet_value)
        ) WITHOUT ROWID;

        CREATE INDEX idx_ident_match
            ON identifiers(match_value,case_sensitive,identifier_type,namespace,target_id);
        CREATE INDEX idx_ident_numeric
            ON identifiers(namespace,identifier_type,derived_numeric_value,target_id)
            WHERE numeric_semantics=1 AND derived_numeric_value IS NOT NULL;
        CREATE INDEX idx_alias_match ON aliases(match_value,case_sensitive,target_id);
        CREATE INDEX idx_facet_lookup ON facets(facet_key,facet_value_norm,target_id);
        CREATE INDEX idx_document_scope
            ON documents(platform,product,provider,channel,lifecycle,entity_type,namespace,target_id);

        CREATE VIRTUAL TABLE documents_fts USING fts5(
            target_id UNINDEXED,
            title,
            aliases,
            native_identifiers,
            description,
            tokenize='unicode61 remove_diacritics 2'
        );
        """
    )


def _populate(conn: sqlite3.Connection, bundle: Mapping[str, Any]) -> None:
    docs_by_id = {doc["target_id"]: doc for doc in bundle["documents"]}
    aliases_by_id: dict[str, list[str]] = {target_id: [] for target_id in docs_by_id}
    native_by_id: dict[str, list[str]] = {target_id: [] for target_id in docs_by_id}
    for row in bundle["aliases"]:
        aliases_by_id[row["target_id"]].append(row["value"])
    for row in bundle["identifiers"]:
        native_by_id[row["target_id"]].append(row["value"])

    for target_id in sorted(docs_by_id):
        doc = docs_by_id[target_id]
        scope = doc.get("scope") or {}
        lexical = doc.get("lexical_fields") or {}
        title = str(doc["title"])
        description = str(lexical.get("description") or "")
        conn.execute(
            "INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                target_id,
                str(doc["entity_type"]),
                title,
                _fold(title),
                scope.get("namespace"),
                scope.get("platform"),
                scope.get("product"),
                scope.get("provider"),
                scope.get("channel"),
                doc.get("lifecycle"),
                description,
            ),
        )
        conn.execute(
            "INSERT INTO documents_fts VALUES(?,?,?,?,?)",
            (
                target_id,
                title,
                "\n".join(sorted(set(aliases_by_id[target_id]))),
                "\n".join(sorted(set(native_by_id[target_id]))),
                description,
            ),
        )

    for row in sorted(
        bundle["identifiers"],
        key=lambda item: (
            item["target_id"], item["identifier_type"], item["namespace"], item["value"]
        ),
    ):
        value = str(row["value"])
        case_sensitive = bool(row["case_sensitive"])
        conn.execute(
            "INSERT INTO identifiers VALUES(?,?,?,?,?,?,?,?,?)",
            (
                row["target_id"],
                row["identifier_type"],
                value,
                _nfkc(value) if case_sensitive else _fold(value),
                row["namespace"],
                int(case_sensitive),
                int(bool(row.get("primary"))),
                int(bool(row.get("numeric_semantics"))),
                row.get("derived_numeric_value"),
            ),
        )

    for row in sorted(
        bundle["aliases"],
        key=lambda item: (item["target_id"], _fold(item["value"]), item["kind"]),
    ):
        value = str(row["value"])
        case_sensitive = bool(row["case_sensitive"])
        conn.execute(
            "INSERT INTO aliases VALUES(?,?,?,?,?,?)",
            (
                row["target_id"],
                value,
                _nfkc(value) if case_sensitive else _fold(value),
                str(row.get("kind") or "alias"),
                int(case_sensitive),
                json.dumps(
                    row.get("scope") or {},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )

    facet_rows: list[tuple[str, str, str, str]] = []
    for projection in bundle["filters"]:
        target_id = projection["target_id"]
        for key, value in sorted((projection.get("facets") or {}).items()):
            if value is None:
                continue
            text = str(value)
            facet_rows.append((target_id, str(key), text, _fold(text)))
    conn.executemany(
        "INSERT INTO facets(target_id,facet_key,facet_value,facet_value_norm) VALUES(?,?,?,?)",
        sorted(facet_rows),
    )


def build_index(bundle: Mapping[str, Any], output_path: Path) -> dict[str, str]:
    """Build, integrity-bind, and atomically publish a derived SQLite search index."""
    validate_projection_bundle(bundle)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex}.tmp")

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(temp_path)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA page_size=4096")
        _probe_fts5(conn)
        _create_schema(conn)
        _populate(conn, bundle)

        metadata = _base_metadata_for_bundle(bundle)
        metadata["logical_content_digest"] = _logical_content_digest(conn)
        metadata["manifest_digest"] = _digest(metadata)
        conn.executemany(
            "INSERT INTO metadata(key,value) VALUES(?,?)",
            sorted(metadata.items()),
        )
        conn.commit()

        quick = conn.execute("PRAGMA quick_check").fetchone()
        if not quick or quick[0] != "ok":
            raise SearchIndexValidationError(f"new SQLite index failed quick_check: {quick!r}")
        if _logical_content_digest(conn) != metadata["logical_content_digest"]:
            raise SearchIndexValidationError("new SQLite index logical-content digest mismatch")
        conn.close()
        conn = None

        # r+b is required for a valid fsync file descriptor on Windows runners.
        with temp_path.open("r+b") as handle:
            os.fsync(handle.fileno())
        os.replace(temp_path, output_path)
        return metadata
    except SearchIndexValidationError:
        raise
    except (sqlite3.DatabaseError, OSError) as exc:
        raise SearchIndexError(f"failed to build SQLite search index: {exc}") from exc
    finally:
        if conn is not None:
            conn.close()
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _metadata_dict(conn: sqlite3.Connection) -> dict[str, str]:
    try:
        rows = conn.execute("SELECT key,value FROM metadata ORDER BY key").fetchall()
    except sqlite3.DatabaseError as exc:
        raise SearchIndexValidationError("search index metadata is unreadable") from exc
    return {str(row[0]): str(row[1]) for row in rows}


def _verify_metadata(metadata: Mapping[str, str], expected_bundle: Mapping[str, Any]) -> None:
    validate_projection_bundle(expected_bundle)
    required = {
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "index_adapter_id": INDEX_ADAPTER_ID,
        "index_adapter_version": INDEX_ADAPTER_VERSION,
        "search_contract_version": contract.SEARCH_CONTRACT_VERSION,
    }
    for key, expected in required.items():
        if metadata.get(key) != expected:
            raise SearchIndexValidationError(
                f"search index metadata mismatch for {key}: {metadata.get(key)!r} != {expected!r}"
            )

    logical_digest = metadata.get("logical_content_digest")
    if not logical_digest:
        raise SearchIndexValidationError("search index lacks logical_content_digest")
    manifest_digest = metadata.get("manifest_digest")
    unsigned = {key: value for key, value in metadata.items() if key != "manifest_digest"}
    if not manifest_digest or _digest(unsigned) != manifest_digest:
        raise SearchIndexValidationError("search index manifest digest mismatch")

    expected_meta = _base_metadata_for_bundle(expected_bundle)
    binding_keys = {
        "bundle_digest",
        "canonical_corpus_id",
        "canonical_corpus_digest",
        "canonical_schema_version",
        "registry_bundle_version",
        "registry_bundle_digest",
        "projection_profile_version",
        "projection_profile_digest",
        "document_count",
        "identifier_count",
        "alias_count",
        "filter_projection_count",
    }
    for key in sorted(binding_keys):
        if metadata.get(key) != expected_meta.get(key):
            raise SearchIndexValidationError(f"search index is stale or misbound: {key}")


def _verify_logical_content(conn: sqlite3.Connection, metadata: Mapping[str, str]) -> None:
    try:
        actual = _logical_content_digest(conn)
    except sqlite3.DatabaseError as exc:
        raise SearchIndexValidationError("search index logical content is unreadable") from exc
    if actual != metadata.get("logical_content_digest"):
        raise SearchIndexValidationError("search index logical-content digest mismatch")


def _scope_clause(
    scope_hints: Mapping[str, str], document_alias: str = "d"
) -> tuple[str, list[str]]:
    clauses: list[str] = []
    params: list[str] = []
    for key, value in sorted(scope_hints.items()):
        clauses.append(
            f"EXISTS (SELECT 1 FROM facets sf WHERE sf.target_id={document_alias}.target_id "
            "AND sf.facet_key=? AND sf.facet_value_norm=?)"
        )
        params.extend([str(key), _fold(str(value))])
    return " AND ".join(clauses), params


class SQLiteSearchCore:
    """Verified read-only production search runtime for the Phase 5.4 contract."""

    def __init__(self, path: Path, conn: sqlite3.Connection, metadata: Mapping[str, str]):
        self.path = Path(path)
        self.conn = conn
        self.metadata = dict(metadata)

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        expected_bundle: Mapping[str, Any],
    ) -> "SQLiteSearchCore":
        """Open only when the caller supplies the expected authoritative SPC binding."""
        if expected_bundle is None:
            raise SearchIndexValidationError("expected SPC binding is required")
        path = Path(path)
        if not path.is_file():
            raise SearchIndexValidationError(f"search index does not exist: {path}")
        uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            quick = conn.execute("PRAGMA quick_check").fetchone()
            if not quick or quick[0] != "ok":
                raise SearchIndexValidationError(f"SQLite quick_check failed: {quick!r}")
            metadata = _metadata_dict(conn)
            _verify_metadata(metadata, expected_bundle)
            required_tables = {
                "documents",
                "documents_fts",
                "identifiers",
                "aliases",
                "facets",
                "metadata",
            }
            actual_tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
                ).fetchall()
            }
            if not required_tables.issubset(actual_tables):
                raise SearchIndexValidationError("search index schema is incomplete")
            _verify_logical_content(conn, metadata)
            return cls(path, conn, metadata)
        except SearchIndexValidationError:
            if conn is not None:
                conn.close()
            raise
        except sqlite3.DatabaseError as exc:
            if conn is not None:
                conn.close()
            raise SearchIndexValidationError("search index is corrupt or unreadable") from exc
        except Exception:
            if conn is not None:
                conn.close()
            raise

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "SQLiteSearchCore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def manifest(self) -> dict[str, str]:
        return dict(self.metadata)

    def _row_match(
        self, row: sqlite3.Row, matched_value: str, reason: str
    ) -> dict[str, Any]:
        return {
            "target_id": row["target_id"],
            "title": row["title"],
            "entity_type": row["entity_type"],
            "scope": {
                "namespace": row["namespace"],
                "platform": row["platform"],
                "product": row["product"],
                "provider": row["provider"],
                "channel": row["channel"],
            },
            "lifecycle": row["lifecycle"],
            "matched_value": matched_value,
            "match_reason": reason,
        }

    def _envelope(
        self, query: str, stage: str, matches: Iterable[dict[str, Any]]
    ) -> dict[str, Any]:
        rows = list(matches)
        status = "no_match" if not rows else "direct" if len(rows) == 1 else "disambiguation"
        return {
            "search_contract_version": contract.SEARCH_CONTRACT_VERSION,
            "query": query,
            "status": status,
            "match_stage": stage if rows else "none",
            "matches": rows,
        }

    def _select_documents_for_targets(
        self,
        target_values: Sequence[tuple[str, str]],
        reason: str,
    ) -> list[dict[str, Any]]:
        if not target_values:
            return []
        matched_by_target: dict[str, str] = {}
        for target_id, matched in target_values:
            matched_by_target.setdefault(target_id, matched)
        placeholders = ",".join("?" for _ in matched_by_target)
        sql = f"""
            SELECT d.*,
                   COALESCE(pi.identifier_type,'') AS primary_identifier_type,
                   COALESCE(pi.value,'') AS primary_identifier_value
            FROM documents d
            LEFT JOIN identifiers pi
              ON pi.target_id=d.target_id AND pi.primary_flag=1
            WHERE d.target_id IN ({placeholders})
        """
        rows = self.conn.execute(sql, list(matched_by_target)).fetchall()
        rows = sorted(
            rows,
            key=lambda row: (
                _fold(str(row["platform"] or "")),
                _fold(str(row["product"] or "")),
                _fold(str(row["provider"] or "")),
                _fold(str(row["channel"] or "")),
                _fold(str(row["primary_identifier_type"] or "")),
                _fold(str(row["primary_identifier_value"] or "")),
                _fold(str(row["lifecycle"] or "")),
                str(row["target_id"]),
            ),
        )
        return [
            self._row_match(row, matched_by_target[row["target_id"]], reason)
            for row in rows
        ]

    def resolve(
        self,
        query: str,
        *,
        graph_depth: int = 1,
        limit: int = DEFAULT_TOP_K,
    ) -> dict[str, Any]:
        limit = _validate_limit(limit)
        request = contract.parse_query(query, graph_depth=graph_depth)
        normalized = request["normalized_query"]
        if not normalized:
            return self._envelope(query, "none", [])

        canonical = self.conn.execute(
            "SELECT target_id FROM documents WHERE target_id=?", (normalized,)
        ).fetchall()
        if canonical:
            pairs = [(str(row[0]), normalized) for row in canonical]
            return self._envelope(
                query,
                "canonical_identifier",
                self._select_documents_for_targets(pairs, "exact canonical identifier"),
            )

        value_hint = request.get("identifier_value_hint")
        if value_hint is not None:
            scope_sql, scope_params = _scope_clause(request["scope_hints"])
            sql = """
                SELECT i.target_id,i.value
                FROM identifiers i
                JOIN documents d ON d.target_id=i.target_id
                WHERE ((i.case_sensitive=1 AND i.match_value=?)
                    OR (i.case_sensitive=0 AND i.match_value=?))
            """
            params: list[Any] = [_nfkc(value_hint), _fold(value_hint)]
            if request.get("identifier_type_hint"):
                sql += " AND i.identifier_type=?"
                params.append(request["identifier_type_hint"])
            if scope_sql:
                sql += " AND " + scope_sql
                params.extend(scope_params)
            rows = self.conn.execute(sql, params).fetchall()
            if rows:
                pairs = [(str(row["target_id"]), str(row["value"])) for row in rows]
                stage = "scoped_identifier" if request["scope_hints"] else "native_identifier"
                return self._envelope(
                    query,
                    stage,
                    self._select_documents_for_targets(
                        pairs, "registry-aware exact native identifier"
                    ),
                )

        alias_scope_sql, alias_scope_params = _scope_clause(request["scope_hints"])
        alias_sql = """
            SELECT a.target_id,a.value
            FROM aliases a
            JOIN documents d ON d.target_id=a.target_id
            WHERE ((a.case_sensitive=1 AND a.match_value=?)
                OR (a.case_sensitive=0 AND a.match_value=?))
        """
        alias_params: list[Any] = [_nfkc(normalized), _fold(normalized)]
        if alias_scope_sql:
            alias_sql += " AND " + alias_scope_sql
            alias_params.extend(alias_scope_params)
        alias_rows = self.conn.execute(alias_sql, alias_params).fetchall()
        if alias_rows:
            pairs = [(str(row["target_id"]), str(row["value"])) for row in alias_rows]
            return self._envelope(
                query,
                "alias",
                self._select_documents_for_targets(pairs, "exact scoped alias"),
            )

        lexical_text = " ".join(request["terms"])
        tokens = _fts_tokens(lexical_text)
        if not tokens:
            return self._envelope(query, "none", [])
        expression = _fts_expression(tokens)
        scope_sql, scope_params = _scope_clause(request["scope_hints"])
        sql = """
            SELECT d.*, bm25(documents_fts) AS engine_score
            FROM documents_fts
            JOIN documents d ON d.target_id=documents_fts.target_id
            WHERE documents_fts MATCH ?
        """
        params: list[Any] = [expression]
        if scope_sql:
            sql += " AND " + scope_sql
            params.extend(scope_params)
        title_norm = _fold(lexical_text)
        sql += """
            ORDER BY
              engine_score ASC,
              CASE WHEN d.title_norm=? THEN 0 ELSE 1 END ASC,
              d.title_norm ASC,
              d.target_id ASC
            LIMIT ?
        """
        params.extend([title_norm, limit])
        rows = self.conn.execute(sql, params).fetchall()
        matches = [
            self._row_match(row, normalized, "bounded SQLite FTS5 lexical match")
            for row in rows
        ]
        return self._envelope(query, "lexical", matches)

    def numeric_browse(
        self,
        *,
        namespace: str,
        identifier_type: str = "event_id",
        limit: int = DEFAULT_TOP_K,
    ) -> list[dict[str, Any]]:
        limit = _validate_limit(limit)
        rows = self.conn.execute(
            """
            SELECT target_id,value,derived_numeric_value
            FROM identifiers
            WHERE namespace=? AND identifier_type=?
              AND numeric_semantics=1 AND derived_numeric_value IS NOT NULL
            ORDER BY derived_numeric_value ASC,target_id ASC
            LIMIT ?
            """,
            (namespace, identifier_type, limit),
        ).fetchall()
        return [
            {
                "target_id": row["target_id"],
                "value": row["value"],
                "derived_numeric_value": int(row["derived_numeric_value"]),
            }
            for row in rows
        ]


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _bundle_from_fixture(path: Path) -> dict[str, Any]:
    return contract.build_projection_bundle(_load_json(path))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Atlas Phase 5.4.3 SQLite + FTS5 production search core"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build an atomic derived SQLite search index")
    build.add_argument(
        "--fixture",
        type=Path,
        default=Path("fixtures/phase-5.4.1/acceptance-corpus.json"),
    )
    build.add_argument("--output", type=Path, required=True)

    query = sub.add_parser("query", help="query a verified SQLite search index")
    query.add_argument("query")
    query.add_argument("--index", type=Path, required=True)
    query.add_argument(
        "--fixture",
        type=Path,
        default=Path("fixtures/phase-5.4.1/acceptance-corpus.json"),
    )
    query.add_argument("--limit", type=int, default=DEFAULT_TOP_K)

    args = parser.parse_args()
    bundle = _bundle_from_fixture(args.fixture)
    if args.command == "build":
        metadata = build_index(bundle, args.output)
        print(json.dumps(metadata, indent=2, ensure_ascii=False, sort_keys=True))
        return 0

    with SQLiteSearchCore.open(args.index, expected_bundle=bundle) as core:
        result = core.resolve(args.query, limit=args.limit)
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
