#!/usr/bin/env python3
"""Phase 5.4.4 catalog, lifecycle/version browse, and bounded graph pivots.

This module deliberately does not select a graph database. Graph adjacency is derived
from the authoritative Search Projection Corpus (SPC) EdgeProjection collection and
kept in memory. SQLite remains the accepted exact/lexical/catalog index from ADR-0022.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import reference_search as contract  # noqa: E402
import sqlite_search as search  # noqa: E402

MAX_GRAPH_SEEDS = 20
MAX_GRAPH_RESULTS = 100
MAX_GRAPH_EDGES = 100_000
MAX_ALLOWED_RELATIONSHIP_TYPES = 32

# Deliberately excludes potentially explosive structural edges such as HAS_FIELD.
DEFAULT_GRAPH_RELATIONSHIP_TYPES = frozenset(
    {
        "RELATED_TO",
        "EQUIVALENT_SIGNAL",
        "SUPERSEDES",
        "SUPERSEDED_BY",
        "VERSION_OF",
        "MAPS_TO_ATTACK",
        "COUNTERED_BY",
        "DETECTED_BY",
        "HUNTED_BY",
        "INVESTIGATED_BY",
        "RESPONDED_BY",
        "REQUIRES_TELEMETRY",
        "HAS_TELEMETRY_PROVIDER",
        "HAS_TELEMETRY_SOURCE",
    }
)


class CatalogGraphValidationError(ValueError):
    """Raised when the Phase 5.4.4 projection/runtime contract is violated."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256-" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _fold(value: str) -> str:
    return search._fold(value)


def _registry_relationship_types() -> frozenset[str]:
    path = ROOT / "model" / "registries" / "relationship-types.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    values = data.get("values") or []
    return frozenset(str(item["value"]) for item in values)


def _stable_edges(edges: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    normalized = [
        {
            "source_id": str(edge["source_id"]),
            "relationship_type": str(edge["relationship_type"]),
            "target_id": str(edge["target_id"]),
        }
        for edge in edges
    ]
    return sorted(
        normalized,
        key=lambda item: (item["source_id"], item["relationship_type"], item["target_id"]),
    )


def build_phase544_bundle(fixture: Mapping[str, Any]) -> dict[str, Any]:
    """Build the Phase 5.4.1 SPC plus optional version facets and EdgeProjections.

    Existing Phase 5.4.1 fixtures remain byte/contract compatible because this helper
    is additive and Phase 5.4.4-specific. When edges exist, the canonical-corpus digest
    is rebound to both records and fixture edge seeds so graph changes cannot reuse an
    older corpus identity.
    """
    base = contract.build_projection_bundle(dict(fixture))
    bundle = copy.deepcopy(base)

    records = fixture.get("records") or []
    record_by_id = {str(record["id"]): record for record in records}
    filter_by_id = {item["target_id"]: item for item in bundle["filters"]}
    for target_id, record in record_by_id.items():
        version = record.get("version")
        if version is not None:
            filter_by_id[target_id]["facets"]["version"] = str(version)

    edges = _stable_edges(fixture.get("edges") or [])
    if len(edges) > MAX_GRAPH_EDGES:
        raise CatalogGraphValidationError(f"edge projection exceeds {MAX_GRAPH_EDGES} rows")
    targets = set(record_by_id)
    registry = _registry_relationship_types()
    seen: set[tuple[str, str, str]] = set()
    for edge in edges:
        source_id = edge["source_id"]
        target_id = edge["target_id"]
        relationship_type = edge["relationship_type"]
        if source_id not in targets or target_id not in targets:
            raise CatalogGraphValidationError("edge projection references a missing target")
        if relationship_type not in registry:
            raise CatalogGraphValidationError(f"unregistered relationship type: {relationship_type}")
        identity = (source_id, relationship_type, target_id)
        if identity in seen:
            raise CatalogGraphValidationError(f"duplicate EdgeProjection: {identity!r}")
        seen.add(identity)
    bundle["edges"] = edges

    if edges:
        corpus_material = {
            "records": sorted(records, key=lambda item: item["id"]),
            "edges": edges,
        }
        bundle["build_binding"]["canonical_corpus_digest"] = _digest(corpus_material)

    unsigned = {key: value for key, value in bundle.items() if key != "bundle_digest"}
    bundle["bundle_digest"] = _digest(unsigned)
    return bundle


def validate_phase544_bundle(bundle: Mapping[str, Any]) -> None:
    search.validate_projection_bundle(bundle)
    edges = bundle.get("edges")
    if not isinstance(edges, list):
        raise CatalogGraphValidationError("SPC edges must be a list")
    if len(edges) > MAX_GRAPH_EDGES:
        raise CatalogGraphValidationError(f"SPC edges exceed {MAX_GRAPH_EDGES}")
    targets = {doc["target_id"] for doc in bundle["documents"]}
    registry = _registry_relationship_types()
    previous: tuple[str, str, str] | None = None
    for edge in edges:
        if not isinstance(edge, Mapping):
            raise CatalogGraphValidationError("EdgeProjection must be an object")
        identity = (
            str(edge.get("source_id") or ""),
            str(edge.get("relationship_type") or ""),
            str(edge.get("target_id") or ""),
        )
        if identity[0] not in targets or identity[2] not in targets:
            raise CatalogGraphValidationError("EdgeProjection references a missing SearchDocument")
        if identity[1] not in registry:
            raise CatalogGraphValidationError(f"unregistered relationship type: {identity[1]}")
        if previous is not None and identity <= previous:
            raise CatalogGraphValidationError("EdgeProjection rows must be unique and deterministically sorted")
        previous = identity


def _validate_filters(filters: Mapping[str, str] | None) -> dict[str, str]:
    if filters is None:
        return {}
    if not isinstance(filters, Mapping):
        raise contract.QueryValidationError("catalog filters must be an object")
    if len(filters) > contract.MAX_FILTERS:
        raise contract.QueryValidationError(f"catalog filters exceed {contract.MAX_FILTERS}")
    allowed = set(contract.FILTER_KEYS)
    normalized: dict[str, str] = {}
    for key, value in filters.items():
        key_text = str(key).casefold()
        if key_text not in allowed:
            raise contract.QueryValidationError(f"unsupported catalog filter: {key}")
        if not isinstance(value, str) or not value:
            raise contract.QueryValidationError(f"catalog filter {key_text} requires a non-empty string")
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise contract.QueryValidationError("catalog filter contains an invalid Unicode surrogate")
        if len(value) > contract.MAX_QUERY_SCALARS:
            raise contract.QueryValidationError("catalog filter value is oversized")
        normalized[key_text] = value
    return normalized


def _stable_document_row(row: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        _fold(str(row.get("platform") or "")),
        _fold(str(row.get("product") or "")),
        _fold(str(row.get("provider") or "")),
        _fold(str(row.get("channel") or "")),
        _fold(str(row.get("lifecycle") or "")),
        _fold(str(row.get("title") or "")),
        str(row.get("target_id") or ""),
    )


class CatalogGraphRuntime:
    """Deterministic catalog and bounded graph view over an activated search core."""

    def __init__(self, core: search.SQLiteSearchCore, bundle: Mapping[str, Any]):
        validate_phase544_bundle(bundle)
        if core.manifest().get("bundle_digest") != bundle.get("bundle_digest"):
            raise CatalogGraphValidationError("catalog/graph runtime is not bound to the activated SPC")
        self.core = core
        self.bundle = dict(bundle)
        self.documents = {doc["target_id"]: doc for doc in bundle["documents"]}
        self._outgoing: dict[str, list[dict[str, str]]] = defaultdict(list)
        self._incoming: dict[str, list[dict[str, str]]] = defaultdict(list)
        for edge in bundle["edges"]:
            item = dict(edge)
            self._outgoing[item["source_id"]].append(item)
            self._incoming[item["target_id"]].append(item)
        for adjacency in (self._outgoing, self._incoming):
            for target_id in adjacency:
                adjacency[target_id].sort(
                    key=lambda item: (item["relationship_type"], item["source_id"], item["target_id"])
                )

    def browse(
        self,
        *,
        filters: Mapping[str, str] | None = None,
        limit: int = search.DEFAULT_TOP_K,
    ) -> list[dict[str, Any]]:
        """Browse provider/source/lifecycle/version facets without using FTS syntax."""
        limit = search._validate_limit(limit)
        normalized = _validate_filters(filters)
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in sorted(normalized.items()):
            clauses.append(
                "EXISTS (SELECT 1 FROM facets f WHERE f.target_id=d.target_id "
                "AND f.facet_key=? AND f.facet_value_norm=?)"
            )
            params.extend([key, _fold(value)])
        sql = "SELECT d.* FROM documents d"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY d.platform,d.product,d.provider,d.channel,d.lifecycle,d.title_norm,d.target_id LIMIT ?"
        params.append(limit)
        rows = self.core.conn.execute(sql, params).fetchall()
        return [
            {
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
            }
            for row in rows
        ]

    def facet_values(
        self,
        facet_key: str,
        *,
        filters: Mapping[str, str] | None = None,
        limit: int = search.MAX_TOP_K,
    ) -> list[dict[str, Any]]:
        """Return deterministic catalog values/counts for a controlled facet."""
        limit = search._validate_limit(limit)
        key = str(facet_key).casefold()
        if key not in contract.FILTER_KEYS:
            raise contract.QueryValidationError(f"unsupported catalog facet: {facet_key}")
        normalized = _validate_filters(filters)
        clauses = ["f.facet_key=?"]
        params: list[Any] = [key]
        for filter_key, value in sorted(normalized.items()):
            clauses.append(
                "EXISTS (SELECT 1 FROM facets sf WHERE sf.target_id=f.target_id "
                "AND sf.facet_key=? AND sf.facet_value_norm=?)"
            )
            params.extend([filter_key, _fold(value)])
        sql = (
            "SELECT f.facet_value,COUNT(DISTINCT f.target_id) AS item_count FROM facets f WHERE "
            + " AND ".join(clauses)
            + " GROUP BY f.facet_value,f.facet_value_norm "
              "ORDER BY f.facet_value_norm ASC,f.facet_value ASC LIMIT ?"
        )
        params.append(limit)
        return [
            {"value": row["facet_value"], "item_count": int(row["item_count"])}
            for row in self.core.conn.execute(sql, params).fetchall()
        ]

    def numeric_event_ids(
        self,
        *,
        namespace: str,
        limit: int = search.DEFAULT_TOP_K,
    ) -> list[dict[str, Any]]:
        return self.core.numeric_browse(namespace=namespace, identifier_type="event_id", limit=limit)

    def graph_expand(
        self,
        seed_ids: Sequence[str],
        *,
        depth: int = 1,
        allowed_relationship_types: Iterable[str] | None = None,
        direction: str = "both",
        limit: int = MAX_GRAPH_RESULTS,
    ) -> list[dict[str, Any]]:
        """Bounded BFS over derived EdgeProjections with deterministic dedupe/order."""
        if isinstance(seed_ids, (str, bytes)) or not isinstance(seed_ids, Sequence):
            raise contract.QueryValidationError("graph seed_ids must be a sequence")
        if not seed_ids or len(seed_ids) > MAX_GRAPH_SEEDS:
            raise contract.QueryValidationError(f"graph seed count must be between 1 and {MAX_GRAPH_SEEDS}")
        if depth < 0 or depth > contract.MAX_GRAPH_DEPTH:
            raise contract.QueryValidationError(
                f"graph depth must be between 0 and {contract.MAX_GRAPH_DEPTH}"
            )
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_GRAPH_RESULTS:
            raise contract.QueryValidationError(f"graph limit must be between 1 and {MAX_GRAPH_RESULTS}")
        if direction not in {"outgoing", "incoming", "both"}:
            raise contract.QueryValidationError("graph direction must be outgoing, incoming, or both")

        seeds = sorted({str(value) for value in seed_ids})
        if any(seed not in self.documents for seed in seeds):
            raise contract.QueryValidationError("graph seed is not present in the active SPC")

        registry = _registry_relationship_types()
        if allowed_relationship_types is None:
            allowed = set(DEFAULT_GRAPH_RELATIONSHIP_TYPES)
        else:
            allowed = {str(value) for value in allowed_relationship_types}
        if not allowed or len(allowed) > MAX_ALLOWED_RELATIONSHIP_TYPES:
            raise contract.QueryValidationError("invalid allowed relationship-type set")
        unknown = allowed - registry
        if unknown:
            raise contract.QueryValidationError(f"unregistered graph relationship types: {sorted(unknown)}")

        if depth == 0:
            return []

        visited = set(seeds)
        queue: deque[tuple[str, int]] = deque((seed, 0) for seed in seeds)
        discovered: list[dict[str, Any]] = []
        while queue and len(discovered) < limit:
            current, current_depth = queue.popleft()
            if current_depth >= depth:
                continue
            candidates: list[tuple[str, dict[str, str], str]] = []
            if direction in {"outgoing", "both"}:
                candidates.extend((edge["target_id"], edge, "outgoing") for edge in self._outgoing.get(current, []))
            if direction in {"incoming", "both"}:
                candidates.extend((edge["source_id"], edge, "incoming") for edge in self._incoming.get(current, []))
            candidates.sort(
                key=lambda item: (item[1]["relationship_type"], item[2], item[0], item[1]["source_id"], item[1]["target_id"])
            )
            for neighbor, edge, edge_direction in candidates:
                if edge["relationship_type"] not in allowed or neighbor in visited:
                    continue
                visited.add(neighbor)
                next_depth = current_depth + 1
                doc = self.documents[neighbor]
                discovered.append(
                    {
                        "target_id": neighbor,
                        "title": doc["title"],
                        "entity_type": doc["entity_type"],
                        "depth": next_depth,
                        "via_id": current,
                        "relationship_type": edge["relationship_type"],
                        "direction": edge_direction,
                    }
                )
                if len(discovered) >= limit:
                    break
                queue.append((neighbor, next_depth))
        return discovered

    def resolve_with_graph(
        self,
        query: str,
        *,
        graph_depth: int = 1,
        limit: int = search.DEFAULT_TOP_K,
    ) -> dict[str, Any]:
        """Compose search + graph pivots without allowing graph to outrank search."""
        result = self.core.resolve(query, graph_depth=graph_depth, limit=limit)
        seeds = [match["target_id"] for match in result["matches"]]
        pivots = self.graph_expand(seeds, depth=graph_depth, limit=limit) if seeds and graph_depth else []
        return {
            "search_contract_version": contract.SEARCH_CONTRACT_VERSION,
            "search": result,
            "graph_pivots": pivots,
        }
