#!/usr/bin/env python3
"""Engine-neutral Phase 5.4.1 search projection and reference resolver.

This module is deliberately not the production lexical search engine. It freezes
query safety, projection, exact identifier, scope, ambiguity, alias, and numeric
browse semantics so later engine adapters cannot redefine identity resolution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable

SEARCH_CONTRACT_VERSION = "1.0.0"
MAX_QUERY_SCALARS = 512
MAX_TERMS = 32
MAX_FILTERS = 16
MAX_GRAPH_DEPTH = 2

FILTER_KEYS = {
    "platform", "product", "provider", "channel", "namespace",
    "type", "lifecycle", "version",
}

SCOPE_WORDS = {
    "sysmon": {"namespace": "microsoft.sysmon", "product": "sysmon"},
    "windows": {"namespace": "microsoft.windows.security", "platform": "windows"},
}

REFERENCE_REGISTRY_PROFILE = {
    "scope_words": SCOPE_WORDS,
    "numeric_identifier_types": ["event_id"],
    "case_insensitive_identifier_types": ["event_id", "attack_id", "kubernetes_activity"],
}

PROJECTION_PROFILE = {
    "version": "1.0.0",
    "document_fields": ["title", "aliases", "native_identifiers", "description"],
    "exact_precedence": ["canonical_identifier", "native_identifier", "scoped_identifier", "alias"],
    "reference_lexical_only": True,
}


class QueryValidationError(ValueError):
    """Raised when a query violates the bounded public/core query contract."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256-" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _nfkc(value: str) -> str:
    return unicodedata.normalize("NFKC", value)


def _fold(value: str) -> str:
    return _nfkc(value).casefold()


def _match_value(query: str, candidate: str, case_sensitive: bool) -> bool:
    return _nfkc(query) == _nfkc(candidate) if case_sensitive else _fold(query) == _fold(candidate)


def _contains_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def _scope_value(record: dict[str, Any], key: str) -> str | None:
    if key == "namespace":
        return record.get("namespace")
    if key == "type":
        return record.get("entity_type")
    if key == "lifecycle":
        return record.get("lifecycle")
    return (record.get("scope") or {}).get(key)


def _scope_matches(record: dict[str, Any], hints: dict[str, str]) -> bool:
    for key, expected in hints.items():
        actual = _scope_value(record, key)
        if actual is None or _fold(str(actual)) != _fold(str(expected)):
            return False
    return True


def _stable_record_key(record: dict[str, Any]) -> tuple[str, ...]:
    scope = record.get("scope") or {}
    identifiers = record.get("native_identifiers") or []
    primary = next((item for item in identifiers if item.get("primary")), identifiers[0] if identifiers else {})
    return (
        _fold(str(scope.get("platform") or "")),
        _fold(str(scope.get("product") or "")),
        _fold(str(scope.get("provider") or "")),
        _fold(str(scope.get("channel") or "")),
        _fold(str(primary.get("identifier_type") or primary.get("type") or "")),
        _fold(str(primary.get("value") or "")),
        _fold(str(record.get("lifecycle") or "")),
        str(record["id"]),
    )


def parse_query(query: str, *, graph_depth: int = 1) -> dict[str, Any]:
    if not isinstance(query, str):
        raise QueryValidationError("query must be a string")
    if _contains_surrogate(query):
        raise QueryValidationError("query contains an invalid Unicode surrogate")
    if len(query) > MAX_QUERY_SCALARS:
        raise QueryValidationError(f"query exceeds {MAX_QUERY_SCALARS} Unicode scalar values")
    if graph_depth < 0 or graph_depth > MAX_GRAPH_DEPTH:
        raise QueryValidationError(f"graph_depth must be between 0 and {MAX_GRAPH_DEPTH}")

    normalized = re.sub(r"\s+", " ", _nfkc(query).strip())
    raw_terms = normalized.split(" ") if normalized else []
    filters: list[dict[str, str]] = []
    terms: list[str] = []

    for term in raw_terms:
        if ":" in term:
            key, value = term.split(":", 1)
            key_folded = key.casefold()
            if key_folded in FILTER_KEYS and value:
                filters.append({"key": key_folded, "value": value})
                continue
        terms.append(term)

    if len(terms) > MAX_TERMS:
        raise QueryValidationError(f"query exceeds {MAX_TERMS} parsed terms")
    if len(filters) > MAX_FILTERS:
        raise QueryValidationError(f"query exceeds {MAX_FILTERS} structured filters")

    scope_hints: dict[str, str] = {}
    identifier_type_hint: str | None = None
    identifier_value_hint: str | None = None
    scope_hints.update({entry["key"]: entry["value"] for entry in filters})

    if len(terms) >= 2 and terms[0].casefold() in SCOPE_WORDS:
        scope_hints.update(SCOPE_WORDS[terms[0].casefold()])
        if len(terms) == 2:
            identifier_value_hint = terms[1]
    elif len(terms) == 3 and terms[0].casefold() == "event" and terms[1].casefold() == "id":
        identifier_type_hint = "event_id"
        identifier_value_hint = terms[2]
    elif len(terms) == 1:
        identifier_value_hint = terms[0]

    return {
        "search_contract_version": SEARCH_CONTRACT_VERSION,
        "original_query": query,
        "normalized_query": normalized,
        "terms": terms,
        "filters": filters,
        "scope_hints": scope_hints,
        "identifier_type_hint": identifier_type_hint,
        "identifier_value_hint": identifier_value_hint,
        "graph_depth": graph_depth,
    }


def build_projection_bundle(fixture: dict[str, Any]) -> dict[str, Any]:
    records = fixture.get("records")
    if not fixture.get("fixture_only") or not isinstance(records, list) or not records:
        raise ValueError("Phase 5.4.1 projection input must be a non-empty fixture-only record list")

    ids = [record.get("id") for record in records]
    if any(not isinstance(value, str) or not value.startswith("atlas:") for value in ids):
        raise ValueError("all projection seeds require an Atlas canonical target ID")
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate canonical target IDs in projection input")

    documents: list[dict[str, Any]] = []
    identifiers: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    filters: list[dict[str, Any]] = []

    for record in sorted(records, key=lambda item: item["id"]):
        target_id = record["id"]
        native = record.get("native_identifiers") or []
        alias_seed = record.get("aliases") or []
        scope = {
            "namespace": record.get("namespace"),
            "platform": (record.get("scope") or {}).get("platform"),
            "product": (record.get("scope") or {}).get("product"),
            "provider": (record.get("scope") or {}).get("provider"),
            "channel": (record.get("scope") or {}).get("channel"),
        }
        document_without_digest = {
            "search_contract_version": SEARCH_CONTRACT_VERSION,
            "target_id": target_id,
            "entity_type": record["entity_type"],
            "title": record["title"],
            "scope": scope,
            "lifecycle": record.get("lifecycle"),
            "lexical_fields": {
                "title": record["title"],
                "aliases": sorted({item["value"] for item in alias_seed}),
                "native_identifiers": sorted({item["value"] for item in native}),
                "description": record.get("description") or "",
            },
        }
        document = dict(document_without_digest)
        document["projection_digest"] = _digest(document_without_digest)
        documents.append(document)

        for item in native:
            numeric = bool(item.get("numeric_semantics"))
            projected = {
                "search_contract_version": SEARCH_CONTRACT_VERSION,
                "target_id": target_id,
                "identifier_type": item["type"],
                "value": item["value"],
                "namespace": item.get("namespace") or record["namespace"],
                "scope": {key: value for key, value in scope.items() if value is not None},
                "case_sensitive": bool(item.get("case_sensitive")),
                "normalization": "identity" if item.get("case_sensitive") else "unicode-nfkc-casefold",
                "primary": bool(item.get("primary")),
                "numeric_semantics": numeric,
            }
            if numeric:
                if not str(item["value"]).isascii() or not str(item["value"]).isdigit():
                    raise ValueError(f"numeric identifier is not an ASCII decimal integer: {item['value']!r}")
                projected["derived_numeric_value"] = int(item["value"])
            identifiers.append(projected)

        for item in alias_seed:
            aliases.append({
                "search_contract_version": SEARCH_CONTRACT_VERSION,
                "target_id": target_id,
                "value": item["value"],
                "kind": item.get("kind") or "alias",
                "scope": item.get("scope") or {},
                "case_sensitive": bool(item.get("case_sensitive")),
                "normalization": "identity" if item.get("case_sensitive") else "unicode-nfkc-casefold",
                "derivation": "fixture-source-alias",
            })

        filters.append({
            "target_id": target_id,
            "facets": {
                "namespace": record.get("namespace"),
                "platform": scope["platform"],
                "product": scope["product"],
                "provider": scope["provider"],
                "channel": scope["channel"],
                "type": record.get("entity_type"),
                "lifecycle": record.get("lifecycle"),
            },
        })

    identifiers.sort(key=lambda item: (item["namespace"], item["identifier_type"], item["value"], item["target_id"]))
    aliases.sort(key=lambda item: (_fold(item["value"]), item["target_id"]))
    filters.sort(key=lambda item: item["target_id"])

    source_for_digest = sorted(records, key=lambda item: item["id"])
    binding = {
        "canonical_corpus_id": fixture["canonical_corpus_id"],
        "canonical_corpus_digest": _digest(source_for_digest),
        "canonical_schema_version": fixture["canonical_schema_version"],
        "registry_bundle_version": "phase-5.4.1-reference-1",
        "registry_bundle_digest": _digest(REFERENCE_REGISTRY_PROFILE),
        "projection_profile_version": PROJECTION_PROFILE["version"],
        "projection_profile_digest": _digest(PROJECTION_PROFILE),
    }
    bundle_without_digest = {
        "search_contract_version": SEARCH_CONTRACT_VERSION,
        "build_binding": binding,
        "documents": documents,
        "identifiers": identifiers,
        "aliases": aliases,
        "filters": filters,
        "edges": [],
    }
    bundle = dict(bundle_without_digest)
    bundle["bundle_digest"] = _digest(bundle_without_digest)
    return bundle


class ReferenceResolver:
    """Deterministic reference implementation for Phase 5.4.1 contracts."""

    def __init__(self, bundle: dict[str, Any]):
        self.bundle = bundle
        self.documents = {item["target_id"]: item for item in bundle["documents"]}
        self.identifiers = list(bundle["identifiers"])
        self.aliases = list(bundle["aliases"])

    def _seed_for_target(self, target_id: str) -> dict[str, Any]:
        doc = self.documents[target_id]
        identifiers = [item for item in self.identifiers if item["target_id"] == target_id]
        scope = doc["scope"]
        return {
            "id": target_id,
            "entity_type": doc["entity_type"],
            "title": doc["title"],
            "namespace": scope.get("namespace"),
            "scope": {key: value for key, value in scope.items() if key != "namespace"},
            "lifecycle": doc.get("lifecycle"),
            "native_identifiers": identifiers,
        }

    def _make_match(self, target_id: str, matched_value: str, reason: str, *, reference_score: int | None = None) -> dict[str, Any]:
        doc = self.documents[target_id]
        result = {
            "target_id": target_id,
            "title": doc["title"],
            "entity_type": doc["entity_type"],
            "scope": doc["scope"],
            "lifecycle": doc.get("lifecycle"),
            "matched_value": matched_value,
            "match_reason": reason,
        }
        if reference_score is not None:
            result["reference_score"] = reference_score
        return result

    def _envelope(self, query: str, stage: str, target_pairs: Iterable[tuple[str, str]], reason: str) -> dict[str, Any]:
        unique: dict[str, str] = {}
        for target_id, matched in target_pairs:
            unique.setdefault(target_id, matched)
        ordered_ids = sorted(unique, key=lambda target_id: _stable_record_key(self._seed_for_target(target_id)))
        matches = [self._make_match(target_id, unique[target_id], reason) for target_id in ordered_ids]
        status = "no_match" if not matches else "direct" if len(matches) == 1 else "disambiguation"
        return {
            "search_contract_version": SEARCH_CONTRACT_VERSION,
            "query": query,
            "status": status,
            "match_stage": stage if matches else "none",
            "matches": matches,
        }

    def resolve(self, query: str, *, graph_depth: int = 1) -> dict[str, Any]:
        request = parse_query(query, graph_depth=graph_depth)
        normalized = request["normalized_query"]
        if not normalized:
            return self._envelope(query, "none", [], "empty bounded query")

        canonical = [(target_id, normalized) for target_id in self.documents if normalized == target_id]
        if canonical:
            return self._envelope(query, "canonical_identifier", canonical, "exact canonical identifier")

        value_hint = request.get("identifier_value_hint")
        if value_hint is not None:
            exact: list[tuple[str, str]] = []
            for item in self.identifiers:
                if request.get("identifier_type_hint") and item["identifier_type"] != request["identifier_type_hint"]:
                    continue
                doc_seed = self._seed_for_target(item["target_id"])
                if request["scope_hints"] and not _scope_matches(doc_seed, request["scope_hints"]):
                    continue
                if _match_value(value_hint, item["value"], item["case_sensitive"]):
                    exact.append((item["target_id"], item["value"]))
            if exact:
                stage = "scoped_identifier" if request["scope_hints"] else "native_identifier"
                return self._envelope(query, stage, exact, "registry-aware exact native identifier")

        alias_hits: list[tuple[str, str]] = []
        for item in self.aliases:
            if _match_value(normalized, item["value"], item["case_sensitive"]):
                if request["scope_hints"]:
                    doc_seed = self._seed_for_target(item["target_id"])
                    if not _scope_matches(doc_seed, request["scope_hints"]):
                        continue
                alias_hits.append((item["target_id"], item["value"]))
        if alias_hits:
            return self._envelope(query, "alias", alias_hits, "exact scoped alias")

        lexical_terms = [_fold(term) for term in request["terms"] if term]
        lexical_results: list[tuple[int, str]] = []
        if lexical_terms:
            for target_id, doc in self.documents.items():
                seed = self._seed_for_target(target_id)
                if request["scope_hints"] and not _scope_matches(seed, request["scope_hints"]):
                    continue
                fields = doc["lexical_fields"]
                haystack = " ".join([fields["title"], fields["description"], *fields["aliases"], *fields["native_identifiers"]])
                folded = _fold(haystack)
                score = sum(1 for term in lexical_terms if term in folded)
                if score == len(lexical_terms):
                    lexical_results.append((score, target_id))
        if lexical_results:
            lexical_results.sort(key=lambda pair: (-pair[0], _fold(self.documents[pair[1]]["title"]), pair[1]))
            matches = [
                self._make_match(target_id, normalized, "engine-neutral reference lexical containment", reference_score=score)
                for score, target_id in lexical_results
            ]
            return {
                "search_contract_version": SEARCH_CONTRACT_VERSION,
                "query": query,
                "status": "direct" if len(matches) == 1 else "disambiguation",
                "match_stage": "lexical_reference",
                "matches": matches,
            }

        return self._envelope(query, "none", [], "no exact, alias, or reference lexical match")

    def numeric_browse(self, *, namespace: str, identifier_type: str = "event_id") -> list[dict[str, Any]]:
        rows = [
            item for item in self.identifiers
            if item["namespace"] == namespace
            and item["identifier_type"] == identifier_type
            and item["numeric_semantics"]
        ]
        rows.sort(key=lambda item: (item["derived_numeric_value"], item["target_id"]))
        return [
            {"target_id": item["target_id"], "value": item["value"], "derived_numeric_value": item["derived_numeric_value"]}
            for item in rows
        ]


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Atlas Phase 5.4.1 engine-neutral reference resolver")
    parser.add_argument("query")
    parser.add_argument("--fixture", type=Path, default=Path("fixtures/phase-5.4.1/acceptance-corpus.json"))
    args = parser.parse_args()
    bundle = build_projection_bundle(load_fixture(args.fixture))
    result = ReferenceResolver(bundle).resolve(args.query)
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
