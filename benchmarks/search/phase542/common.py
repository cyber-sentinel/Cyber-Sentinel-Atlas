from __future__ import annotations

import hashlib, importlib.util, json, math, os, platform, re, statistics, unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "fixtures" / "phase-5.4.1" / "acceptance-corpus.json"
REFERENCE_SEARCH = ROOT / "tools" / "search" / "reference_search.py"
QUERY_SUITE = Path(__file__).with_name("query-suite.json")
MAX_QUERY_SCALARS = 512
MAX_LEXICAL_TERMS = 32
TOP_K = 10


def _load_reference_module():
    spec = importlib.util.spec_from_file_location("atlas_reference_search", REFERENCE_SEARCH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Phase 5.4.1 reference search module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return "sha256-" + hashlib.sha256(canonical_json(value)).hexdigest()


def directory_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def percentile(samples: Sequence[float], p: float) -> float:
    ordered = sorted(samples)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p
    low, high = math.floor(rank), math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def latency_summary(samples: Sequence[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(samples, .50), 4),
        "p95_ms": round(percentile(samples, .95), 4),
        "p99_ms": round(percentile(samples, .99), 4),
        "mean_ms": round(statistics.fmean(samples), 4),
        "max_ms": round(max(samples), 4),
    }


def normalize_bounded_query(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("lexical query must be a string")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError("lexical query contains a non-scalar Unicode surrogate")
    if len(value) > MAX_QUERY_SCALARS:
        raise ValueError(f"lexical query exceeds {MAX_QUERY_SCALARS} Unicode scalar values")
    normalized = unicodedata.normalize("NFKC", value)
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in normalized):
        raise ValueError("normalized lexical query contains a non-scalar Unicode surrogate")
    if len(normalized) > MAX_QUERY_SCALARS:
        raise ValueError(f"normalized lexical query exceeds {MAX_QUERY_SCALARS} Unicode scalar values")
    return normalized


def tokenize_lexical(value: str) -> list[str]:
    normalized = normalize_bounded_query(value)
    terms = [x.casefold() for x in re.findall(r"\w+", normalized, re.UNICODE) if x]
    if len(terms) > MAX_LEXICAL_TERMS:
        raise ValueError(f"lexical request exceeds {MAX_LEXICAL_TERMS} terms")
    return terms


def sqlite_fts_expression(terms: Sequence[str]) -> str:
    return " OR ".join('"' + x.replace('"', '""') + '"' for x in terms)


@dataclass(frozen=True)
class BenchDoc:
    target_id: str
    title: str
    aliases: str
    native_ids: str
    body: str
    namespace: str
    platform: str
    product: str
    provider: str
    channel: str
    lifecycle: str
    numeric_event_id: int | None


def load_base_documents() -> tuple[list[BenchDoc], str]:
    reference = _load_reference_module()
    bundle = reference.build_projection_bundle(json.loads(FIXTURE.read_text(encoding="utf-8")))
    ids: dict[str, list[dict[str, Any]]] = {}
    aliases: dict[str, list[dict[str, Any]]] = {}
    for item in bundle["identifiers"]:
        ids.setdefault(item["target_id"], []).append(item)
    for item in bundle["aliases"]:
        aliases.setdefault(item["target_id"], []).append(item)
    docs = []
    for item in bundle["documents"]:
        tid, scope = item["target_id"], item["scope"]
        target_ids = ids.get(tid, [])
        numeric = [int(x["derived_numeric_value"]) for x in target_ids if x.get("numeric_semantics") and "derived_numeric_value" in x]
        docs.append(BenchDoc(
            tid,
            item["title"],
            " ".join(sorted(x["value"] for x in aliases.get(tid, []))),
            " ".join(sorted(x["value"] for x in target_ids)),
            item["lexical_fields"].get("description") or "",
            str(scope.get("namespace") or ""),
            str(scope.get("platform") or ""),
            str(scope.get("product") or ""),
            str(scope.get("provider") or ""),
            str(scope.get("channel") or ""),
            str(item.get("lifecycle") or ""),
            numeric[0] if numeric else None,
        ))
    return sorted(docs, key=lambda d: d.target_id), bundle["bundle_digest"]


def expand_documents(base: Sequence[BenchDoc], total: int) -> list[BenchDoc]:
    if total < len(base):
        raise ValueError("doc count below acceptance corpus size")
    result = list(base)
    for i in range(total - len(base)):
        seed = base[i % len(base)]
        fanout_term = " benchmarkfanout" if i % 5 == 0 else ""
        result.append(BenchDoc(
            f"atlas:benchmark-noise:{i:08d}",
            f"Benchmark Noise Document {i}",
            f"noise-{i} sourcegroup-{i % 257}",
            "",
            (
                f"Deterministic synthetic corpus scale record {i} telemetry security indexing retrieval "
                f"fieldgroup-{i % 1021} operationgroup-{i % 4093} uniquetoken-{i:08x}{fanout_term}"
            ),
            seed.namespace,
            seed.platform,
            seed.product,
            seed.provider,
            seed.channel,
            seed.lifecycle,
            None,
        ))
    return result


def environment() -> dict[str, Any]:
    memory = None
    p = Path("/proc/meminfo")
    if p.exists():
        for line in p.read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = int(line.split()[1]) * 1024
                break
    return {
        "os": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "memory_bytes": memory,
        "cache_condition": "process-warm repeated queries; OS page cache not flushed; build/open measured separately",
    }
