#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import catalog_graph

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "phase-5.4.4" / "catalog-graph-corpus.json"


def main() -> int:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    bundle = catalog_graph.build_phase544_bundle(fixture)
    catalog_graph.validate_phase544_bundle(bundle)

    required_queries = {
        "4688": "atlas:event:microsoft.windows.security:4688",
        "Event ID 4688": "atlas:event:microsoft.windows.security:4688",
        "windows 4688": "atlas:event:microsoft.windows.security:4688",
        "sysmon 1": "atlas:event:microsoft.sysmon:1",
        "592": "atlas:event:microsoft.windows.security:592",
        "T1059": "atlas:attack-technique:mitre.attack:t1059",
        "T1059.001": "atlas:attack-technique:mitre.attack:t1059.001",
        "CreateAccessKey": "atlas:operation:aws.cloudtrail.iam:createaccesskey",
        "EXECVE": "atlas:audit-record:linux.audit:execve",
        "exec_start": "atlas:activity:docker.events:container.exec-start",
        "kubectl exec": "atlas:activity:kubernetes.audit:create.pods.exec",
        "FileAccessed": "atlas:activity:microsoft.m365.audit:fileaccessed",
    }

    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "atlas-phase544.sqlite3"
        catalog_graph.search.build_index(bundle, path)
        with catalog_graph.search.SQLiteSearchCore.open(
            path, expected_bundle=bundle
        ) as core:
            runtime = catalog_graph.CatalogGraphRuntime(core, bundle)
            for query, expected in required_queries.items():
                result = core.resolve(query)
                targets = [row["target_id"] for row in result["matches"]]
                if expected not in targets:
                    raise SystemExit(f"required acceptance query failed: {query!r} -> {targets!r}")

            collision = core.resolve("1")
            if collision["status"] != "disambiguation" or len(collision["matches"]) < 2:
                raise SystemExit("bare Event ID collision did not return disambiguation")

            windows = runtime.numeric_event_ids(namespace="microsoft.windows.security")
            if [row["derived_numeric_value"] for row in windows] != [592, 4688]:
                raise SystemExit("numeric Event ID browse is not stable/numeric")

            legacy = runtime.browse(filters={"lifecycle": "legacy"})
            if "atlas:event:microsoft.windows.security:592" not in {
                row["target_id"] for row in legacy
            }:
                raise SystemExit("legacy telemetry disappeared from catalog browse")

            version = runtime.browse(filters={"version": "windows-legacy"})
            if [row["target_id"] for row in version] != [
                "atlas:event:microsoft.windows.security:592"
            ]:
                raise SystemExit("version catalog browse failed")

            graph = runtime.graph_expand(
                ["atlas:activity:synthetic.graph:a"], depth=2, direction="outgoing"
            )
            if [row["target_id"] for row in graph] != [
                "atlas:activity:synthetic.graph:b",
                "atlas:activity:synthetic.graph:c",
            ]:
                raise SystemExit("bounded graph depth-2 expansion failed")

            composed = runtime.resolve_with_graph(
                "atlas:activity:synthetic.graph:a", graph_depth=2
            )
            if composed["search"]["match_stage"] != "canonical_identifier":
                raise SystemExit("graph composition changed search-stage precedence")
            if not composed["graph_pivots"]:
                raise SystemExit("graph composition failed to expose pivots")

    print(
        "Phase 5.4.4 validation passed: "
        f"documents={len(bundle['documents'])} edges={len(bundle['edges'])} "
        f"bundle={bundle['bundle_digest']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
