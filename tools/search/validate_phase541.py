#!/usr/bin/env python3
"""Permanent Phase 5.4.1 search contract/reference resolver validator."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SEARCH_SCHEMA_ROOT = ROOT / "schemas" / "search" / "v1"
FIXTURE = ROOT / "fixtures" / "phase-5.4.1" / "acceptance-corpus.json"
REFERENCE_MODULE = ROOT / "tools" / "search" / "reference_search.py"
RAW_BASE = "https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/search/v1/"


def load_reference_module():
    spec = importlib.util.spec_from_file_location("atlas_phase541_reference", REFERENCE_MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Phase 5.4.1 reference search module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_search_schemas(bundle, reference):
    schemas = {}
    resources = []
    for path in sorted(SEARCH_SCHEMA_ROOT.glob("*.json")):
        schema = load_json(path)
        expected = RAW_BASE + path.name
        if schema.get("$id") != expected:
            raise AssertionError(f"{path}: unexpected $id {schema.get('$id')!r}; expected {expected!r}")
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
        resources.append((expected, Resource.from_contents(schema)))

    required = {
        "search-document.schema.json",
        "identifier-projection.schema.json",
        "alias-projection.schema.json",
        "search-projection-bundle.schema.json",
        "query-request.schema.json",
        "search-result.schema.json",
    }
    missing = required - set(schemas)
    if missing:
        raise AssertionError(f"missing Phase 5.4.1 search schemas: {sorted(missing)}")

    registry = Registry().with_resources(resources)
    Draft202012Validator(schemas["search-projection-bundle.schema.json"], registry=registry).validate(bundle)
    for document in bundle["documents"]:
        Draft202012Validator(schemas["search-document.schema.json"]).validate(document)
    for identifier in bundle["identifiers"]:
        Draft202012Validator(schemas["identifier-projection.schema.json"]).validate(identifier)
    for alias in bundle["aliases"]:
        Draft202012Validator(schemas["alias-projection.schema.json"]).validate(alias)

    for query in ["4688", "windows 4688", "provider:aws-iam CreateAccessKey", ""]:
        request = reference.parse_query(query)
        Draft202012Validator(schemas["query-request.schema.json"]).validate(request)

    resolver = reference.ReferenceResolver(bundle)
    for query in ["4688", "1", "592", "T1059.001", "kubectl exec", "not-present"]:
        result = resolver.resolve(query)
        Draft202012Validator(schemas["search-result.schema.json"]).validate(result)


def assert_result(resolver, query, *, status, stage, targets, lifecycle=None):
    result = resolver.resolve(query)
    if result["status"] != status:
        raise AssertionError(f"{query!r}: status {result['status']!r} != {status!r}")
    if result["match_stage"] != stage:
        raise AssertionError(f"{query!r}: stage {result['match_stage']!r} != {stage!r}")
    actual = [item["target_id"] for item in result["matches"]]
    if set(actual) != set(targets):
        raise AssertionError(f"{query!r}: targets {actual!r} != {targets!r}")
    if lifecycle is not None and result["matches"][0]["lifecycle"] != lifecycle:
        raise AssertionError(f"{query!r}: lifecycle is not {lifecycle!r}")
    return result


def validate_acceptance(reference, bundle):
    resolver = reference.ReferenceResolver(bundle)
    win4688 = "atlas:event:microsoft.windows.security:4688"
    sysmon1 = "atlas:event:microsoft.sysmon:1"
    synthetic1 = "atlas:event:synthetic.test.provider:1"

    assert_result(resolver, "4688", status="direct", stage="native_identifier", targets=[win4688])
    assert_result(resolver, "Event ID 4688", status="direct", stage="native_identifier", targets=[win4688])
    assert_result(resolver, "windows 4688", status="direct", stage="scoped_identifier", targets=[win4688])
    assert_result(resolver, "sysmon 1", status="direct", stage="scoped_identifier", targets=[sysmon1])

    ambiguous = assert_result(
        resolver,
        "1",
        status="disambiguation",
        stage="native_identifier",
        targets=[sysmon1, synthetic1],
    )
    reverse_fixture = copy.deepcopy(load_json(FIXTURE))
    reverse_fixture["records"] = list(reversed(reverse_fixture["records"]))
    reverse_result = reference.ReferenceResolver(reference.build_projection_bundle(reverse_fixture)).resolve("1")
    if ambiguous != reverse_result:
        raise AssertionError("ambiguous exact resolution changed when source record order was reversed")

    assert_result(
        resolver,
        "592",
        status="direct",
        stage="native_identifier",
        targets=["atlas:event:microsoft.windows.security:592"],
        lifecycle="legacy",
    )
    assert_result(resolver, "T1059", status="direct", stage="native_identifier", targets=["atlas:attack-technique:mitre.attack:t1059"])
    assert_result(resolver, "T1059.001", status="direct", stage="native_identifier", targets=["atlas:attack-technique:mitre.attack:t1059.001"])
    assert_result(resolver, "CreateAccessKey", status="direct", stage="native_identifier", targets=["atlas:operation:aws.cloudtrail.iam:createaccesskey"])
    assert_result(resolver, "EXECVE", status="direct", stage="native_identifier", targets=["atlas:audit-record:linux.audit:execve"])
    assert_result(resolver, "exec_start", status="direct", stage="native_identifier", targets=["atlas:activity:docker.events:container.exec-start"])
    assert_result(resolver, "kubectl exec", status="direct", stage="alias", targets=["atlas:activity:kubernetes.audit:create.pods.exec"])
    assert_result(resolver, "FileAccessed", status="direct", stage="native_identifier", targets=["atlas:activity:microsoft.m365.audit:fileaccessed"])

    browse = resolver.numeric_browse(namespace="microsoft.windows.security")
    if [item["derived_numeric_value"] for item in browse] != [592, 4688]:
        raise AssertionError(f"Windows numeric browse is not numeric and deterministic: {browse!r}")


def validate_determinism(reference, fixture, bundle):
    reversed_fixture = copy.deepcopy(fixture)
    reversed_fixture["records"] = list(reversed(reversed_fixture["records"]))
    rebuilt = reference.build_projection_bundle(reversed_fixture)
    if bundle != rebuilt or bundle["bundle_digest"] != rebuilt["bundle_digest"]:
        raise AssertionError("Search Projection Corpus is not deterministic across input ordering")


def validate_fail_closed(reference, fixture, resolver):
    cases = [
        (lambda: reference.parse_query("x" * 513), "oversized query"),
        (lambda: reference.parse_query(" ".join(["x"] * 33)), "excessive term count"),
        (lambda: reference.parse_query(" ".join([f"platform:x{i}" for i in range(17)])), "excessive filter count"),
        (lambda: reference.parse_query("x", graph_depth=3), "excessive graph depth"),
        (lambda: reference.parse_query("\ud800"), "invalid Unicode surrogate"),
    ]
    for call, label in cases:
        try:
            call()
        except reference.QueryValidationError:
            pass
        else:
            raise AssertionError(f"{label} did not fail closed")

    injection = resolver.resolve('" OR *')
    if injection["status"] not in {"no_match", "direct", "disambiguation"}:
        raise AssertionError("injection-like input escaped the typed search result contract")

    duplicate = copy.deepcopy(fixture)
    duplicate["records"].append(copy.deepcopy(duplicate["records"][0]))
    try:
        reference.build_projection_bundle(duplicate)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate projection seed IDs did not fail closed")

    non_decimal = copy.deepcopy(fixture)
    non_decimal["records"][0]["native_identifiers"][0]["value"] = "0x1250"
    try:
        reference.build_projection_bundle(non_decimal)
    except ValueError:
        pass
    else:
        raise AssertionError("non-decimal value marked numeric did not fail closed")


def main() -> int:
    reference = load_reference_module()
    fixture = load_json(FIXTURE)
    bundle = reference.build_projection_bundle(fixture)
    validate_search_schemas(bundle, reference)
    validate_determinism(reference, fixture, bundle)
    resolver = reference.ReferenceResolver(bundle)
    validate_acceptance(reference, bundle)
    validate_fail_closed(reference, fixture, resolver)
    print(
        "Phase 5.4.1 search validation passed: "
        f"documents={len(bundle['documents'])} identifiers={len(bundle['identifiers'])} "
        f"aliases={len(bundle['aliases'])} digest={bundle['bundle_digest']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
