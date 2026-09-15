#!/usr/bin/env python3
import argparse
import hashlib
import json
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import parse_qs, unquote

MAX_RESPONSE = 8 * 1024 * 1024


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def decode_stream(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    position = 0
    output: list[dict[str, Any]] = []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        value, position = decoder.raw_decode(text, position)
        if not isinstance(value, dict):
            raise ValueError("expected JSON object stream")
        output.append(value)
    return output


def module_graph(args: argparse.Namespace) -> None:
    raw = subprocess.check_output(
        ["go", "list", "-m", "-json", "all"],
        cwd=args.module_root,
        text=True,
        encoding="utf-8",
    )
    rows: list[dict[str, Any]] = []
    for row in decode_stream(raw):
        item: dict[str, Any] = {
            "path": row.get("Path", ""),
            "version": row.get("Version", ""),
            "sum": row.get("Sum", ""),
            "go_version": row.get("GoVersion", ""),
            "main": bool(row.get("Main", False)),
            "indirect": bool(row.get("Indirect", False)),
        }
        replacement = row.get("Replace")
        if isinstance(replacement, dict):
            item["replace"] = {
                "path": replacement.get("Path", ""),
                "version": replacement.get("Version", ""),
                "sum": replacement.get("Sum", ""),
            }
        rows.append(item)
    rows.sort(key=lambda item: (str(item["path"]), str(item["version"])))
    write_json(Path(args.output), {"modules": rows})


def read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        block = stream.read(remaining)
        if not block:
            raise EOFError(f"unexpected EOF reading {size} bytes")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def request(proc: subprocess.Popen[bytes], payload: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("stdio pipes are unavailable")
    proc.stdin.write(struct.pack(">I", len(raw)) + raw)
    proc.stdin.flush()
    size = struct.unpack(">I", read_exact(proc.stdout, 4))[0]
    if size <= 0 or size > MAX_RESPONSE:
        raise RuntimeError(f"invalid response size {size}")
    obj = json.loads(read_exact(proc.stdout, size).decode())
    if not isinstance(obj, dict):
        raise RuntimeError("response must be object")
    return obj


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def stats(values: list[float]) -> dict[str, float]:
    return {
        "min_ms": round(min(values), 3),
        "median_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "max_ms": round(max(values), 3),
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def measure(args: argparse.Namespace) -> None:
    binary = Path(args.binary).resolve()
    starts: list[float] = []
    statuses: list[float] = []
    for index in range(args.iterations):
        start = time.perf_counter_ns()
        proc = subprocess.Popen(
            [str(binary), "--serve-stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            handshake = request(
                proc,
                {
                    "id": f"h{index}",
                    "method": "core.handshake",
                    "params": {
                        "protocol": "atlas-core",
                        "version": "1.0.0",
                        "client_name": "phase554d-evidence",
                        "client_version": "1",
                        "session_nonce": f"phase554d-{index}",
                    },
                },
            )
            handshake_end = time.perf_counter_ns()
            if handshake.get("ok") is not True:
                raise RuntimeError(f"handshake failed: {handshake}")
            status_start = time.perf_counter_ns()
            status = request(proc, {"id": f"s{index}", "method": "core.status", "params": {}})
            status_end = time.perf_counter_ns()
            if status.get("ok") is not True:
                raise RuntimeError(f"status failed: {status}")
            starts.append((handshake_end - start) / 1e6)
            statuses.append((status_end - status_start) / 1e6)
        finally:
            if proc.stdin:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)

    build = subprocess.check_output(
        ["go", "version", "-m", str(binary)], text=True, encoding="utf-8"
    ).splitlines()
    write_json(
        Path(args.output),
        {
            "runner_os": args.runner_os,
            "iterations": args.iterations,
            "binary": {
                "name": binary.name,
                "size_bytes": binary.stat().st_size,
                "sha256": sha256(binary),
                "go_version_m": build,
            },
            "toolchain": subprocess.check_output(
                ["go", "version"], text=True, encoding="utf-8"
            ).strip(),
            "startup_to_handshake": stats(starts),
            "status_roundtrip": stats(statuses),
        },
    )


def flatten(items: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def visit(values: Any) -> None:
        if not isinstance(values, list):
            return
        for value in values:
            if isinstance(value, dict):
                output.append(value)
                visit(value.get("components"))

    visit(items)
    return output


def binary_modules(binary: Path) -> dict[str, str]:
    raw = subprocess.check_output(
        ["go", "version", "-m", str(binary)], text=True, encoding="utf-8"
    )
    modules: dict[str, str] = {}
    for line in raw.splitlines():
        fields = line.strip().split("\t")
        if len(fields) < 3 or fields[0] != "dep":
            continue
        module, version = fields[1], fields[2]
        if module in modules and modules[module] != version:
            raise ValueError(
                f"binary contains conflicting versions for {module}: "
                f"{modules[module]!r} and {version!r}"
            )
        modules[module] = version
    if not modules:
        raise ValueError("binary does not expose any linked Go module dependencies")
    return modules


def sbom_module_identity(component: dict[str, Any]) -> tuple[str, str] | None:
    purl = str(component.get("purl", ""))
    if not purl.startswith("pkg:golang/"):
        return None
    base, _, query = purl.partition("?")
    if "module" not in parse_qs(query).get("type", []):
        return None
    payload = base[len("pkg:golang/") :]
    if "@" not in payload:
        raise ValueError(f"Go module purl has no version: {purl}")
    module, version = payload.rsplit("@", 1)
    module = unquote(module)
    version = unquote(version)
    component_version = str(component.get("version", ""))
    if component_version and component_version != version:
        raise ValueError(
            f"SBOM component version disagrees with purl for {module}: "
            f"{component_version!r} != {version!r}"
        )
    return module, version


def review_sbom(args: argparse.Namespace) -> None:
    source = Path(args.sbom)
    binary = Path(args.binary)
    bom = json.loads(source.read_text(encoding="utf-8"))
    if bom.get("bomFormat") != "CycloneDX":
        raise ValueError("not CycloneDX")
    if str(bom.get("specVersion")) != "1.6":
        raise ValueError(f"unexpected specVersion {bom.get('specVersion')}")

    components = flatten(bom.get("components"))
    if not components:
        raise ValueError("no SBOM components")

    sbom_modules: dict[str, str] = {}
    module_components: dict[str, dict[str, Any]] = {}
    for component in components:
        identity = sbom_module_identity(component)
        if identity is None:
            continue
        module, version = identity
        previous = sbom_modules.get(module)
        if previous is not None and previous != version:
            raise ValueError(
                f"SBOM contains conflicting versions for {module}: {previous!r} and {version!r}"
            )
        sbom_modules[module] = version
        module_components[module] = component

    linked_modules = binary_modules(binary)
    missing = sorted(set(linked_modules) - set(sbom_modules))
    if missing:
        raise ValueError(f"SBOM is missing linked binary modules: {missing}")
    mismatched = sorted(
        (module, linked_modules[module], sbom_modules.get(module, ""))
        for module in linked_modules
        if sbom_modules.get(module) != linked_modules[module]
    )
    if mismatched:
        raise ValueError(f"SBOM linked module version mismatch: {mismatched}")

    missing_license_evidence: list[str] = []
    for module in sorted(linked_modules):
        component = module_components[module]
        evidence = component.get("evidence")
        evidence_licenses = evidence.get("licenses", []) if isinstance(evidence, dict) else []
        licenses = component.get("licenses", [])
        if not licenses and not evidence_licenses:
            missing_license_evidence.append(module)
    if missing_license_evidence:
        raise ValueError(
            "linked third-party modules missing license evidence: "
            f"{missing_license_evidence}"
        )

    inventory: list[dict[str, Any]] = []
    for component in components:
        evidence = component.get("evidence")
        identity = sbom_module_identity(component)
        inventory.append(
            {
                "name": component.get("name", ""),
                "version": component.get("version", ""),
                "purl": component.get("purl", ""),
                "licenses": component.get("licenses", []),
                "license_evidence": evidence.get("licenses", [])
                if isinstance(evidence, dict)
                else [],
                "linked_module": bool(identity and identity[0] in linked_modules),
            }
        )
    inventory.sort(
        key=lambda item: (str(item["name"]), str(item["version"]), str(item["purl"]))
    )
    write_json(
        Path(args.output),
        {
            "sbom": source.name,
            "binary": binary.name,
            "component_count": len(inventory),
            "linked_module_count": len(linked_modules),
            "linked_modules": [
                {"path": module, "version": linked_modules[module]}
                for module in sorted(linked_modules)
            ],
            "components": inventory,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    command = subparsers.add_parser("module-graph")
    command.add_argument("--module-root", required=True)
    command.add_argument("--output", required=True)
    command.set_defaults(func=module_graph)

    command = subparsers.add_parser("measure")
    command.add_argument("--binary", required=True)
    command.add_argument("--runner-os", required=True)
    command.add_argument("--iterations", type=int, default=20)
    command.add_argument("--output", required=True)
    command.set_defaults(func=measure)

    command = subparsers.add_parser("review-sbom")
    command.add_argument("--sbom", required=True)
    command.add_argument("--binary", required=True)
    command.add_argument("--output", required=True)
    command.set_defaults(func=review_sbom)

    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
