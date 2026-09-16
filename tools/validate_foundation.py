#!/usr/bin/env python3
from pathlib import Path
import json
import sys

REQUIRED = [
    "README.md",
    "VERSION",
    "docs/product/product-vision.md",
    "docs/product/product-principles.md",
    "docs/product/personas.md",
    "docs/product/competitive-positioning.md",
    "docs/architecture/system-context.md",
    "docs/architecture/information-architecture.md",
    "docs/architecture/knowledge-graph-model.md",
    "docs/architecture/source-provenance-model.md",
    "docs/architecture/search-architecture.md",
    "docs/architecture/ai-rag-architecture.md",
    "docs/architecture/offline-first-architecture.md",
    "docs/architecture/api-cli-architecture.md",
    "docs/architecture/security-architecture.md",
    "docs/ux/ux-information-architecture.md",
    "docs/mvp/mvp-scope.md",
    "docs/mvp/release-gates.md",
    "docs/roadmap.md",
    "schemas/atlas-node.schema.json",
    "schemas/atlas-edge.schema.json",
]

errors = []

for item in REQUIRED:
    if not Path(item).is_file():
        errors.append(f"Missing required foundation file: {item}")

for schema_path in ("schemas/atlas-node.schema.json", "schemas/atlas-edge.schema.json"):
    try:
        data = json.loads(Path(schema_path).read_text(encoding="utf-8"))
        if data.get("type") != "object":
            errors.append(f"{schema_path}: root type must be object")
        if "$schema" not in data:
            errors.append(f"{schema_path}: missing $schema")
    except Exception as exc:
        errors.append(f"{schema_path}: invalid JSON: {exc}")

for p in Path(".").rglob("*"):
    if not p.is_file() or ".git" in p.parts:
        continue
    if p.suffix.lower() not in {".md", ".json", ".py", ".yml", ".yaml"}:
        continue
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        errors.append(f"{p}: not UTF-8")
        continue
    for i, line in enumerate(text.splitlines(), 1):
        if line.rstrip() != line:
            errors.append(f"{p}:{i}: trailing whitespace")

readme = Path("README.md").read_text(encoding="utf-8")
for required_phrase in (
    "Provenance-First Cyber Defense Knowledge & Investigation Platform",
    "No technical claim without provenance",
    "Repository visibility:** Public",
    "Release state:** Pre-preview / unreleased",
):
    if required_phrase not in readme:
        errors.append(f"README missing required phrase: {required_phrase}")

# The repository is public while the product remains pre-preview. Prevent the
# historical private-development marker from silently returning and making the
# release posture contradictory.
if "Private during active development" in readme:
    errors.append("README contains obsolete private-development visibility marker")

all_docs = "\n".join(
    p.read_text(encoding="utf-8")
    for p in Path("docs").rglob("*.md")
)

if "Microsoft Kusto Query Language (KQL)" not in all_docs:
    errors.append("Foundation must explicitly distinguish Microsoft Kusto Query Language (KQL)")

if "Elastic Kibana Query Language (KQL)" not in all_docs:
    errors.append("Foundation must explicitly distinguish Elastic Kibana Query Language (KQL)")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("Atlas Phase 5.1 foundation validation passed.")
