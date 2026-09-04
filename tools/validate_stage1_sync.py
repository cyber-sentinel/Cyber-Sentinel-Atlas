#!/usr/bin/env python3
from pathlib import Path
import re
import sys

errors = []

required = [
    "docs/project-state.md",
    "docs/roadmap.md",
    "docs/architecture/api-cli-architecture.md",
    "docs/architecture/knowledge-graph-model.md",
    "docs/architecture/offline-first-architecture.md",
    "docs/architecture/canonical-identifier-architecture.md",
    "docs/architecture/universal-telemetry-taxonomy.md",
    "docs/architecture/coverage-model.md",
    "docs/architecture/content-release-pipeline.md",
    "docs/architecture/telemetry-lifecycle.md",
    "docs/adr/0001-canonical-vendor-neutral-model.md",
    "docs/adr/0002-claim-level-provenance.md",
    "docs/adr/0003-offline-first.md",
    "docs/adr/0004-ecosystem-ownership-atlas-defenseops-forge.md",
    "docs/adr/0005-canonical-identifier-architecture.md",
    "docs/adr/0006-shared-core-and-interface-sequencing.md",
    "docs/adr/0007-universal-telemetry-taxonomy.md",
    "docs/adr/0008-coverage-measurement-model.md",
    "docs/adr/0009-controlled-content-release-pipeline.md",
    "docs/adr/0010-telemetry-lifecycle-and-legacy-preservation.md",
]

for item in required:
    if not Path(item).exists():
        errors.append(f"Missing Stage 1 artifact: {item}")

def read(path):
    return Path(path).read_text(encoding="utf-8")

readme = read("README.md")
roadmap = read("docs/roadmap.md")
state = read("docs/project-state.md")
gates = read("docs/mvp/release-gates.md")
api_cli = read("docs/architecture/api-cli-architecture.md")
ids = read("docs/architecture/canonical-identifier-architecture.md")
taxonomy = read("docs/architecture/universal-telemetry-taxonomy.md")
coverage = read("docs/architecture/coverage-model.md")
pipeline = read("docs/architecture/content-release-pipeline.md")
lifecycle = read("docs/architecture/telemetry-lifecycle.md")

# Stage 1 regression invariants must remain true even after later phases start.
if "Phase 5.1" not in readme or "COMPLETE" not in readme:
    errors.append("README must retain Phase 5.1 COMPLETE status")

if "Stage 1" not in readme or "COMPLETE" not in readme:
    errors.append("README must retain Stage 1 COMPLETE status")

phase51_block = roadmap.split("## Phase 5.1 — Product Foundation", 1)
if len(phase51_block) != 2 or "Status: **COMPLETE**" not in phase51_block[1].split("## Stage 1", 1)[0]:
    errors.append("Roadmap must retain Phase 5.1 COMPLETE")

stage1_block = roadmap.split("## Stage 1 — Governance / Architecture Sync", 1)
if len(stage1_block) != 2 or "Status: **COMPLETE**" not in stage1_block[1].split("## Phase 5.2", 1)[0]:
    errors.append("Roadmap must retain Stage 1 COMPLETE")

if "## Phase 5.2 — Canonical Data Model" not in roadmap:
    errors.append("Roadmap must retain the Phase 5.2 section")

if "Phase 5.1 — Product Foundation: **COMPLETE**" not in state:
    errors.append("project-state must retain Phase 5.1 COMPLETE")

if "Stage 1 — Governance / Architecture Sync: **COMPLETE**" not in state:
    errors.append("project-state must retain Stage 1 COMPLETE")

if "Phase 5.2 — Canonical Data Model:" not in state:
    errors.append("project-state must contain Phase 5.2 status")

if not re.search(r"Last Reviewed Main SHA: `[0-9a-f]{40}`", state):
    errors.append("project-state must record a 40-character Last Reviewed Main SHA")

if "Architecture Sync Status: **GREEN**" not in state:
    errors.append("project-state must retain GREEN architecture sync status")

stage1_gate_lines = [
    line for line in gates.splitlines()
    if line.startswith("- [ ]") and any(term in line for term in (
        "project-state.md", "Phase 5.1 consistently", "Atlas / DefenseOps / Forge",
        "Canonical identifier", "Shared-core/Desktop/Web", "Universal telemetry",
        "Coverage architecture", "Controlled content release", "Legacy/current",
        "ADR-0004 through ADR-0010"
    ))
]
if stage1_gate_lines:
    errors.append("Stage 1 release gates must remain closed: " + "; ".join(stage1_gate_lines))

# Ecosystem ownership.
if "The former Sentinel Forge CLI concept becomes an Atlas interface." in api_cli:
    errors.append("Legacy Forge ownership statement still present")

for phrase in (
    "Cyber-Sentinel-Forge is retired",
    "DefenseOps is an approved engineering source for Atlas",
    "official user-facing command is",
):
    if phrase not in api_cli:
        errors.append(f"API/CLI architecture missing ownership phrase: {phrase}")

if "`atlas`" not in api_cli:
    errors.append("Official atlas CLI command is not recorded")

# Canonical ID contract and cross-domain conceptual validation.
for phrase in (
    "atlas:<entity-type>:<namespace>:<canonical-key>",
    "atlas:event:microsoft.windows.security:4688",
    "atlas:event:microsoft.sysmon:1",
    "atlas:audit-record:linux.audit:execve",
    "atlas:operation:aws.cloudtrail.iam:createaccesskey",
    "atlas:activity:kubernetes.audit:create.pods.exec",
    "atlas:audit-action:mongodb.audit:authcheck",
):
    if phrase not in ids:
        errors.append(f"Canonical ID architecture missing required example/contract: {phrase}")

# Universal telemetry taxonomy.
for phrase in (
    "TelemetryProvider",
    "TelemetrySource",
    "TelemetryRecordType",
    "Event",
    "AuditRecord",
    "Operation",
    "Activity",
    "Finding",
    "FlowRecord",
):
    if phrase not in taxonomy:
        errors.append(f"Universal telemetry taxonomy missing: {phrase}")

if "vendor-specific root abstraction" not in taxonomy:
    errors.append("Universal taxonomy must explicitly reject vendor-specific root abstraction")

# Coverage requirements.
for phrase in (
    "Telemetry Coverage != Detection Coverage",
    "denominator",
    "version",
):
    if phrase not in coverage:
        errors.append(f"Coverage architecture missing requirement: {phrase}")

# Controlled publication and rollback.
for phrase in (
    "Official Source",
    "Raw Snapshot",
    "Parser",
    "Normalizer",
    "Schema Validation",
    "Inventory Diff",
    "Tests",
    "Human Review",
    "Signed Content Pack",
    "Manifest Verification",
    "Signature Verification",
    "Checksum Verification",
    "Preserve Last Known Good",
    "Atomic Install",
    "Health Check",
    "Rollback to Last Known Good",
):
    if phrase not in pipeline:
        errors.append(f"Content release pipeline missing stage: {phrase}")

# Lifecycle preservation.
for phrase in (
    "current",
    "legacy",
    "deprecated",
    "superseded",
    "retired",
    "SUPERSEDES",
    "SUPERSEDED_BY",
    "EQUIVALENT_SIGNAL",
    "VERSION_OF",
    "RELATED_TO",
):
    if phrase not in lifecycle:
        errors.append(f"Telemetry lifecycle missing: {phrase}")

# ADR-0001 through ADR-0010 must all remain Accepted.
for i in range(1, 11):
    candidates = sorted(Path("docs/adr").glob(f"{i:04d}-*.md"))
    if len(candidates) != 1:
        errors.append(f"Expected exactly one ADR-{i:04d} file, found {len(candidates)}")
        continue
    text = read(candidates[0])
    if "**Status:** Accepted" not in text:
        errors.append(f"ADR-{i:04d} must remain Accepted")

# Preserve core decisions of ADR-0001..0003.
accepted_checks = {
    "docs/adr/0001-canonical-vendor-neutral-model.md": "vendor becomes the domain model",
    "docs/adr/0002-claim-level-provenance.md": "Material technical claims are first-class records",
    "docs/adr/0003-offline-first.md": "signed, local knowledge packs and deterministic local search",
}
for path, decision_phrase in accepted_checks.items():
    text = read(path)
    if decision_phrase not in text:
        errors.append(f"Existing accepted ADR changed unexpectedly: {path}")

# Internal Markdown links must resolve locally.
link_re = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
for path in [Path("README.md"), *Path("docs").rglob("*.md")]:
    text = path.read_text(encoding="utf-8")
    for target in link_re.findall(text):
        target = target.strip().strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        target = target.split("#", 1)[0].split("?", 1)[0]
        if not target:
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            errors.append(f"Broken internal link: {path} -> {target}")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("Atlas Stage 1 architecture/governance regression validation passed.")
