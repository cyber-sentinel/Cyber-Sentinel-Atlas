#!/usr/bin/env python3
"""Static closure validator for the Phase 5.5.3 Shared Core architecture gate."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARCH = ROOT / "docs" / "architecture" / "phase-5.5.3-shared-core-technology-spike.md"
ADR = ROOT / "docs" / "adr" / "0024-production-shared-core-technology-selection.md"
PLAN = ROOT / "benchmarks" / "shared-core" / "phase553" / "evaluation-plan.json"
STATE = ROOT / "docs" / "project-state.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
CURRENT = ROOT / "docs" / "current-status.md"
HISTORY_STATE = ROOT / "docs" / "history" / "project-state-phase53-snapshot.md"
HISTORY_ROADMAP = ROOT / "docs" / "history" / "roadmap-pre-phase54-snapshot.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    for path in (ARCH, ADR, PLAN, STATE, ROADMAP, CURRENT, HISTORY_STATE, HISTORY_ROADMAP):
        require(path.is_file(), f"missing Phase 5.5.3 architecture artifact: {path.relative_to(ROOT)}")

    arch = ARCH.read_text(encoding="utf-8")
    adr = ADR.read_text(encoding="utf-8")
    state = STATE.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    current = CURRENT.read_text(encoding="utf-8")
    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    require("Status: **ARCHITECTURE GATE / SPIKE AUTHORIZED**" in arch, "Phase 5.5.3 architecture status missing")
    proposed = "**Status:** Proposed" in adr
    accepted = "**Status:** Accepted" in adr
    require(proposed ^ accepted, "ADR-0024 must be exactly Proposed or Accepted")
    if accepted:
        require("**Select Go as the production Atlas Shared Core implementation family.**" in adr, "accepted ADR-0024 must select Go")
        require("Accepted by Architecture Authority" in adr, "accepted ADR-0024 must record Architecture Authority acceptance")
    else:
        require("Go proposed" in adr or "Decision to be made" in adr, "Proposed ADR-0024 must preserve an explicit pending decision")

    require("No candidate may gain points by changing a frozen contract." in arch, "contract-fidelity invariant missing")
    require("No serialization/hashing migration occurs in Phase 5.5.3" in arch, "serialization migration guard missing")

    require(plan.get("plan_version") == "1.0.0", "unexpected Phase 5.5.3 evaluation plan version")
    require(plan.get("phase") == "5.5.3", "evaluation plan phase mismatch")
    require(plan.get("production_selection_frozen") is False, "evaluation plan must remain a pre-selection evidence contract")
    require(sum(plan.get("score_weights", {}).values()) == 100, "Shared Core decision weights must total 100")
    require(set(plan.get("initial_executable_finalists", [])) == {"rust", "go", "python-control"}, "initial executable finalist set drifted")
    require(len(plan.get("hard_gates", [])) == 8, "all eight Shared Core hard gates are required")
    require(set(plan.get("required_operating_systems", [])) == {"windows-latest", "ubuntu-latest"}, "Linux/Windows evidence is mandatory")
    require(plan.get("serialization_gate", {}).get("migration_allowed_in_spike") is False, "serialization migration must remain blocked")

    for phrase in (
        "Phase 5.4 — Deterministic Search Core: **COMPLETE / MERGED**",
        "Phase 5.5.2 — Verified Pack Runtime: **COMPLETE / MERGED / POST-MERGE VERIFIED**",
        "Phase 5.5.3 — Production Shared Core Technology Spike: **ARCHITECTURE GATE / SPIKE AUTHORIZED**",
        "Architecture Sync Status: **GREEN**",
        "ADR-0024 — Production Shared Core Technology Selection",
    ):
        require(phrase in state, f"project-state missing current architecture phrase: {phrase}")

    for phrase in (
        "## Phase 5.4 — Deterministic Search Core",
        "Status: **COMPLETE / MERGED**",
        "### Phase 5.5.3 — Production Shared Core Technology Spike",
        "Status: **ARCHITECTURE GATE / SPIKE AUTHORIZED**",
        "## Phase 5.6 — Windows Desktop MVP",
    ):
        require(phrase in roadmap, f"roadmap missing current phase invariant: {phrase}")

    pre_selection_status = "Production Shared Core technology spike / ADR: **NEXT**" in current
    post_selection_status = "Go" in current and ("Shared Core" in current or "5.5.3" in current)
    require(pre_selection_status or post_selection_status, "current-status must describe the Shared Core selection/implementation boundary")

    require("Tauri, Rust, SQLite, React, and TypeScript remain candidates only." in HISTORY_STATE.read_text(encoding="utf-8"), "historical state snapshot was not preserved byte-for-content")
    require("Status: **NOT STARTED**" in HISTORY_ROADMAP.read_text(encoding="utf-8"), "historical roadmap snapshot was not preserved")

    canonical = ROOT / "schemas" / "v1"
    require(canonical.is_dir(), "canonical schemas/v1 missing")
    require(not (canonical / "shared-core.schema.json").exists(), "Shared Core architecture leaked into canonical schema family")

    print(f"Phase 5.5.3 Shared Core architecture gate: PASS ({'Accepted' if accepted else 'Proposed'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
