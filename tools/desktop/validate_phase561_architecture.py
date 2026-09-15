#!/usr/bin/env python3
"""Static validator for Phase 5.6.1 Windows Desktop technology-selection boundary."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARCH = ROOT / "docs" / "architecture" / "phase-5.6.1-windows-desktop-technology-spike.md"
ADR = ROOT / "docs" / "adr" / "0026-windows-desktop-technology-selection.md"
PLAN = ROOT / "benchmarks" / "desktop" / "phase561" / "evaluation-plan.json"
STATE = ROOT / "docs" / "project-state.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
CURRENT = ROOT / "docs" / "current-status.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    for path in (ARCH, ADR, PLAN, STATE, ROADMAP, CURRENT):
        require(path.is_file(), f"missing Phase 5.6.1 artifact: {path.relative_to(ROOT)}")

    arch = ARCH.read_text(encoding="utf-8")
    adr = ADR.read_text(encoding="utf-8")
    state = STATE.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    current = CURRENT.read_text(encoding="utf-8")
    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    require("Status: **EVIDENCE SPIKE AUTHORIZED / DECISION PENDING**" in arch, "Phase 5.6.1 architecture status drifted")
    require("**Status:** Proposed — Evidence Pending" in adr, "ADR-0026 must remain Proposed while evidence is incomplete")
    require("Decision to be made after executable Phase 5.6.1 evidence" in adr, "ADR-0026 prematurely selected a framework")
    require("no Windows Desktop framework is selected" in arch, "architecture artifact must explicitly preserve decision-pending state")

    for phrase in (
        "atlas-core --serve-stdio",
        "protocol `1.0.0`",
        "No candidate may import production Go Shared Core packages directly",
        "No candidate may introduce localhost HTTP/TCP",
        "Critical/high vulnerabilities",
        "ATLAS-CI-WIN01",
    ):
        require(phrase in arch, f"Phase 5.6.1 architecture invariant missing: {phrase}")

    require(plan.get("plan_version") == "1.0.0", "unexpected Phase 5.6.1 evaluation plan version")
    require(plan.get("phase") == "5.6.1", "Phase 5.6.1 evaluation plan phase mismatch")
    require(plan.get("selection_status") == "evidence-pending", "selection must remain evidence-pending")
    require(plan.get("decision_adr") == "ADR-0026", "evaluation plan ADR mismatch")

    candidates = plan.get("candidates", [])
    candidate_ids = {candidate.get("id") for candidate in candidates}
    require(candidate_ids == {"tauri2", "electron", "wails-stable", "winui3"}, "candidate set drifted")
    require(all(candidate.get("round1_required") is True for candidate in candidates), "all four candidates must enter R1")

    hard_gates = plan.get("hard_gates", [])
    gate_ids = {gate.get("id") for gate in hard_gates}
    require(len(hard_gates) == 12, "all twelve Phase 5.6.1 hard gates are required")
    require(gate_ids == {f"G-DT{i}" for i in range(1, 13)}, "Phase 5.6.1 hard-gate identifiers drifted")

    expected_fast_fail = {"G-DT1", "G-DT2", "G-DT3", "G-DT4", "G-DT7", "G-DT9", "G-DT10"}
    require(set(plan.get("fast_fail_gates", [])) == expected_fast_fail, "fast-fail gate set drifted")

    weights = plan.get("score_weights", {})
    require(sum(weights.values()) == 100, "Desktop technology decision weights must total 100")

    version_policy = plan.get("version_policy", {})
    require(version_policy.get("accepted_baseline_must_pin_exact_versions") is True, "accepted baseline must pin exact versions")
    require(version_policy.get("latest_tags_allowed_in_accepted_baseline") is False, "mutable latest tags must remain forbidden")
    require(version_policy.get("lockfiles_required") is True, "candidate lockfiles are mandatory")

    measurements = plan.get("measurement_policy", {})
    require(measurements.get("same_atlas_core_binary_for_all_candidates") is True, "all candidates must use the same atlas-core binary")
    require(measurements.get("same_smoke_corpus_for_all_candidates") is True, "all candidates must use the same smoke corpus")
    require(measurements.get("same_windows_runner_class") is True, "comparative measurements require the same Windows runner class")
    require(measurements.get("measured_launches_minimum", 0) >= 5, "at least five measured launches are required")
    require(measurements.get("network_denial_must_be_explicit") is True, "offline evidence must use explicit network denial")

    acceptance = plan.get("acceptance", {})
    require(acceptance.get("all_hard_gates_require_resolved_evidence") is True, "all mandatory gates must resolve")
    require(acceptance.get("adr_must_remain_proposed_until_evidence_complete") is True, "ADR acceptance must remain evidence-gated")
    require(acceptance.get("architecture_authority_acceptance_required") is True, "Architecture Authority acceptance remains required")

    for text, name in ((state, "project-state"), (roadmap, "roadmap"), (current, "current-status")):
        require("Phase 5.6" in text, f"{name} missing Phase 5.6")
        require("5.6.1" in text, f"{name} missing Phase 5.6.1")

    require("Phase 5.6.1 — Desktop Technology Spike + ADR-0026: **AUTHORIZED / NEXT**" in state, "project-state must authorize Phase 5.6.1 without selecting a stack")
    require("Windows Desktop implementation stack — to be selected by Phase 5.6.1 / ADR-0026" in state, "project-state must keep Desktop technology open")
    require("No Desktop stack is accepted until the spike evidence and ADR-0026 pass review and CI." in current, "current-status must preserve evidence-gated Desktop selection")
    require("Status: **AUTHORIZED / NEXT**" in roadmap, "roadmap must identify Phase 5.6.1 as next")

    print("Phase 5.6.1 Desktop technology architecture gate: PASS (evidence pending)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
