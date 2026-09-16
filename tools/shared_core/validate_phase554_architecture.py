#!/usr/bin/env python3
"""Static validator for the Phase 5.5.4 Production Go Shared Core architecture gate."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADR = ROOT / "docs" / "adr" / "0025-shared-core-local-interface-boundary.md"
ARCH = ROOT / "docs" / "architecture" / "phase-5.5.4-production-go-shared-core.md"
STATE = ROOT / "docs" / "project-state.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
CURRENT = ROOT / "docs" / "current-status.md"
CANONICAL = ROOT / "schemas" / "v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    for path in (ADR, ARCH, STATE, ROADMAP, CURRENT):
        require(path.is_file(), f"missing Phase 5.5.4 architecture artifact: {path.relative_to(ROOT)}")

    adr = ADR.read_text(encoding="utf-8")
    arch = ARCH.read_text(encoding="utf-8")
    state = STATE.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    current = CURRENT.read_text(encoding="utf-8")

    require("**Status:** Accepted — Architecture Authority approved 2026-09-06" in adr, "ADR-0025 must be Accepted")
    for phrase in (
        "local child-process stdio protocol",
        "4-byte unsigned big-endian payload length",
        "maximum request payload: **1 MiB**",
        "maximum response payload: **8 MiB**",
        "duplicate JSON object member names are rejected",
        "protocol JSON nesting depth is bounded to **32**",
        "core.handshake",
        "one request at a time per child process",
        "The process does **not** listen on TCP, UDP, Unix sockets, named pipes, HTTP, WebSocket",
    ):
        require(phrase in adr, f"ADR-0025 invariant missing: {phrase}")

    # Historical architecture authority remains immutable after implementation closure.
    require("Status: **ARCHITECTURE ACCEPTED / IMPLEMENTATION AUTHORIZED**" in arch, "Phase 5.5.4 architecture status drifted")
    for phrase in (
        "shared-core/go/",
        "cmd/atlas-core",
        "5.5.4A — Core skeleton + protocol",
        "5.5.4B — Canonical + search + graph",
        "5.5.4C — Pack trust + durable state",
        "5.5.4D — Supply-chain / closure",
        "github.com/theupdateframework/go-tuf/v2 v2.4.2",
        "modernc.org/sqlite v1.58.0",
        "golang.org/x/text v0.36.0",
        "SBOM",
        "govulncheck",
    ):
        require(phrase in arch, f"Phase 5.5.4 architecture invariant missing: {phrase}")

    require("Production packages must not import `benchmarks/shared-core/phase553` as a runtime dependency." in arch, "benchmark/runtime separation missing")
    require("no canonical schema drift exists" in arch, "canonical schema preservation exit criterion missing")

    state_old = "Phase 5.5.4 — Production Go Shared Core: **ARCHITECTURE ACCEPTED / IMPLEMENTATION AUTHORIZED**" in state
    state_closed = "Phase 5.5.4 — Production Go Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**" in state
    require(state_old or state_closed, "project-state has invalid Phase 5.5.4 lifecycle state")

    roadmap_old = "### Phase 5.5.4 — Production Go Shared Core\n\nStatus: **ARCHITECTURE ACCEPTED / IMPLEMENTATION AUTHORIZED**" in roadmap
    roadmap_closed = "### Phase 5.5.4 — Production Go Shared Core\n\nStatus: **COMPLETE / MERGED / POST-MERGE VERIFIED**" in roadmap
    require(roadmap_old or roadmap_closed, "roadmap has invalid Phase 5.5.4 lifecycle state")

    current_old = "Phase 5.5.4 — Production Go Shared Core: ARCHITECTURE ACCEPTED / IMPLEMENTATION AUTHORIZED" in current
    current_closed = "Phase 5.5.4 — Production Go Shared Core: COMPLETE / MERGED / POST-MERGE VERIFIED" in current
    require(current_old or current_closed, "current-status has invalid Phase 5.5.4 lifecycle state")

    for text, name in ((state, "project-state"), (roadmap, "roadmap"), (current, "current-status")):
        require("ADR-0025" in text, f"{name} missing ADR-0025")

    require("Shared Core Local Interface: child-process stdio protocol — ADR-0025 Accepted" in state, "project-state interface decision missing")
    require("ADR-0025 — Shared Core Local Interface Boundary" in state, "project-state Accepted ADR list missing ADR-0025")
    require("stable Shared Core local interface/IPC transport" not in state, "accepted interface must not remain listed as open")

    require(CANONICAL.is_dir(), "canonical schemas/v1 missing")
    require(not (CANONICAL / "shared-core.schema.json").exists(), "Shared Core implementation leaked into canonical schema family")
    require(not (CANONICAL / "protocol.schema.json").exists(), "local protocol leaked into canonical schema family")

    print("Phase 5.5.4 Production Go Shared Core architecture gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
