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


def phase554_lifecycle_valid(text: str) -> bool:
    """Accept the original implementation-authorized boundary or a later verified closure."""
    authorized = "ARCHITECTURE ACCEPTED / IMPLEMENTATION AUTHORIZED" in text
    closed_state = "Phase 5.5.4 — Production Go Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**" in text
    closed_roadmap = (
        "### Phase 5.5.4 — Production Go Shared Core\n\nStatus: **COMPLETE / MERGED / POST-MERGE VERIFIED**" in text
        or "### Phase 5.5.4 — Production Go Shared Core\nStatus: **COMPLETE / MERGED / POST-MERGE VERIFIED**" in text
    )
    return authorized or closed_state or closed_roadmap


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

    for text, name in ((state, "project-state"), (roadmap, "roadmap"), (current, "current-status")):
        require("Phase 5.5.4" in text, f"{name} missing Phase 5.5.4")
        require(phase554_lifecycle_valid(text), f"{name} must preserve an authorized or verified-complete Phase 5.5.4 lifecycle state")
        require("ADR-0025" in text, f"{name} missing ADR-0025")

    require("Shared Core Local Interface: child-process stdio protocol — ADR-0025 Accepted" in state, "project-state interface decision missing")
    require("ADR-0025 — Shared Core Local Interface Boundary" in state, "project-state Accepted ADR list missing ADR-0025")
    require("stable Shared Core local interface/IPC transport" not in state, "accepted interface must not remain listed as open")

    if "Phase 5.5.4 — Production Go Shared Core: **COMPLETE / MERGED / POST-MERGE VERIFIED**" in state:
        require("Phase 5.6 — Windows Desktop MVP: **READY / IMPLEMENTATION ENTRY AUTHORIZED**" in state, "verified Phase 5.5.4 closure must clear the Phase 5.6 blocker")

    require(CANONICAL.is_dir(), "canonical schemas/v1 missing")
    require(not (CANONICAL / "shared-core.schema.json").exists(), "Shared Core implementation leaked into canonical schema family")
    require(not (CANONICAL / "protocol.schema.json").exists(), "local protocol leaked into canonical schema family")

    print("Phase 5.5.4 Production Go Shared Core architecture gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
