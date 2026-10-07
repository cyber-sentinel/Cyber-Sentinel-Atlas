#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN_SHA = "4e4953bee6ddcc135d68427a417089e49ea66a3b"
STATUS_DATE = "2026-10-07"

manifest = json.loads((ROOT / "content/encyclopedia/coverage-manifest.json").read_text(encoding="utf-8"))
snapshot = json.loads((ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").read_text(encoding="utf-8"))
bench = manifest["windows_security_log_review_benchmark"]
family = next(x for x in manifest["families"] if x["id"] == "windows-security-auditing")
assert bench["listed_unique_event_id_count"] == 422
assert bench["encyclopedia_grade_listed_id_count"] == 56
assert bench["remaining_listed_id_count"] == 366
assert bench["completion_ratio"] == "56/422"
assert family["denominator_count"] == 423
assert family["encyclopedia_grade_count"] == 50
assert family["remaining_count"] == 373
assert snapshot["completion_ratio"] == "50/423"
assert snapshot["remaining_count"] == 373

provider_ids = [str(x["event_id"]) for x in snapshot["events"] if x.get("coverage_state") == "ENCYCLOPEDIA_GRADE" and x.get("counts_toward_release_coverage") is True]
assert len(provider_ids) == 50
provider_ids = sorted(provider_ids, key=int)
provider_list = ", ".join(f"`{x}`" for x in provider_ids)


def sub_once(text: str, pattern: str, repl: str, label: str) -> str:
    out, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    if n != 1:
        raise RuntimeError(f"{label}: expected exactly one match, got {n}")
    return out


def write(path: str, transform) -> None:
    p = ROOT / path
    before = p.read_text(encoding="utf-8")
    after = transform(before)
    if before == after:
        raise RuntimeError(f"{path}: no change produced")
    p.write_text(after, encoding="utf-8")
    print(f"updated {path}")


def sync_root_readme(t: str) -> str:
    row = (
        "| Windows Security Auditing | 423 unique Event IDs on `Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296` "
        f"| 50 — {provider_list} | 373 |"
    )
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "README provider row")


def sync_docs_readme(t: str) -> str:
    t = sub_once(t, r"^- Windows Security Log UWS benchmark: .*?$", "- Windows Security Log UWS benchmark: **56/422 encyclopedia-grade listed identities**, `366` remaining", "docs README UWS")
    t = sub_once(t, r"^- Windows Security Auditing: .*?$", "- Windows Security Auditing: **50/423 encyclopedia-grade**, `373` remaining", "docs README provider")
    t = sub_once(t, r"^- Current Windows Security exemplars: .*?$", f"- Current Windows Security exemplars: {provider_list}", "docs README exemplars")
    return t


def sync_ingestion_readme(t: str) -> str:
    return sub_once(
        t,
        r"^Current reviewed `main` coverage is .*?$",
        "Current reviewed `main` coverage is **50/423** encyclopedia-grade Event IDs for `Microsoft-Windows-Security-Auditing`, while the cross-provider Security Log UWS review benchmark is **56/422** and Sysmon 15.22 remains **30/30** complete. Moving counters remain authoritative only in the machine-readable coverage ledgers.",
        "ingestion README current coverage",
    )


def sync_source_profiles(t: str) -> str:
    return sub_once(
        t,
        r"^The current reviewed Windows Security Auditing numerator is .*?$",
        "The current reviewed Windows Security Auditing numerator is **50/423**; the cross-provider Security Log UWS review benchmark is **56/422**; Sysmon 15.22 remains **30/30**. Moving coverage state is authoritative in `content/encyclopedia/coverage-manifest.json`.",
        "source profiles current coverage",
    )


def sync_product_surfaces(t: str) -> str:
    row = (
        "| Windows Security Auditing | `Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296` — 423 unique Event IDs / 488 provider event-version definitions "
        f"| `50/423` — Event IDs {provider_list} | 373 |"
    )
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "product surfaces provider row")


def sync_windows_plan(t: str) -> str:
    t = sub_once(
        t,
        r"^The cross-provider Windows Security Log UWS review benchmark is independently .*?$",
        "The cross-provider Windows Security Log UWS review benchmark is independently `56/422` encyclopedia-grade listed identities with `366` remaining; it is a review benchmark, not a provider denominator.",
        "coverage plan UWS",
    )
    row = f"| Windows Security Auditing | 423 unique Event IDs / 488 provider event-version definitions | 50 — {provider_list} | 373 |"
    t = sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "coverage plan provider row")
    return t


def sync_roadmap(t: str) -> str:
    t = sub_once(t, r"^- Windows Security Log UWS review benchmark: .*?$", "- Windows Security Log UWS review benchmark: **56/422** listed identities encyclopedia-grade; **366** remaining;", "roadmap UWS")
    t = sub_once(t, r"^- Windows Security encyclopedia-grade numerator: .*?$", f"- Windows Security encyclopedia-grade numerator: **50/423** — Event IDs {provider_list};", "roadmap provider")
    t = sub_once(t, r"^- Windows Security remaining: .*?$", "- Windows Security remaining: **373**;", "roadmap remaining")
    return t


def sync_current_status(t: str) -> str:
    t = sub_once(t, r"^Status timestamp: .*?$", f"Status timestamp: {STATUS_DATE}", "current status timestamp")
    t = sub_once(
        t,
        r"^- Reviewed `main` corpus baseline: .*?$",
        f"- Reviewed `main` corpus baseline: `{MAIN_SHA}` — PR #164 promoted Security-Auditing Event IDs 4664–4675 after all six exact-head workflows completed **SUCCESS**; Windows Security Log UWS benchmark is `56/422`, Windows Security Auditing is `50/423` with `373` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.",
        "current status baseline",
    )
    anchor = "- PR #161 Windows Security-Auditing 4626–4653 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS / POST-MERGE CHECKS GREEN** as `463fa36992c47fb02365b35a2c68afd787ddbb1a`; UWS review benchmark advanced to `36/422` and Security-Auditing to `30/423`."
    additions = (
        anchor
        + "\n- PR #163 Windows Security-Auditing 4654–4663 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `792ec7102faf1d5d9cde0a88b3f627d6d6d44f54`; UWS review benchmark advanced to `46/422` and Security-Auditing to `40/423`."
        + "\n- PR #164 Windows Security-Auditing 4664–4675 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `4e4953bee6ddcc135d68427a417089e49ea66a3b`; UWS review benchmark advanced to `56/422` and Security-Auditing to `50/423`."
    )
    if "- PR #164 Windows Security-Auditing 4664–4675 encyclopedia promotion" not in t:
        if t.count(anchor) != 1:
            raise RuntimeError("current status PR #161 anchor mismatch")
        t = t.replace(anchor, additions, 1)
    t = sub_once(t, r"^  - Windows Security Log UWS review benchmark: .*?$", "  - Windows Security Log UWS review benchmark: `56/422` listed identities encyclopedia-grade; remaining `366`", "current status UWS current-state")
    t = sub_once(t, r"^  - Windows Security encyclopedia-grade: .*?$", f"  - Windows Security encyclopedia-grade: `50/423` — Event IDs {provider_list}; remaining `373`", "current status provider current-state")
    return t


def sync_project_state(t: str) -> str:
    t = sub_once(t, r"^- Last Reviewed Main SHA: .*?$", f"- Last Reviewed Main SHA: `{MAIN_SHA}`", "project state main SHA")
    t = sub_once(
        t,
        r"^- Latest reviewed merged corpus baseline: .*?$",
        f"- Latest reviewed merged corpus baseline: `{MAIN_SHA}` — PR #164 promoted Security-Auditing Event IDs 4664–4675 after all six exact-head workflows completed successfully; Windows Security Log UWS benchmark is `56/422`, Windows Security Auditing is `50/423` with `373` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.",
        "project state baseline",
    )
    anchor = "- PR #161 Windows Security-Auditing 4626–4653 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS / POST-MERGE CHECKS GREEN** as `463fa36992c47fb02365b35a2c68afd787ddbb1a`; UWS review benchmark advanced to `36/422` and Security-Auditing to `30/423`."
    additions = (
        anchor
        + "\n- PR #163 Windows Security-Auditing 4654–4663 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `792ec7102faf1d5d9cde0a88b3f627d6d6d44f54`; UWS review benchmark advanced to `46/422` and Security-Auditing to `40/423`."
        + "\n- PR #164 Windows Security-Auditing 4664–4675 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `4e4953bee6ddcc135d68427a417089e49ea66a3b`; UWS review benchmark advanced to `56/422` and Security-Auditing to `50/423`."
    )
    if "- PR #164 Windows Security-Auditing 4664–4675 encyclopedia promotion" not in t:
        if t.count(anchor) != 1:
            raise RuntimeError("project state PR #161 anchor mismatch")
        t = t.replace(anchor, additions, 1)
    t = sub_once(t, r"^    - Windows Security Log UWS review benchmark: .*?$", "    - Windows Security Log UWS review benchmark: `56/422` listed identities encyclopedia-grade; remaining `366`", "project state UWS current-state")
    t = sub_once(t, r"^    - Windows Security encyclopedia grade: .*?$", f"    - Windows Security encyclopedia grade: `50/423` — Event IDs {provider_list}; remaining `373`", "project state provider current-state")
    return t


write("README.md", sync_root_readme)
write("docs/README.md", sync_docs_readme)
write("ingestion/README.md", sync_ingestion_readme)
write("ingestion/source-profiles/README.md", sync_source_profiles)
write("docs/product-surfaces.md", sync_product_surfaces)
write("docs/windows-sysmon-coverage-plan.md", sync_windows_plan)
write("docs/roadmap.md", sync_roadmap)
write("docs/current-status.md", sync_current_status)
write("docs/project-state.md", sync_project_state)
print("docs_sync=PASS")
print("uws=56/422 remaining=366")
print("security_auditing=50/423 remaining=373")
