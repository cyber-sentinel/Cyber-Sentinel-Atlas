#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN_SHA = "368ee14fda4300d8c3ca01c43014fb9973326a78"
STATUS_DATE = "2026-10-07"

manifest = json.loads((ROOT / "content/encyclopedia/coverage-manifest.json").read_text(encoding="utf-8"))
snapshot = json.loads((ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").read_text(encoding="utf-8"))
bench = manifest["windows_security_log_review_benchmark"]
family = next(x for x in manifest["families"] if x["id"] == "windows-security-auditing")
assert bench["listed_unique_event_id_count"] == 422
assert bench["encyclopedia_grade_listed_id_count"] == 66
assert bench["remaining_listed_id_count"] == 356
assert bench["completion_ratio"] == "66/422"
assert family["denominator_count"] == 423
assert family["encyclopedia_grade_count"] == 60
assert family["remaining_count"] == 363
assert snapshot["completion_ratio"] == "60/423"
assert snapshot["remaining_count"] == 363

provider_ids = sorted(
    [str(x["event_id"]) for x in snapshot["events"] if x.get("coverage_state") == "ENCYCLOPEDIA_GRADE" and x.get("counts_toward_release_coverage") is True],
    key=int,
)
assert len(provider_ids) == 60
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
        f"| 60 — {provider_list} | 363 |"
    )
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "README provider row")


def sync_docs_readme(t: str) -> str:
    t = sub_once(t, r"^- Windows Security Log UWS benchmark: .*?$", "- Windows Security Log UWS benchmark: **66/422 encyclopedia-grade listed identities**, `356` remaining", "docs README UWS")
    t = sub_once(t, r"^- Windows Security Auditing: .*?$", "- Windows Security Auditing: **60/423 encyclopedia-grade**, `363` remaining", "docs README provider")
    t = sub_once(t, r"^- Current Windows Security exemplars: .*?$", f"- Current Windows Security exemplars: {provider_list}", "docs README exemplars")
    return t


def sync_ingestion_readme(t: str) -> str:
    return sub_once(
        t,
        r"^Current reviewed `main` coverage is .*?$",
        "Current reviewed `main` coverage is **60/423** encyclopedia-grade Event IDs for `Microsoft-Windows-Security-Auditing`, while the cross-provider Security Log UWS review benchmark is **66/422** and Sysmon 15.22 remains **30/30** complete. Moving counters remain authoritative only in the machine-readable coverage ledgers.",
        "ingestion README current coverage",
    )


def sync_source_profiles(t: str) -> str:
    return sub_once(
        t,
        r"^The current reviewed Windows Security Auditing numerator is .*?$",
        "The current reviewed Windows Security Auditing numerator is **60/423**; the cross-provider Security Log UWS review benchmark is **66/422**; Sysmon 15.22 remains **30/30**. Moving coverage state is authoritative in `content/encyclopedia/coverage-manifest.json`.",
        "source profiles current coverage",
    )


def sync_product_surfaces(t: str) -> str:
    row = (
        "| Windows Security Auditing | `Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296` — 423 unique Event IDs / 488 provider event-version definitions "
        f"| `60/423` — Event IDs {provider_list} | 363 |"
    )
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "product surfaces provider row")


def sync_windows_plan(t: str) -> str:
    t = sub_once(
        t,
        r"^The cross-provider Windows Security Log UWS review benchmark is independently .*?$",
        "The cross-provider Windows Security Log UWS review benchmark is independently `66/422` encyclopedia-grade listed identities with `356` remaining; it is a review benchmark, not a provider denominator.",
        "coverage plan UWS",
    )
    row = f"| Windows Security Auditing | 423 unique Event IDs / 488 provider event-version definitions | 60 — {provider_list} | 363 |"
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "coverage plan provider row")


def sync_roadmap(t: str) -> str:
    t = sub_once(t, r"^- Windows Security Log UWS review benchmark: .*?$", "- Windows Security Log UWS review benchmark: **66/422** listed identities encyclopedia-grade; **356** remaining;", "roadmap UWS")
    t = sub_once(t, r"^- Windows Security encyclopedia-grade numerator: .*?$", f"- Windows Security encyclopedia-grade numerator: **60/423** — Event IDs {provider_list};", "roadmap provider")
    t = sub_once(t, r"^- Windows Security remaining: .*?$", "- Windows Security remaining: **363**;", "roadmap remaining")
    return t


def add_pr166_history(t: str, label: str) -> str:
    if "- PR #166 Windows Security-Auditing 4689–4698 encyclopedia promotion" in t:
        return t
    anchor = "- PR #164 Windows Security-Auditing 4664–4675 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `4e4953bee6ddcc135d68427a417089e49ea66a3b`; UWS review benchmark advanced to `56/422` and Security-Auditing to `50/423`."
    addition = anchor + "\n- PR #166 Windows Security-Auditing 4689–4698 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `368ee14fda4300d8c3ca01c43014fb9973326a78`; UWS review benchmark advanced to `66/422` and Security-Auditing to `60/423`."
    if t.count(anchor) != 1:
        raise RuntimeError(f"{label}: PR #164 anchor mismatch")
    return t.replace(anchor, addition, 1)


def sync_current_status(t: str) -> str:
    t = sub_once(t, r"^Status timestamp: .*?$", f"Status timestamp: {STATUS_DATE}", "current status timestamp")
    t = sub_once(
        t,
        r"^- Reviewed `main` corpus baseline: .*?$",
        f"- Reviewed `main` corpus baseline: `{MAIN_SHA}` — PR #166 promoted Security-Auditing Event IDs 4689–4698 after all six exact-head workflows completed **SUCCESS**; Windows Security Log UWS benchmark is `66/422`, Windows Security Auditing is `60/423` with `363` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.",
        "current status baseline",
    )
    t = add_pr166_history(t, "current status")
    t = sub_once(t, r"^  - Windows Security Log UWS review benchmark: .*?$", "  - Windows Security Log UWS review benchmark: `66/422` listed identities encyclopedia-grade; remaining `356`", "current status UWS current-state")
    t = sub_once(t, r"^  - Windows Security encyclopedia-grade: .*?$", f"  - Windows Security encyclopedia-grade: `60/423` — Event IDs {provider_list}; remaining `363`", "current status provider current-state")
    return t


def sync_project_state(t: str) -> str:
    t = sub_once(t, r"^- Last Reviewed Main SHA: .*?$", f"- Last Reviewed Main SHA: `{MAIN_SHA}`", "project state main SHA")
    t = sub_once(
        t,
        r"^- Latest reviewed merged corpus baseline: .*?$",
        f"- Latest reviewed merged corpus baseline: `{MAIN_SHA}` — PR #166 promoted Security-Auditing Event IDs 4689–4698 after all six exact-head workflows completed successfully; Windows Security Log UWS benchmark is `66/422`, Windows Security Auditing is `60/423` with `363` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.",
        "project state baseline",
    )
    t = add_pr166_history(t, "project state")
    t = sub_once(t, r"^    - Windows Security Log UWS review benchmark: .*?$", "    - Windows Security Log UWS review benchmark: `66/422` listed identities encyclopedia-grade; remaining `356`", "project state UWS current-state")
    t = sub_once(t, r"^    - Windows Security encyclopedia grade: .*?$", f"    - Windows Security encyclopedia grade: `60/423` — Event IDs {provider_list}; remaining `363`", "project state provider current-state")
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
print("uws=66/422 remaining=356")
print("security_auditing=60/423 remaining=363")
