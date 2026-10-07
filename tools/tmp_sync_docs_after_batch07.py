#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN_SHA = "1472bb1818e296399e9b4d216ab27ccc991251c0"
STATUS_DATE = "2026-10-07"

manifest = json.loads((ROOT / "content/encyclopedia/coverage-manifest.json").read_text(encoding="utf-8"))
snapshot = json.loads((ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").read_text(encoding="utf-8"))
bench = manifest["windows_security_log_review_benchmark"]
family = next(x for x in manifest["families"] if x["id"] == "windows-security-auditing")
assert bench["listed_unique_event_id_count"] == 422
assert bench["encyclopedia_grade_listed_id_count"] == 76
assert bench["remaining_listed_id_count"] == 346
assert bench["completion_ratio"] == "76/422"
assert family["denominator_count"] == 423
assert family["encyclopedia_grade_count"] == 70
assert family["remaining_count"] == 353
assert snapshot["completion_ratio"] == "70/423"
assert snapshot["remaining_count"] == 353

provider_ids = sorted(
    [str(x["event_id"]) for x in snapshot["events"] if x.get("coverage_state") == "ENCYCLOPEDIA_GRADE" and x.get("counts_toward_release_coverage") is True],
    key=int,
)
assert len(provider_ids) == 70
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
        f"| 70 — {provider_list} | 353 |"
    )
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "README provider row")


def sync_docs_readme(t: str) -> str:
    t = sub_once(t, r"^- Windows Security Log UWS benchmark: .*?$", "- Windows Security Log UWS benchmark: **76/422 encyclopedia-grade listed identities**, `346` remaining", "docs README UWS")
    t = sub_once(t, r"^- Windows Security Auditing: .*?$", "- Windows Security Auditing: **70/423 encyclopedia-grade**, `353` remaining", "docs README provider")
    t = sub_once(t, r"^- Current Windows Security exemplars: .*?$", f"- Current Windows Security exemplars: {provider_list}", "docs README exemplars")
    return t


def sync_ingestion_readme(t: str) -> str:
    return sub_once(
        t,
        r"^Current reviewed `main` coverage is .*?$",
        "Current reviewed `main` coverage is **70/423** encyclopedia-grade Event IDs for `Microsoft-Windows-Security-Auditing`, while the cross-provider Security Log UWS review benchmark is **76/422** and Sysmon 15.22 remains **30/30** complete. Moving counters remain authoritative only in the machine-readable coverage ledgers.",
        "ingestion README current coverage",
    )


def sync_source_profiles(t: str) -> str:
    return sub_once(
        t,
        r"^The current reviewed Windows Security Auditing numerator is .*?$",
        "The current reviewed Windows Security Auditing numerator is **70/423**; the cross-provider Security Log UWS review benchmark is **76/422**; Sysmon 15.22 remains **30/30**. Moving coverage state is authoritative in `content/encyclopedia/coverage-manifest.json`.",
        "source profiles current coverage",
    )


def sync_product_surfaces(t: str) -> str:
    row = (
        "| Windows Security Auditing | `Microsoft-Windows-Security-Auditing / Security / Windows Server 2025 Datacenter 24H2 build 26100.33296` — 423 unique Event IDs / 488 provider event-version definitions "
        f"| `70/423` — Event IDs {provider_list} | 353 |"
    )
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "product surfaces provider row")


def sync_windows_plan(t: str) -> str:
    t = sub_once(
        t,
        r"^The cross-provider Windows Security Log UWS review benchmark is independently .*?$",
        "The cross-provider Windows Security Log UWS review benchmark is independently `76/422` encyclopedia-grade listed identities with `346` remaining; it is a review benchmark, not a provider denominator.",
        "coverage plan UWS",
    )
    row = f"| Windows Security Auditing | 423 unique Event IDs / 488 provider event-version definitions | 70 — {provider_list} | 353 |"
    return sub_once(t, r"^\| Windows Security Auditing \|.*$", row, "coverage plan provider row")


def sync_roadmap(t: str) -> str:
    t = sub_once(t, r"^- Windows Security Log UWS review benchmark: .*?$", "- Windows Security Log UWS review benchmark: **76/422** listed identities encyclopedia-grade; **346** remaining;", "roadmap UWS")
    t = sub_once(t, r"^- Windows Security encyclopedia-grade numerator: .*?$", f"- Windows Security encyclopedia-grade numerator: **70/423** — Event IDs {provider_list};", "roadmap provider")
    t = sub_once(t, r"^- Windows Security remaining: .*?$", "- Windows Security remaining: **353**;", "roadmap remaining")
    return t


def add_pr168_history(t: str, label: str) -> str:
    if "- PR #168 Windows Security-Auditing 4699–4709 encyclopedia promotion" in t:
        return t
    anchor = "- PR #166 Windows Security-Auditing 4689–4698 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `368ee14fda4300d8c3ca01c43014fb9973326a78`; UWS review benchmark advanced to `66/422` and Security-Auditing to `60/423`."
    addition = anchor + "\n- PR #168 Windows Security-Auditing 4699–4709 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `1472bb1818e296399e9b4d216ab27ccc991251c0`; UWS review benchmark advanced to `76/422` and Security-Auditing to `70/423`."
    if t.count(anchor) != 1:
        raise RuntimeError(f"{label}: PR #166 anchor mismatch")
    return t.replace(anchor, addition, 1)


def sync_current_status(t: str) -> str:
    t = sub_once(t, r"^Status timestamp: .*?$", f"Status timestamp: {STATUS_DATE}", "current status timestamp")
    t = sub_once(
        t,
        r"^- Reviewed `main` corpus baseline: .*?$",
        f"- Reviewed `main` corpus baseline: `{MAIN_SHA}` — PR #168 promoted Security-Auditing Event IDs 4699–4709 after all six exact-head workflows completed **SUCCESS**; Windows Security Log UWS benchmark is `76/422`, Windows Security Auditing is `70/423` with `353` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.",
        "current status baseline",
    )
    t = add_pr168_history(t, "current status")
    t = sub_once(t, r"^  - Windows Security Log UWS review benchmark: .*?$", "  - Windows Security Log UWS review benchmark: `76/422` listed identities encyclopedia-grade; remaining `346`", "current status UWS current-state")
    t = sub_once(t, r"^  - Windows Security encyclopedia-grade: .*?$", f"  - Windows Security encyclopedia-grade: `70/423` — Event IDs {provider_list}; remaining `353`", "current status provider current-state")
    return t


def sync_project_state(t: str) -> str:
    t = sub_once(t, r"^- Last Reviewed Main SHA: .*?$", f"- Last Reviewed Main SHA: `{MAIN_SHA}`", "project state main SHA")
    t = sub_once(
        t,
        r"^- Latest reviewed merged corpus baseline: .*?$",
        f"- Latest reviewed merged corpus baseline: `{MAIN_SHA}` — PR #168 promoted Security-Auditing Event IDs 4699–4709 after all six exact-head workflows completed successfully; Windows Security Log UWS benchmark is `76/422`, Windows Security Auditing is `70/423` with `353` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.",
        "project state baseline",
    )
    t = add_pr168_history(t, "project state")
    t = sub_once(t, r"^    - Windows Security Log UWS review benchmark: .*?$", "    - Windows Security Log UWS review benchmark: `76/422` listed identities encyclopedia-grade; remaining `346`", "project state UWS current-state")
    t = sub_once(t, r"^    - Windows Security encyclopedia grade: .*?$", f"    - Windows Security encyclopedia grade: `70/423` — Event IDs {provider_list}; remaining `353`", "project state provider current-state")
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
print("uws=76/422 remaining=346")
print("security_auditing=70/423 remaining=353")
