#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "ae2a18bb91315efcb5537877480757a0c7f01ebd"

manifest = json.loads((ROOT / "content/encyclopedia/coverage-manifest.json").read_text())
snap = json.loads((ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").read_text())

uws = manifest["windows_security_log_review_benchmark"]
fam = next(x for x in manifest["families"] if x["id"] == "windows-security-auditing")
uws_ratio = uws["completion_ratio"]
uws_remaining = uws["remaining_listed_id_count"]
sa_count = fam["encyclopedia_grade_count"]
sa_den = fam["denominator_count"]
sa_ratio = f"{sa_count}/{sa_den}"
sa_remaining = fam["remaining_count"]
sa_ids = [e["event_id"] for e in snap["events"] if e.get("coverage_state") == "ENCYCLOPEDIA_GRADE"]

assert uws_ratio == "96/422" and uws_remaining == 326
assert sa_count == len(sa_ids) == 90
assert sa_ratio == "90/423" and sa_remaining == 333
ids = ", ".join(f"`{x}`" for x in sa_ids)


def load(path: str) -> str:
    return (ROOT / path).read_text()


def save(path: str, content: str) -> None:
    (ROOT / path).write_text(content)


def sub1(content: str, pattern: str, replacement, label: str) -> str:
    out, count = re.subn(pattern, replacement, content, count=1, flags=re.M)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one current-state anchor, got {count}")
    return out


# README.md: provider table only; it intentionally does not project the UWS benchmark.
p = "README.md"
s = load(p)
pat = r"^\| Windows Security Auditing \| (.*?) \| \d+ — .*? \| \d+ \|$"
s = sub1(s, pat, lambda m: f"| Windows Security Auditing | {m.group(1)} | {sa_count} — {ids} | {sa_remaining} |", "README coverage row")
save(p, s)

# docs/README.md
p = "docs/README.md"
s = load(p)
s = sub1(s, r"^- Windows Security Log UWS benchmark: .*$", f"- Windows Security Log UWS benchmark: **{uws_ratio} encyclopedia-grade listed identities**, `{uws_remaining}` remaining", "docs README UWS")
s = sub1(s, r"^- Windows Security Auditing: .*$", f"- Windows Security Auditing: **{sa_ratio} encyclopedia-grade**, `{sa_remaining}` remaining", "docs README SA")
s = sub1(s, r"^- Current Windows Security exemplars: .*$", f"- Current Windows Security exemplars: {ids}", "docs README IDs")
save(p, s)

history_anchor = "- PR #168 Windows Security-Auditing 4699–4709 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `1472bb1818e296399e9b4d216ab27ccc991251c0`; UWS review benchmark advanced to `76/422` and Security-Auditing to `70/423`."
history_insert = history_anchor + "\n" + "\n".join([
    "- PR #169 authoritative coverage documentation synchronization — **MERGED / ALL APPLICABLE EXACT-HEAD WORKFLOWS SUCCESS** as `034c7c49d9d4bd1d493340646b572d084fb4bfb1`.",
    "- PR #170 Windows Security-Auditing 4710–4719 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `aae2b2081fa51ece3a72b0c75c6e2886c4f1bdcc`; UWS review benchmark advanced to `86/422` and Security-Auditing to `80/423`.",
    "- PR #171 Windows Security-Auditing 4720, 4722–4730 encyclopedia promotion — **MERGED / ALL SIX EXACT-HEAD WORKFLOWS SUCCESS** as `ae2a18bb91315efcb5537877480757a0c7f01ebd`; UWS review benchmark advanced to `96/422` and Security-Auditing to `90/423`.",
])

# docs/current-status.md
p = "docs/current-status.md"
s = load(p)
s = sub1(s, r"^- Reviewed `main` corpus baseline: .*$", f"- Reviewed `main` corpus baseline: `{BASE}` — PR #171 promoted Security-Auditing Event IDs 4720, 4722–4730 after all six exact-head workflows completed **SUCCESS**; Windows Security Log UWS benchmark is `{uws_ratio}`, Windows Security Auditing is `{sa_ratio}` with `{sa_remaining}` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.", "current-status baseline")
if "- PR #170 Windows Security-Auditing 4710–4719 encyclopedia promotion" not in s:
    if history_anchor not in s:
        raise SystemExit("current-status historical anchor missing")
    s = s.replace(history_anchor, history_insert, 1)
save(p, s)

# docs/project-state.md
p = "docs/project-state.md"
s = load(p)
s = sub1(s, r"^- Last Reviewed Main SHA: `[^`]+`$", f"- Last Reviewed Main SHA: `{BASE}`", "project-state SHA")
s = sub1(s, r"^- Latest reviewed merged corpus baseline: .*$", f"- Latest reviewed merged corpus baseline: `{BASE}` — PR #171 promoted Security-Auditing Event IDs 4720, 4722–4730 after all six exact-head workflows completed successfully; Windows Security Log UWS benchmark is `{uws_ratio}`, Windows Security Auditing is `{sa_ratio}` with `{sa_remaining}` remaining, Sysmon remains `30/30`, and the global Windows denominator remains unfrozen.", "project-state baseline")
if "- PR #170 Windows Security-Auditing 4710–4719 encyclopedia promotion" not in s:
    if history_anchor not in s:
        raise SystemExit("project-state historical anchor missing")
    s = s.replace(history_anchor, history_insert, 1)
save(p, s)

# docs/product-surfaces.md: provider table only.
p = "docs/product-surfaces.md"
s = load(p)
pat = r"^\| Windows Security Auditing \| (.*?) \| `\d+/423` — Event IDs .*? \| \d+ \|$"
s = sub1(s, pat, lambda m: f"| Windows Security Auditing | {m.group(1)} | `{sa_ratio}` — Event IDs {ids} | {sa_remaining} |", "product-surfaces row")
save(p, s)

# docs/roadmap.md
p = "docs/roadmap.md"
s = load(p)
s = sub1(s, r"^- Windows Security Log UWS review benchmark: .*$", f"- Windows Security Log UWS review benchmark: **{uws_ratio}** listed identities encyclopedia-grade; **{uws_remaining}** remaining;", "roadmap UWS")
s = sub1(s, r"^- Windows Security encyclopedia-grade numerator: .*$", f"- Windows Security encyclopedia-grade numerator: **{sa_ratio}** — Event IDs {ids};", "roadmap SA")
s = sub1(s, r"^- Windows Security remaining: .*$", f"- Windows Security remaining: **{sa_remaining}**;", "roadmap remaining")
save(p, s)

# docs/windows-sysmon-coverage-plan.md
p = "docs/windows-sysmon-coverage-plan.md"
s = load(p)
s = sub1(s, r"^The cross-provider Windows Security Log UWS review benchmark is independently .*$", f"The cross-provider Windows Security Log UWS review benchmark is independently `{uws_ratio}` encyclopedia-grade listed identities with `{uws_remaining}` remaining; it is a review benchmark, not a provider denominator.", "coverage-plan UWS")
pat = r"^\| Windows Security Auditing \| 423 unique Event IDs / 488 provider event-version definitions \| \d+ — .*? \| \d+ \|$"
s = sub1(s, pat, f"| Windows Security Auditing | 423 unique Event IDs / 488 provider event-version definitions | {sa_count} — {ids} | {sa_remaining} |", "coverage-plan row")
save(p, s)

# ingestion/README.md
p = "ingestion/README.md"
s = load(p)
s = sub1(s, r"^Current reviewed `main` coverage is .*$", f"Current reviewed `main` coverage is **{sa_ratio}** encyclopedia-grade Event IDs for `Microsoft-Windows-Security-Auditing`, while the cross-provider Security Log UWS review benchmark is **{uws_ratio}** and Sysmon 15.22 remains **30/30** complete. Moving counters remain authoritative only in the machine-readable coverage ledgers.", "ingestion README")
save(p, s)

# ingestion/source-profiles/README.md
p = "ingestion/source-profiles/README.md"
s = load(p)
s = sub1(s, r"^The current reviewed Windows Security Auditing numerator is .*$", f"The current reviewed Windows Security Auditing numerator is **{sa_ratio}**; the cross-provider Security Log UWS review benchmark is **{uws_ratio}**; Sysmon 15.22 remains **30/30**. Moving coverage state is authoritative in `content/encyclopedia/coverage-manifest.json`.", "source profiles README")
save(p, s)

allowed = {
    "README.md",
    "docs/README.md",
    "docs/current-status.md",
    "docs/product-surfaces.md",
    "docs/project-state.md",
    "docs/roadmap.md",
    "docs/windows-sysmon-coverage-plan.md",
    "ingestion/README.md",
    "ingestion/source-profiles/README.md",
}
changed = set(subprocess.check_output(["git", "diff", "--name-only"], cwd=ROOT, text=True).splitlines())
if changed != allowed:
    raise SystemExit(f"unexpected durable scope: {sorted(changed)}")

checks = {
    "README.md": ("90 — ", "| 333 |"),
    "docs/README.md": ("96/422", "90/423", "333"),
    "docs/current-status.md": ("PR #171", "96/422", "90/423", BASE),
    "docs/product-surfaces.md": ("90/423", "333"),
    "docs/project-state.md": ("PR #171", "96/422", "90/423", BASE),
    "docs/roadmap.md": ("96/422", "90/423", "333"),
    "docs/windows-sysmon-coverage-plan.md": ("96/422", "90 — ", "333"),
    "ingestion/README.md": ("96/422", "90/423"),
    "ingestion/source-profiles/README.md": ("96/422", "90/423"),
}
for path, needles in checks.items():
    text = load(path)
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"new coverage projection missing in {path}: {missing}")

print(f"coverage={uws_ratio} security_auditing={sa_ratio} files={len(changed)}")
