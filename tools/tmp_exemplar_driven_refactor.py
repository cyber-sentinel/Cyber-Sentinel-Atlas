#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


# 1) Deterministic discovery of encyclopedia source records.
path = ROOT / "tools/content/build_encyclopedia_records.py"
text = path.read_text(encoding="utf-8")
start = text.index("SOURCE_PATHS = [\n")
end = text.index("\n\nSYSMON_SCHEMA_SOURCE", start)
source_block = '''FIXED_SOURCE_PATHS = [
    ROOT / "ingestion" / "source-profiles" / "microsoft-sysmon-docs.source.json",
    ROOT / "ingestion" / "source-profiles" / "microsoft-sysmon-schema-export.source.json",
    ROOT / "ingestion" / "source-profiles" / "microsoft-windows-provider-metadata.source.json",
    ROOT / "ingestion" / "source-profiles" / "microsoft-windows-security-auditing-4688-doc.source.json",
]
ENCYCLOPEDIA_SOURCE_DIR = ROOT / "content" / "encyclopedia" / "sources"


def source_paths() -> list[Path]:
    """Return fixed ingestion authorities plus every governed encyclopedia source record."""
    content_sources = sorted(ENCYCLOPEDIA_SOURCE_DIR.glob("*.json"), key=lambda item: item.as_posix())
    return [*FIXED_SOURCE_PATHS, *content_sources]
'''
text = text[:start] + source_block + text[end:]
text = replace_once(text, "    for path in SOURCE_PATHS:\n", "    for path in source_paths():\n", "source-record iteration")
path.write_text(text, encoding="utf-8")

# 2) Make engineering-pack required Windows records derive from approved exemplars.
path = ROOT / "tools/release/build_engineering_preview_pack.py"
text = path.read_text(encoding="utf-8")
anchor = 'ROOT = Path(__file__).resolve().parents[2]\n'
insert = '''ROOT = Path(__file__).resolve().parents[2]
APPROVED_EXEMPLARS = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"


def approved_windows_event_ids() -> list[str]:
    data = json.loads(APPROVED_EXEMPLARS.read_text(encoding="utf-8"))
    event_ids = [
        str(item["native_event_id"])
        for item in data.get("events", [])
        if item.get("namespace") == "microsoft.windows.security"
    ]
    if len(event_ids) != len(set(event_ids)) or any(not event_id.isdecimal() for event_id in event_ids):
        raise RuntimeError("approved Windows Security exemplar IDs are invalid or duplicated")
    return sorted(event_ids, key=int)
'''
text = replace_once(text, anchor, insert, "pack approved-exemplar helper")
start = text.index('    for required in (\n        "atlas:event:microsoft.windows.security:4688",')
end_marker = '            raise RuntimeError(f"required engineering-preview record is missing: {required}")\n'
end = text.index(end_marker, start) + len(end_marker)
replacement = '''    required_records = [
        "atlas:event:microsoft.sysmon:1",
        "atlas:event:microsoft.sysmon:3",
    ]
    required_records.extend(
        f"atlas:event:microsoft.windows.security:{event_id}"
        for event_id in approved_windows_event_ids()
    )
    for required in required_records:
        if required not in by_id:
            raise RuntimeError(f"required engineering-preview record is missing: {required}")
'''
text = text[:start] + replacement + text[end:]
path.write_text(text, encoding="utf-8")

# 3) Make the clean-Windows probe enumerate every approved Windows exemplar.
path = ROOT / "tools/release/probe_engineering_preview.py"
text = path.read_text(encoding="utf-8")
start = text.index('EXPECTED_EVENT = "atlas:event:microsoft.windows.security:4688"')
end = text.index('EXPECTED_SYSMON = ', start)
constants = '''ROOT = Path(__file__).resolve().parents[2]
APPROVED_EXEMPLARS = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"


def approved_windows_event_ids() -> list[str]:
    data = json.loads(APPROVED_EXEMPLARS.read_text(encoding="utf-8"))
    event_ids = [
        str(item["native_event_id"])
        for item in data.get("events", [])
        if item.get("namespace") == "microsoft.windows.security"
    ]
    if len(event_ids) != len(set(event_ids)) or any(not event_id.isdecimal() for event_id in event_ids):
        raise RuntimeError("approved Windows Security exemplar IDs are invalid or duplicated")
    return sorted(event_ids, key=int)


'''
text = text[:start] + constants + text[end:]

start = text.index('        search_4688 = request(\n')
end = text.index('        search_sysmon = request(\n', start)
dynamic_probe = '''        windows_security_results: dict[str, dict[str, bool]] = {}
        windows_security_event_ids = approved_windows_event_ids()
        if not windows_security_event_ids:
            raise RuntimeError("approved Windows Security exemplar set is unexpectedly empty")
        for index, event_id in enumerate(windows_security_event_ids):
            target_id = f"atlas:event:microsoft.windows.security:{event_id}"
            search_result = request(
                process.stdin,
                process.stdout,
                f"qw{index}",
                "search.query",
                {"query": event_id, "graph_depth": 1, "limit": 10},
            )
            search_ok = search_contains_target(search_result, target_id)
            if not search_ok:
                raise RuntimeError(
                    f"Windows Event {event_id} was not returned by deterministic search: {search_result}"
                )
            record = request(
                process.stdin,
                process.stdout,
                f"rw{index}",
                "record.get",
                {"id": target_id},
            )
            record_ok = isinstance(record, dict) and record.get("id") == target_id
            if not record_ok:
                raise RuntimeError(f"Windows Event {event_id} record identity mismatch")
            windows_security_results[event_id] = {
                "search_ok": search_ok,
                "record_ok": record_ok,
            }
        windows_security_exemplars_all_ok = all(
            item["search_ok"] and item["record_ok"]
            for item in windows_security_results.values()
        )

'''
text = text[:start] + dynamic_probe + text[end:]

start = text.index('        search_4624 = request(\n')
end = text.index('        search_sysmon_3 = request(\n', start)
text = text[:start] + text[end:]

start = text.index('        evidence = {\n')
end = text.index('        }\n    finally:', start) + len('        }\n')
evidence = '''        evidence = {
            "schema_version": "1.0.0",
            "handshake_protocol": handshake.get("protocol"),
            "core_version": handshake.get("core_version"),
            "core_commit": handshake.get("core_commit"),
            "pack_ready": status.get("ready"),
            "pack_id": status.get("pack_id"),
            "pack_version": status.get("pack_version"),
            "generation_id": status.get("generation_id"),
            "windows_security_exemplar_event_ids": windows_security_event_ids,
            "windows_security_exemplars": windows_security_results,
            "windows_security_exemplars_all_ok": windows_security_exemplars_all_ok,
            "sysmon_1_search_ok": sysmon_1_search_ok,
            "sysmon_1_processcreate_alias_ok": sysmon_1_processcreate_alias_ok,
            "sysmon_1_record_processcreate_alias_ok": sysmon_1_record_processcreate_alias_ok,
            "sysmon_1_record_ok": True,
            "sysmon_3_search_ok": sysmon_3_search_ok,
            "sysmon_3_record_ok": True,
            "graph_expand_ok": True,
        }
'''
text = text[:start] + evidence + text[end:]
path.write_text(text, encoding="utf-8")

# 4) Bind package-manifest and workflow acceptance to the approved set, not individual IDs.
path = ROOT / ".github/workflows/phase5105-usable-data-preview.yml"
text = path.read_text(encoding="utf-8")
manifest_anchor = '          $Manifest = [ordered]@{\n'
manifest_prelude = '''          $Approved = Get-Content -Raw 'content/encyclopedia/approved-exemplars.json' | ConvertFrom-Json
          $WindowsExemplars = @($Approved.events | Where-Object { $_.namespace -eq 'microsoft.windows.security' } | ForEach-Object { [string]$_.native_event_id } | Sort-Object { [int]$_ })
          if ($WindowsExemplars.Count -lt 1) { throw 'approved Windows Security exemplar set is unexpectedly empty' }
          $Manifest = [ordered]@{
'''
text = replace_once(text, manifest_anchor, manifest_prelude, "workflow manifest exemplar set")
old_acceptance = "            acceptance = [ordered]@{ windows_event_4688=$true; windows_event_4625=$true; windows_event_4648=$true; windows_event_4672=$true; windows_event_4740=$true; windows_event_4768=$true; windows_event_4769=$true; windows_event_4771=$true; sysmon_event_1=$true; record_detail=$true; bounded_graph=$true }"
new_acceptance = "            acceptance = [ordered]@{ windows_security_exemplars_all=$true; windows_security_event_ids=$WindowsExemplars; sysmon_event_1=$true; record_detail=$true; bounded_graph=$true }"
text = replace_once(text, old_acceptance, new_acceptance, "workflow acceptance manifest")
old_readme = '          Acceptance pivots include Windows Security Events 4688, 4625, 4648, 4672, 4740, 4768, 4769 and 4771, Sysmon Event 1,\n'
new_readme = '          Acceptance pivots include every maintainer-approved Windows Security encyclopedia exemplar, Sysmon Event 1,\n'
text = replace_once(text, old_readme, new_readme, "workflow README acceptance text")
pattern = re.compile(r"          if \(\$probe\.pack_ready.*?\n          \}", re.S)
match = pattern.search(text)
if not match or "usable data preview acceptance invariant failed" not in match.group(0):
    raise SystemExit("workflow probe acceptance invariant block not found")
new_check = '''          $Manifest = Get-Content -Raw (Join-Path $env:PHASE5105_CLEAN 'PACKAGE-MANIFEST.json') | ConvertFrom-Json
          $manifestIds = @($Manifest.acceptance.windows_security_event_ids)
          $probeIds = @($probe.windows_security_exemplar_event_ids)
          if (($manifestIds -join ',') -ne ($probeIds -join ',')) { throw 'package/probe Windows Security exemplar set mismatch' }
          if ($probe.pack_ready -ne $true -or $probe.windows_security_exemplars_all_ok -ne $true -or $probe.sysmon_1_search_ok -ne $true -or $probe.sysmon_1_processcreate_alias_ok -ne $true -or $probe.sysmon_1_record_processcreate_alias_ok -ne $true -or $probe.sysmon_1_record_ok -ne $true -or $probe.graph_expand_ok -ne $true) {
            throw 'usable data preview acceptance invariant failed'
          }'''
text = text[:match.start()] + new_check + text[match.end():]
path.write_text(text, encoding="utf-8")

# 5) Add lightweight contract tests and wire them into Foundation Hygiene.
test = ROOT / "tests/phase51010/test_exemplar_driven_preview_contract.py"
test.write_text('''#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


content_builder = load_module("encyclopedia_builder", ROOT / "tools/content/build_encyclopedia_records.py")
probe = load_module("preview_probe", ROOT / "tools/release/probe_engineering_preview.py")


def approved_windows_ids() -> list[str]:
    data = json.loads((ROOT / "content/encyclopedia/approved-exemplars.json").read_text(encoding="utf-8"))
    return sorted(
        [str(item["native_event_id"]) for item in data["events"] if item.get("namespace") == "microsoft.windows.security"],
        key=int,
    )


def test_01_all_governed_source_records_are_discovered():
    expected = sorted((ROOT / "content/encyclopedia/sources").glob("*.json"))
    discovered = [path for path in content_builder.source_paths() if path.parent == ROOT / "content/encyclopedia/sources"]
    assert discovered == expected
    assert len(discovered) == len(set(discovered))


def test_02_probe_set_is_derived_from_approved_exemplars():
    assert probe.approved_windows_event_ids() == approved_windows_ids()


def test_03_workflow_uses_aggregate_exemplar_contract():
    workflow = (ROOT / ".github/workflows/phase5105-usable-data-preview.yml").read_text(encoding="utf-8")
    assert "windows_security_exemplars_all=$true" in workflow
    assert "windows_security_event_ids=$WindowsExemplars" in workflow
    assert "$probe.windows_security_exemplars_all_ok" in workflow
    assert "$probe.windows_4769_search_ok" not in workflow


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
''', encoding="utf-8")

path = ROOT / ".github/workflows/foundation-hygiene.yml"
text = path.read_text(encoding="utf-8")
anchor = '          python tests/phase51010/test_windows_security_review_queue.py\n'
text = replace_once(text, anchor, anchor + '          python tests/phase51010/test_exemplar_driven_preview_contract.py\n', "Foundation exemplar-driven contract test")
path.write_text(text, encoding="utf-8")
