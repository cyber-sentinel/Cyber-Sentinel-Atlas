#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

helper = ROOT / "tools/tmp_apply_eventlog_1100_batch.py"
text = helper.read_text(encoding="utf-8")
old = 'official_status="official-runtime-provider-evidence"'
new = 'official_status="official"'
if text.count(old) != 1:
    raise SystemExit(f"expected one structural source official_status occurrence, found {text.count(old)}")
helper.write_text(text.replace(old, new, 1), encoding="utf-8")

test = ROOT / "tests/phase51010/test_approved_exemplar_content.py"
text = test.read_text(encoding="utf-8")
old = '    assert len(field_ids) == 423\n    assert claim_subjects == field_ids\n    assert relationship_targets == field_ids\n'
new = '    blueprint = json.loads((ROOT / "content/encyclopedia/approved-exemplars.json").read_text(encoding="utf-8"))\n    expected_field_count = sum(len(item.get("fields", [])) for item in blueprint["events"])\n    assert len(field_ids) == expected_field_count\n    assert claim_subjects == field_ids\n    assert relationship_targets == field_ids\n'
if text.count(old) != 1:
    raise SystemExit(f"expected one legacy field-count assertion block, found {text.count(old)}")
test.write_text(text.replace(old, new, 1), encoding="utf-8")
print("eventlog_1100_batch_validation_assumptions_patched=2")
