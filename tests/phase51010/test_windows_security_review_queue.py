#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUEUE = ROOT / "tools/content/build_windows_security_review_queue.py"

spec = importlib.util.spec_from_file_location("windows_security_review_queue", QUEUE)
assert spec is not None and spec.loader is not None
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def test_01_queue_is_exhaustive_disjoint_and_does_not_promote():
    queue = builder.build_queue(batch_size=10)
    snapshot = json.loads(builder.SNAPSHOT.read_text(encoding="utf-8"))
    expected = {entry["event_id"] for entry in snapshot["events"]
                if not entry["counts_toward_release_coverage"]}
    queued = [event_id for batch in queue["batches"] for event_id in batch["event_ids"]]
    assert len(queued) == len(set(queued)) == queue["remaining_count"]
    assert set(queued) == expected
    assert queue["encyclopedia_grade_count"] == snapshot["encyclopedia_grade_count"]
    assert queue["batch_count"] == (len(expected) + 9) // 10
    assert all(1 <= len(batch["event_ids"]) <= 10 for batch in queue["batches"])
    assert queue["purpose"] == "planning-only; no promotion or execution authority"


def test_02_invalid_sizes_and_out_of_scope_state_fail_closed():
    for size in (0, 26):
        try:
            builder.build_queue(batch_size=size)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid batch size was accepted")
    snapshot = json.loads(builder.SNAPSHOT.read_text(encoding="utf-8"))
    altered = copy.deepcopy(snapshot)
    first_uncovered = next(item for item in altered["events"] if not item["counts_toward_release_coverage"])
    first_uncovered["coverage_state"] = "ENCYCLOPEDIA_GRADE"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "snapshot.json"
        path.write_text(json.dumps(altered), encoding="utf-8")
        try:
            builder.build_queue(snapshot_path=path)
        except ValueError:
            pass
        else:
            raise AssertionError("inconsistent coverage state was accepted")


def test_03_same_inputs_same_batches_and_stable_scope_binding():
    first = builder.build_queue(batch_size=25)
    second = builder.build_queue(batch_size=25)
    assert first == second
    assert first["batch_count"] == (first["remaining_count"] + 24) // 25
    assert first["inventory_digest"].startswith("sha256-")
    assert len(first["snapshot_sha256"]) == 64
    assert all(batch["batch_index"] == index
               for index, batch in enumerate(first["batches"]))


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
