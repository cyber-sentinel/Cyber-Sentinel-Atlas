#!/usr/bin/env python3
"""Build the MVP-2 private pack with obsolete phase-5.2 fixture projections removed.

The general engineering-preview builder intentionally preserves historical test
fixtures for old regression paths. MVP-2, however, must present the governed
encyclopedia projection when an event has been promoted. This adapter removes
only the explicitly superseded 4688 fixture field/claim/relationship that would
otherwise appear beside the 15 authoritative encyclopedia field entities.

No source text is copied or rewritten here; this is deterministic record-set
selection before the existing TUF/signing/build pipeline executes.
"""
from __future__ import annotations

from tools.release import build_engineering_preview_pack as base

# These three repository-owned Phase-5.2 support records represented a single
# early 4688 demonstration field. They are superseded by the complete governed
# 4688 encyclopedia dictionary and must not leak into the analyst-facing MVP-2
# read model as a sixteenth duplicate field.
SUPERSEDED_FIXTURE_RECORD_IDS = frozenset({
    "atlas:field:microsoft.windows.security:4688.newprocessname",
    "atlas:claim:atlas.claim:sha256-01002319eb6d49dad74efe68284f646a5ebc9428131e6ad65e4e9a4fa83f6f03",
    "atlas:relationship:atlas.graph:sha256-b7ffc14a9cd3dd9838a4c94dc7610c95d63d8b7a172f6702c30b6e58cbd5af7e",
})

_original_load = base.load_canonical_records


def load_mvp2_records():
    records = _original_load()
    present = {record.get("id") for record in records}
    missing = SUPERSEDED_FIXTURE_RECORD_IDS - present
    if missing:
        raise RuntimeError(
            "MVP-2 superseded-fixture contract drift; expected legacy records are missing: "
            + ", ".join(sorted(missing))
        )
    filtered = [
        record for record in records
        if record.get("id") not in SUPERSEDED_FIXTURE_RECORD_IDS
    ]
    if len(records) - len(filtered) != len(SUPERSEDED_FIXTURE_RECORD_IDS):
        raise RuntimeError("MVP-2 superseded-fixture pruning was not exact")
    return filtered


def main() -> int:
    base.load_canonical_records = load_mvp2_records
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
