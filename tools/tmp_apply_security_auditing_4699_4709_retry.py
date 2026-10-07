#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/tmp_apply_security_auditing_4699_4709.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("batch07_helper", HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Batch 07 helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    h = load_helper()
    impl = h.load_impl()
    base = impl.load_base()
    impl.configure_base(base)
    discovery = h.raw_discovery()
    shapes = h.provider_shapes(discovery)
    inventory = h.build_inventory(base, shapes)
    base.dump(
        ROOT / "ingestion/inventories/windows-security-auditing-4699-4709-26100.telemetry.json",
        inventory,
    )
    h.write_sources(base)
    base.update_blueprint(shapes)
    h.update_coverage(base)
    h.rebuild_snapshot()
    h.update_tests()
    h.write_batch_test(base, shapes)
    h.update_docs(base)
    print("batch_ids=" + ",".join(h.IDS))
    print("inventory_digest=" + inventory["digest"])
    print("coverage=76/422")
    print("security_auditing=70/423")


if __name__ == "__main__":
    main()
