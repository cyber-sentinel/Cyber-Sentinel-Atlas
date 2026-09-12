from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

LINUX = "runs-on: [self-hosted, linux, x64, atlas-ci, atlas-linux]"
WINDOWS = "runs-on: [self-hosted, windows, x64, atlas-ci, atlas-windows]"
MATRIX_OLD = """      matrix:\n        os: [ubuntu-latest, windows-latest]\n    runs-on: ${{ matrix.os }}"""
MATRIX_NEW = """      matrix:\n        os: [ubuntu-latest, windows-latest]\n        include:\n          - os: ubuntu-latest\n            runner: atlas-linux\n          - os: windows-latest\n            runner: atlas-windows\n    runs-on: [self-hosted, atlas-ci, \"${{ matrix.runner }}\"]"""

changed: list[str] = []
counts = {"linux": 0, "windows": 0, "matrix": 0}

for path in sorted(WORKFLOWS.glob("*.yml")):
    text = path.read_text(encoding="utf-8")
    original = text

    n = text.count(MATRIX_OLD)
    if n:
        text = text.replace(MATRIX_OLD, MATRIX_NEW)
        counts["matrix"] += n

    n = text.count("runs-on: ubuntu-latest")
    if n:
        text = text.replace("runs-on: ubuntu-latest", LINUX)
        counts["linux"] += n

    n = text.count("runs-on: windows-latest")
    if n:
        text = text.replace("runs-on: windows-latest", WINDOWS)
        counts["windows"] += n

    if text != original:
        path.write_text(text, encoding="utf-8")
        changed.append(path.relative_to(ROOT).as_posix())

# Reference-host workflow has a permanent contract test that intentionally
# inspects its runner boundary. Update only that assertion with the workflow.
test_path = ROOT / "tests" / "phase53" / "test_reference_host_collection.py"
if test_path.exists():
    text = test_path.read_text(encoding="utf-8")
    old = 'self.assertIn("runs-on: windows-latest", text)'
    new = 'self.assertIn("runs-on: [self-hosted, windows, x64, atlas-ci, atlas-windows]", text)'
    if old in text:
        test_path.write_text(text.replace(old, new), encoding="utf-8")
        changed.append(test_path.relative_to(ROOT).as_posix())

remaining = []
for path in sorted(WORKFLOWS.glob("*.yml")):
    text = path.read_text(encoding="utf-8")
    if (
        "runs-on: ubuntu-latest" in text
        or "runs-on: windows-latest" in text
        or "runs-on: ${{ matrix.os }}" in text
    ):
        remaining.append(path.relative_to(ROOT).as_posix())

if remaining:
    raise SystemExit("GitHub-hosted runs-on remains in: " + ", ".join(remaining))

if not changed:
    raise SystemExit("No workflow migration changes were produced")

print("Migrated workflow runner placement:")
for item in changed:
    print(f"- {item}")
print(f"replacement-counts={counts}")
