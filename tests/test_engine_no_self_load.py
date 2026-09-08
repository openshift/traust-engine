"""Engine never resolves its own config — composition root is the app."""

from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "traust_engine"


def test_no_harness_load_outside_engine_class():
    hits = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "engine.py":
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "HarnessEngine.load(" in line:
                hits.append(f"{path.relative_to(SRC)}:{i}:{line.strip()}")
    assert hits == [], "HarnessEngine.load() in engine library:\n" + "\n".join(hits)
