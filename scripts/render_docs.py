"""Regenerate the numbers in README.md and docs/ from a real run, or check they are current.

Blocks between `<!-- BEGIN:name -->` and `<!-- END:name -->` are replaced:
  demo   -> the table printed by `iamlc demo`
  tests  -> the collected test count
  orphans-> the orphan list from the full run

    python scripts/render_docs.py          # rewrite
    python scripts/render_docs.py --check  # exit 1 if anything is stale (CI)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from count_tests import count  # noqa: E402

from iamlc.cli import table  # noqa: E402
from iamlc.scenario import run  # noqa: E402

FILES = ["README.md", "docs/results.md", "docs/interview-points.md"]


def blocks() -> dict[str, str]:
    full, naive = run(naive=False), run(naive=True)
    return {
        "demo": table(full, naive),
        "tests": str(count()),
        "orphans": ", ".join(full["orphans"]),
    }


def render(text: str, values: dict[str, str]) -> str:
    for name, value in values.items():
        pat = re.compile(rf"(<!-- BEGIN:{name} -->)(.*?)(<!-- END:{name} -->)", re.S)
        sep = "\n" if name == "demo" else ""
        text = pat.sub(lambda m, v=value, s=sep: f"{m.group(1)}{s}{v}{s}{m.group(3)}", text)
    return text


def main(argv: list[str]) -> int:
    check = "--check" in argv
    values = blocks()
    stale = []
    for f in FILES:
        p = ROOT / f
        if not p.exists():
            continue
        old = p.read_text()
        new = render(old, values)
        if old != new:
            stale.append(f)
            if not check:
                p.write_text(new)
    if check and stale:
        print("stale generated blocks in: " + ", ".join(stale) + " (run python scripts/render_docs.py)")
        return 1
    print(f"docs {'checked' if check else 'rendered'}: tests={values['tests']}, files={len(FILES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
