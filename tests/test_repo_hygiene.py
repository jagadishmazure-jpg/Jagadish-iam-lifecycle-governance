import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_brands  # noqa: E402


def test_brand_blocklist_non_empty():
    assert len(check_brands.TERM_HASHES) >= 50 and len(check_brands.SPELLING_HASHES) >= 50


def test_brand_check_catches_planted_name():
    term = "Acme Widgets"
    th = {check_brands.digest(term.lower())}
    sh = {check_brands.digest(term)}
    assert check_brands.find_hits("we use Acme Widgets here", th, sh) == ["Acme Widgets"]
    assert check_brands.find_hits("acme widgets lowercase", th, sh) == []


def test_brand_check_passes_on_repo():
    r = subprocess.run([sys.executable, "scripts/check_brands.py"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_blocklist_has_no_plain_names():
    src = (ROOT / "scripts/check_brands.py").read_text()
    assert all(check_brands.find_hits(line) == [] for line in src.splitlines())


def test_overlap_script_present():
    assert (ROOT / "scripts/overlap_check.py").exists()


def test_actions_pinned_to_sha():
    import re

    for wf in (ROOT / ".github/workflows").glob("*.yml"):
        for line in wf.read_text().splitlines():
            m = re.search(r"uses:\s*([^\s#]+)", line)
            if m and not m.group(1).startswith("./"):
                assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{wf.name}: {m.group(1)}"


def test_no_real_secrets_or_personal_email():
    for p in ROOT.rglob("*"):
        if p.is_file() and ".git" not in p.parts and p.suffix in {".py", ".md", ".yml", ".toml"}:
            t = p.read_text(errors="ignore")
            assert "BEGIN " + "PRIVATE KEY" not in t
            assert "@" + "gmail.com" not in t


def test_required_docs_exist():
    for f in [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "docs/architecture.md",
        "docs/how-it-works.md",
        "docs/implementation-guide.md",
        "docs/interview-points.md",
        "docs/threat-model.md",
        "docs/limitations.md",
        "docs/guardrails.md",
        "docs/results.md",
        "docs/running.md",
    ]:
        assert (ROOT / f).exists(), f
