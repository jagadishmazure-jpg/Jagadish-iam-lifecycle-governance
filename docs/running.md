# Running it

## Offline (the only mode; free)
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
iamlc demo                 # naive vs full table
iamlc demo --json          # all metrics
pytest -q                  # full suite
python scripts/count_tests.py
python scripts/check_brands.py
python scripts/render_docs.py --check
```
Python 3.11+ and no network access are needed.

## Regenerating numbers
`scripts/render_docs.py` reruns the scenario and the test collector and rewrites the marked blocks in
README.md, results.md and interview-points.md. CI runs it with `--check` and fails if any number is stale.

## Originality check
`python scripts/overlap_check.py /path/to/transcript.txt` reports any 8-word run shared with a reference
text. The reference is never committed.

## CI
| Workflow | What it does |
|---|---|
| `ci.yml` | ruff lint and format check, pytest, test count, doc drift check, brand check, gitleaks over full history |
| `codeql.yml` | CodeQL for Python and for the workflow files |
| Dependabot | weekly pip and actions updates |

## Cloud
Nothing here creates cloud resources. If you later connect a real identity provider, use a free developer
tenant and keep the provisioning target a test app.
