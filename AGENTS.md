# AGENTS.md

## Using skillcheck for a user
- Start with `python3 skillcheck.py scan`. It is free, fast and makes no model calls.
- Before `run`, tell the user the cost: roughly 1 minute per prompt per run, using their own CLI subscription. Run it in the background.
- Read `report` by its *taken by* column first. A miss is usually a competing skill, not a broken one.
- After editing a description, re-run with a new `--tag` and `compare`. Don't claim a fix without the re-run.
- Don't run prompt suites from untrusted sources without reading them first.

## Working on this repo
- Python 3 standard library only. Keep `skillcheck.py` a single file.
- `python3 skillcheck.py selftest` must print `selftest ok`.
- Server changes: `python3 check_web.py` must report every check `held`.
- Keep runs locked down (`CLAUDE_TOOLS`, `CODEX_LOCKDOWN`). Changes there need `python3 check_isolation.py`.
