# skillcheck

**Your skill passed eval. Does it fire in *your* setup?**

Official skill evals load one skill in a clean environment. In real use it sits next to dozens of other skills and plugins, and one of them quietly takes the request. In the author's setup, prompts that fired 21/21 in an isolated `claude plugin eval` missed 5 times in the real harness.

skillcheck runs your prompts through your real `claude` and `codex` CLIs with everything you have installed, and reports which skill fired, which one stole the request, how flaky each prompt is, and whether your description fix helped.

[Example report](https://skillcheck-d1d57e.fly.dev/r/S1FWWO2UHQKwhlM3eBCXtw): two skills went from 0/4 and 1/4 to 4/4 after rewriting their descriptions.

## Install

As a Claude Code plugin (the `skillcheck` skill walks you through scan → run → fix → re-run):

```
/plugin install skillcheck --marketplace Noem836/skillcheck
```

Or as one file (Python 3 standard library; PyYAML is used for frontmatter checks if installed). Pin a release and check its hash:

```bash
curl -fsSLO https://raw.githubusercontent.com/Noem836/skillcheck/v0.1.0/skillcheck.py
shasum -a 256 skillcheck.py   # compare with the release notes
```

## Use

```bash
python3 skillcheck.py scan                          # static checks, no model calls
python3 skillcheck.py gen --skills my-skill         # draft should-fire / near-miss prompts → suite.json
python3 skillcheck.py run --agent claude --tag before --runs 3
python3 skillcheck.py report --tag before           # fire rate, false fires, who took it
# edit the description, then
python3 skillcheck.py run --agent claude --tag after --runs 3
python3 skillcheck.py compare --before before --after after
python3 skillcheck.py html --tag before,after       # one-file HTML report
python3 skillcheck.py upload --tag before,after     # optional share link
```

## What it checks

- **Discovery**: Claude Code (`~/.claude/skills`, `.claude/skills`, enabled plugins, `skillOverrides`) and Codex (`~/.agents/skills`, `~/.codex/skills`, `.agents/skills`)
- **Static**: missing/broken frontmatter, name vs folder mismatch, too short/long descriptions, nested `SKILL.md`, slash-only wording, `disable-model-invocation`, duplicate names
- **Real triggers**: each prompt run N times; the first skill loaded is recorded and the run is stopped
- **Competition**: which other skill grabbed a should-fire prompt, and where near-miss prompts went

## Safety

Prompt suites and third-party skills may contain prompt injection, so runs are locked down:
Claude runs with `--tools Skill` only; Codex runs with `--ignore-user-config`, no web search, no apps/plugins, read-only sandbox. `python3 check_isolation.py` verifies this with a canary file.

Runs use your own CLI login and subscription. Nothing is sent anywhere unless you run `upload`, which sends skill names and hit/miss rows only — never prompt texts.

## Report server

`server.py` is the share-link server (stdlib + sqlite). `check_web.py [url]` attacks a running instance (XSS, oversized/deep JSON, slow clients, id guessing, rate-limit spoofing). Deploy with the included `Dockerfile` / `fly.toml`.

## Limits

- Claude Code and Codex only. Gemini CLI and Cursor: activation can't be read reliably yet — PRs welcome.
- A run takes about a minute per prompt; 10 skills × 6 prompts × 3 runs is a few hours of subscription usage.

MIT license.
