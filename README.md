# skillcheck

**Find out which of your skills is stealing the request.**

Your skill passed eval. Does it fire in *your* setup, next to everything else you installed?

Official skill evals load one skill in a clean environment. In real use it sits next to dozens of other skills and plugins, and one of them quietly takes the request. In the author's setup, prompts that fired 21/21 in an isolated `claude plugin eval` missed 5 times in the real harness.

skillcheck runs your prompts through your real `claude` and `codex` CLIs with everything you have installed, and reports which skill fired, which one stole the request, how flaky each prompt is, and whether your description fix helped.

**New: check a skill *before* you install it.** `preflight` tells you which of your installed skills a new one will take requests from, by running your existing skills' prompts with and without it in a throwaway folder. Your real skill folders are not touched. Word overlap only suggests suspects (a narrow skill can take requests with little shared wording), so name the skills you care about with `--skills`:

```bash
python3 skillcheck.py preflight path/to/new-skill            # instant: name clashes, likely rivals, listing size
python3 skillcheck.py preflight path/to/new-skill --measure  # real runs: your skills' fire rate without → with it
python3 skillcheck.py preflight path/to/new-skill --measure --skills my-a,my-b   # pick which of yours to measure
```

[Example report](https://skillcheck.vercel.app/r/S1FWWO2UHQKwhlM3eBCXtw): two skills went from 0/4 and 1/4 to 4/4 after rewriting their descriptions.

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

## For AI agents (remote MCP, no install)

A hosted, read-only MCP server runs the static checks on any public GitHub repo, which is useful before installing or publishing a skill pack:

```bash
claude mcp add --transport http skillcheck https://skillcheck.vercel.app/mcp
```

Tools:

- `preflight_skill(github_url, installed)`: call it before installing a skill. Pass the skills the user already has (name and description, which an agent can read from its own skill listing). It returns the name clashes that would shadow an installed skill, which installed skills the new one is most likely to take requests from, and how much the skill listing grows.
- `check_skill_repo(github_url)` returns the frontmatter/YAML errors, name mismatches, weak or slash-only descriptions, nested `SKILL.md` files, duplicate names, and pairs of skills whose descriptions overlap enough to compete. Real trigger measurement still needs the CLI, because it runs in *your* setup.

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

`server.py` is the share-link server (stdlib, sqlite for local runs, Vercel Blob when configured). `check_web.py [url]` attacks a running instance (XSS, oversized/deep JSON, slow clients, id guessing, rate-limit spoofing). Deploy on Vercel; the `Dockerfile` remains for self-hosting.

## FAQ

**Why isn't my Claude Code skill triggering?**
Usually another installed skill wins the request, or the description reads as slash-command only ("use as /name"). Run `scan`, then `run` + `report` and look at the *taken by* column. See the [guide](https://skillcheck.vercel.app/guide/skill-not-triggering).

**My skill passes `claude plugin eval` but doesn't fire in my normal setup. Why?**
The official eval loads the skill in a clean environment. skillcheck measures it next to everything you actually have installed.

**Which of my skills is stealing requests from another?**
`report` lists, per skill, which other skill loaded on its should-fire prompts.

**Does it work with Codex CLI?**
Yes: `run --agent codex`. Skill activation is read from the `SKILL.md` read in `codex exec --json` events.

**How do I test SKILL.md descriptions before publishing to a marketplace?**
`gen` drafts should-fire and near-miss prompts, `run` measures, you edit, then `compare` shows before/after. The remote MCP gives a quick static check of the whole repo.

**Does it send my prompts or code anywhere?**
No. Runs use your own CLI login locally. `upload` is opt-in and sends skill names and hit/miss rows only.

## Limits

- Claude Code and Codex only. Gemini CLI and Cursor: activation can't be read reliably yet — PRs welcome.
- A run takes about a minute per prompt; 10 skills × 6 prompts × 3 runs is a few hours of subscription usage.

MIT license.
