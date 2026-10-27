#!/usr/bin/env python3
"""skillcheck — does each agent skill actually fire? Static scan + real CLI trigger runs + before/after.

  scan                         static checks of Claude Code and Codex skills
  gen   --out suite.json       draft trigger / near-miss prompts with your own `claude -p`
  run   --agent claude|codex --suite suite.json --tag before [--runs 3]
  report --tag before          per-skill fire rate, false fires, who stole the request
  compare --before before --after after
  html  --tag before,after --out report.html   one-file HTML report (results embedded)
  upload --tag before,after    share link for those results (prompt texts are not sent)
  selftest
Runs use your own CLI login (subscription); nothing leaves your machine except those CLI calls.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

HOME = Path.home()
ROOTS = {  # agent -> skill folders it reads (user level, then project level relative to --project)
    "claude": [HOME / ".claude/skills", Path(".claude/skills")],
    "codex": [HOME / ".agents/skills", HOME / ".codex/skills", Path(".agents/skills")],
}
SANDBOX = Path(tempfile.gettempdir()) / "skillcheck_sandbox"
RESULTS = Path("skillcheck_results.jsonl")
SITE = "https://skillcheck-d1d57e.fly.dev"
# Prompts may come from someone else's suite, so runs get no way to act or send data out (tested 2026-10-22:
# with a blocklist, Claude read a file and called PushNotification/Artifact; Codex sent it via MCP search).
CLAUDE_TOOLS = ["--tools", "Skill"]
CODEX_LOCKDOWN = ["--ignore-user-config", "-s", "read-only", "-c", 'web_search="disabled"',
                  "-c", "features.apps=false", "-c", "features.image_generation=false"]
SLASH_ONLY = re.compile(r"형태로\s*(쓴다|사용)|^usage:\s*/|\buse (it )?as /|\binvoke (it )?(with|as) /|\btype /", re.I | re.M)
MAX_DESC, MIN_DESC = 1024, 40


# ---------- static scan ----------

def frontmatter(text):
    """Return (fields, error). fields: top-level `key: value` pairs; YAML-validated when PyYAML exists."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, "SKILL.md has no frontmatter (---)"
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        return {}, "frontmatter is not closed with ---"
    block = "\n".join(lines[1:end])
    try:
        import yaml
        data = yaml.safe_load(block)
        if not isinstance(data, dict):
            return {}, "frontmatter is not key: value pairs"
        return {k: v for k, v in data.items()}, None
    except ImportError:
        return plain_fields(block), None
    except Exception as exc:  # yaml.YAMLError — e.g. an unquoted ': ' inside description
        return {}, f"frontmatter YAML error: {str(exc).splitlines()[0]}"


def plain_fields(block):
    """Top-level fields without PyYAML: handles block scalars (|, >) and indented continuation lines."""
    fields, more, key = {}, {}, None
    for line in block.splitlines():
        m = re.match(r"^([\w-]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            fields[key], more[key] = m.group(2).strip(), []
        elif key and line[:1] in (" ", "\t"):
            more[key].append(line.strip())
    for k, v in fields.items():
        if v[:1] in ("|", ">") and v.rstrip("-+") in ("|", ">"):
            fields[k] = ("\n" if v[0] == "|" else " ").join(more[k]).strip()
        elif more[k]:
            fields[k] = " ".join([v] + more[k]).strip()
        if len(fields[k]) > 1 and fields[k][0] == fields[k][-1] and fields[k][0] in "\"'":
            fields[k] = fields[k][1:-1]
    return fields

def overrides(project):
    """skillOverrides from user, project and local Claude settings (later wins)."""
    out = {}
    for p in (HOME / ".claude/settings.json", project / ".claude/settings.json", project / ".claude/settings.local.json"):
        try:
            out.update(json.loads(p.read_text()).get("skillOverrides") or {})
        except (OSError, ValueError):
            pass
    return out


def plugin_dirs(project, home=HOME):
    """(skills dir, "plugin:" prefix) for each enabled Claude plugin (enabledPlugins in settings, later wins)."""
    on = {}
    for p in (home / ".claude/settings.json", project / ".claude/settings.json", project / ".claude/settings.local.json"):
        try:
            on.update(json.loads(p.read_text()).get("enabledPlugins") or {})
        except (OSError, ValueError):
            pass
    try:
        installed = json.loads((home / ".claude/plugins/installed_plugins.json").read_text()).get("plugins", {})
    except (OSError, ValueError):
        return []
    # ponytail: only the default skills/ folder; read plugin.json "skills" paths if a plugin moves them
    return [(Path(e["installPath"]) / "skills", key.split("@")[0] + ":")
            for key, entries in installed.items() if on.get(key) for e in entries[-1:]]


def discover(project=Path("."), roots=ROOTS, home=HOME):
    skills = []
    off = overrides(project)
    for agent, dirs in roots.items():
        extra = plugin_dirs(project, home) if agent == "claude" else []
        for d, prefix in [(d, "") for d in dirs] + extra:
            d = d if d.is_absolute() else project / d
            if not d.is_dir():
                continue
            for sk in sorted(p for p in d.iterdir() if p.is_dir()):
                f = sk / "SKILL.md"
                if not f.exists():
                    continue
                meta, err = frontmatter(f.read_text(encoding="utf-8", errors="replace"))
                name = prefix + str(meta.get("name") or sk.name)
                skills.append({"agent": agent, "dir": str(sk), "name": name,
                               "description": str(meta.get("description") or ""), "meta": meta, "error": err,
                               "override": off.get(name) if agent == "claude" else None,
                               "nested": [str(p.relative_to(sk)) for p in sk.rglob("SKILL.md") if p != f]})
    return skills


def check(sk):
    """List of (level, message). level: error | warn | info."""
    out, name, desc, meta = [], sk["name"].split(":")[-1], sk["description"], sk["meta"]  # plugin prefix off
    if sk["error"]:
        return [("error", sk["error"])]
    if not meta.get("name"):
        out.append(("warn", "no name (the folder name is used instead)"))
    elif name != Path(sk["dir"]).name:
        out.append(("warn", f"name '{name}' differs from folder name '{Path(sk['dir']).name}'"))
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name):
        out.append(("info", "Agent Skills spec (agentskills.io) names are lowercase letters, digits and hyphens; other agents may reject this name"))
    if not desc:
        out.append(("error", "no description: it is the only thing automatic triggering is based on"))
    elif len(desc) > MAX_DESC:
        out.append(("error", f"description is {len(desc)} chars, over the {MAX_DESC} limit"))
    elif len(desc) < MIN_DESC:
        out.append(("warn", f"description is short ({len(desc)} chars): without when-to-use wording it rarely wins a request"))
    if SLASH_ONLY.search(desc):
        out.append(("warn", "description reads as slash-command only (\"use as /name\"), which can stop automatic triggering "
                            "(measured: 0/4 before, 4/4 after removing that wording)"))
    if str(meta.get("disable-model-invocation")).lower() == "true":
        out.append(("info", "disable-model-invocation: true, never triggers automatically (ignore if intended)"))
    if sk["override"] not in (None, "on"):
        out.append(("info", f"settings.json skillOverrides is '{sk['override']}': this skill is turned off"))
    if sk["nested"]:
        out.append(("warn", f"nested SKILL.md in subfolders ({', '.join(sk['nested'][:3])}): Codex registers each one as a separate skill"))
    return out


def scan(args):
    skills = discover(Path(args.project))
    dup = Counter((s["agent"], s["name"]) for s in skills)
    report = []
    for s in skills:
        issues = check(s) + ([("warn", "another skill with the same name exists for this agent")] if dup[(s["agent"], s["name"])] > 1 else [])
        report.append({"agent": s["agent"], "name": s["name"], "dir": s["dir"], "issues": issues})
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
        return
    for agent in ROOTS:
        mine = [r for r in report if r["agent"] == agent]
        print(f"== {agent}: {len(mine)} skills")
        for r in mine:
            mark = "OK " if not r["issues"] else ("ERR" if any(l == "error" for l, _ in r["issues"]) else "!  ")
            print(f"  {mark} {r['name']:28} {r['dir']}")
            for level, msg in r["issues"]:
                print(f"       [{level}] {msg}")


def enabled(agent, project):
    return [s for s in discover(project) if s["agent"] == agent and not s["error"]
            and s["override"] in (None, "on") and str(s["meta"].get("disable-model-invocation")).lower() != "true"]


# ---------- prompt generation ----------

def gen(args):
    skills = enabled("claude", Path(args.project))
    if args.skills:
        skills = [s for s in skills if s["name"] in args.skills.split(",")]
    listing = "\n".join(f"- {s['name']}: {s['description']}" for s in enabled("claude", Path(args.project)))
    suite = {"note": "skillcheck gen: prompts were written by a model from the descriptions, so they lean toward the description wording. Replace them with real requests where you can.",
             "skills": {}}
    for s in skills:
        prompt = (f"An AI coding agent has these skills (name: description):\n{listing}\n\n"
                  f"Target skill: {s['name']}\n"
                  "Write user requests to test whether the agent auto-invokes the target skill. "
                  "pos: 3 realistic requests a user would type that SHOULD invoke it, phrased naturally, "
                  "never naming the skill or using a slash command, and not copying the description's wording. "
                  "neg: 3 near-miss requests on a similar topic that should NOT invoke it. "
                  "Use the same language as the description. "
                  'Reply with JSON only: {"pos": [...], "neg": [...]}')
        out = subprocess.run(["claude", "-p", prompt, "--model", args.model, "--output-format", "json",
                              "--setting-sources", "project,local", "--strict-mcp-config", "--no-session-persistence",
                              "--max-turns", "1", "--tools", ""],
                             cwd=SANDBOX_dir(), capture_output=True, text=True, timeout=300)
        m = re.search(r"\{.*\}", json.loads(out.stdout).get("result", ""), re.S)
        cases = json.loads(m.group(0)) if m else {"pos": [], "neg": []}
        suite["skills"][s["name"]] = {"pos": cases.get("pos", [])[:3], "neg": cases.get("neg", [])[:3]}
        print(f"{s['name']}: pos {len(suite['skills'][s['name']]['pos'])} / neg {len(suite['skills'][s['name']]['neg'])}", flush=True)
    Path(args.out).write_text(json.dumps(suite, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"→ {args.out}  (read and edit the prompts, then run)")


def SANDBOX_dir():
    SANDBOX.mkdir(exist_ok=True)
    return SANDBOX


# ---------- real runs ----------

def claude_pick(line):
    """Skill name from one stream-json line, or None."""
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if event.get("type") != "assistant":
        return None
    for block in event.get("message", {}).get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "Skill":
            return block.get("input", {}).get("skill") or "?"
    return None


CODEX_SKILL = re.compile(r"skills/([^/\s'\"]+)/SKILL\.md")


def codex_pick(line):
    """Skill name when a codex exec --json event opens <skills>/<name>/SKILL.md, or None."""
    try:
        item = json.loads(line).get("item") or {}
    except ValueError:
        return None
    if item.get("type") != "command_execution":
        return None
    m = CODEX_SKILL.search(item.get("command", ""))
    return m.group(1) if m else None


def codex_model_args():
    """Keep the user's default model and effort even though the rest of ~/.codex/config.toml is ignored."""
    try:
        conf = __import__("tomllib").loads((HOME / ".codex/config.toml").read_text())
    except (OSError, ValueError, ImportError):
        return []
    return [x for k in ("model", "model_reasoning_effort") if k in conf for x in ("-c", f"{k}={json.dumps(conf[k])}")]


def agent_cmd(agent, text, cwd, model):
    if agent == "claude":
        return ["claude", "-p", text, "--output-format", "stream-json", "--verbose",
                "--settings", '{"disableAllHooks": true}', "--strict-mcp-config", "--no-session-persistence",
                "--max-turns", "3", *CLAUDE_TOOLS] + (["--model", model] if model else [])
    # ponytail: ignoring user config also drops Codex plugin skills; scan does not cover them yet either
    return ["codex", "exec", "--json", "--skip-git-repo-check", *CODEX_LOCKDOWN, *codex_model_args(),
            "-C", str(cwd), text] + (["-m", model] if model else [])


def run_once(agent, text, cwd, model, timeout=240):
    cmd, pick = agent_cmd(agent, text, cwd, model), claude_pick if agent == "claude" else codex_pick
    proc = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    timer = __import__("threading").Timer(timeout, proc.kill)
    timer.start()
    try:
        for line in proc.stdout:
            name = pick(line)
            if name:
                return name  # stop before the skill does any work
        return "none" if proc.wait() == 0 else "ERROR"
    finally:
        timer.cancel()
        proc.kill()
        proc.wait()


def load_suite(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [{"id": f"{s}/{k}{i}", "skill": s, "kind": k, "text": t}
            for s, g in data["skills"].items() for k in ("pos", "neg") for i, t in enumerate(g.get(k, []))]


def read_rows(path=None):
    p = Path(path or RESULTS)
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def run(args):
    out = Path(args.results)
    done = {(r["agent"], r["id"], r["run"]) for r in read_rows(out) if r["tag"] == args.tag}
    cwd = Path(args.cwd) if args.cwd else SANDBOX_dir()
    todo = [(c, k) for c in load_suite(args.suite) for k in range(args.runs) if (args.agent, c["id"], k) not in done]
    for n, (case, k) in enumerate(todo, 1):
        picked = run_once(args.agent, case["text"], cwd, args.model)
        with out.open("a") as f:
            f.write(json.dumps({"tag": args.tag, "agent": args.agent, "run": k, **case, "picked": picked},
                               ensure_ascii=False) + "\n")
        print(f"[{n}/{len(todo)}] {args.agent} {case['id']}#{k} -> {picked}", flush=True)


# ---------- report / compare ----------

def stats(rows):
    """skill -> dict(pos_fire, pos_n, neg_fire, neg_n, stolen Counter, neg_to Counter, flaky ids)."""
    out = {}
    by_case = {}
    for r in rows:
        s = out.setdefault(r["skill"], {"pos_fire": 0, "pos_n": 0, "neg_fire": 0, "neg_n": 0, "stolen": Counter(), "neg_to": Counter(), "flaky": set()})
        hit = r["picked"] == r["skill"]
        s[r["kind"] + "_n"] += 1
        s[r["kind"] + "_fire"] += hit
        if r["kind"] == "pos" and not hit and r["picked"] not in ("none", "ERROR"):
            s["stolen"][r["picked"]] += 1
        if r["kind"] == "neg" and not hit and r["picked"] not in ("none", "ERROR"):
            s["neg_to"][r["picked"]] += 1
        by_case.setdefault((r["skill"], r["id"]), set()).add(hit)
    for (skill, cid), hits in by_case.items():
        if len(hits) > 1:
            out[skill]["flaky"].add(cid)
    return out


def pct(a, n):
    return f"{a}/{n}" + (f" ({a / n:.0%})" if n else "")


def report(args):
    rows = [r for r in read_rows(args.results) if r["tag"] == args.tag and (not args.agent or r["agent"] == args.agent)]
    for agent in sorted({r["agent"] for r in rows}):
        print(f"== {agent} [{args.tag}]  {'skill':26} {'fires':16} {'false fires':12} taken by / near-miss → other / flaky")
        for skill, s in sorted(stats([r for r in rows if r["agent"] == agent]).items()):
            print(f"   {skill:34} {pct(s['pos_fire'], s['pos_n']):16} {pct(s['neg_fire'], s['neg_n']):12} "
                  f"{dict(s['stolen']) or '-'} / {dict(s['neg_to']) or '-'} / {sorted(s['flaky']) or '-'}")


def compare(args):
    rows = read_rows(args.results)
    for agent in sorted({r["agent"] for r in rows if r["tag"] in (args.before, args.after)}):
        b = stats([r for r in rows if r["tag"] == args.before and r["agent"] == agent])
        a = stats([r for r in rows if r["tag"] == args.after and r["agent"] == agent])
        print(f"== {agent}: {args.before} → {args.after}")
        for skill in sorted(set(a) | set(b)):
            x, y = b.get(skill), a.get(skill)
            f = lambda s, k: pct(s[k + "_fire"], s[k + "_n"]) if s else "-"
            print(f"   {skill:28} fires {f(x, 'pos'):12} → {f(y, 'pos'):12}  false {f(x, 'neg'):10} → {f(y, 'neg')}")


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>skillcheck report</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--mute:#6b6b6b;--line:#e3e3e3;--bad:#b42318;--good:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#161616;--fg:#ececec;--mute:#9a9a9a;--line:#333;--bad:#f97066;--good:#47cd89}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:960px;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}p{color:var(--mute);margin:0 0 12px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--mute);font-weight:500}
.bad{color:var(--bad)}.good{color:var(--good)}small{color:var(--mute)}a{color:inherit}footer{margin-top:32px;color:var(--mute);font-size:14px}
</style></head><body><h1>skillcheck report</h1><p>{sub}</p>{body}
<footer>Do your agent skills actually fire in your real setup? <a href="{site}/">Check yours with skillcheck</a> (<a href="https://github.com/Noem836/skillcheck">GitHub</a>) — free, runs locally with your own Claude Code / Codex.</footer>
<script type="application/json" id="skillcheck-data">{data}</script></body></html>""".replace("{site}", SITE)


def render_html(rows, tags):
    esc = __import__("html").escape
    body = []
    for agent in sorted({r["agent"] for r in rows}):
        st = {t: stats([r for r in rows if r["agent"] == agent and r["tag"] == t]) for t in tags}
        head = "".join(f"<th>fires · {esc(t)}</th><th>false fires · {esc(t)}</th>" for t in tags)
        trs = []
        for skill in sorted(set().union(*st.values())):
            cells, last = "", st[tags[-1]].get(skill)
            for t in tags:
                s = st[t].get(skill)
                if not s:
                    cells += "<td>-</td><td>-</td>"
                    continue
                miss = s["pos_n"] and s["pos_fire"] < s["pos_n"]
                cells += (f"<td class='{'bad' if miss else 'good' if s['pos_n'] else ''}'>{pct(s['pos_fire'], s['pos_n'])}</td>"
                          f"<td class='{'bad' if s['neg_fire'] else ''}'>{pct(s['neg_fire'], s['neg_n'])}</td>")
            who = lambda c: ", ".join(f"{esc(k)} {v}" for k, v in c.items()) or "-"
            trs.append(f"<tr><td>{esc(skill)}</td>{cells}<td>{who(last['stolen']) if last else '-'}</td>"
                       f"<td>{who(last['neg_to']) if last else '-'}</td><td>{len(last['flaky']) if last else '-'}</td></tr>")
        body.append(f"<h2>{esc(agent)}</h2><div class='wrap'><table><tr><th>skill</th>{head}<th>taken by</th>"
                    f"<th>near-miss → other skill</th><th>flaky prompts</th></tr>{''.join(trs)}</table></div>")
    sub = (f"tags {' → '.join(map(esc, tags))} · {len(rows)} real CLI runs · fires = share of should-fire prompts where that skill was loaded. "
           f"'taken by' and flaky are for the last tag")
    data = json.dumps(rows, ensure_ascii=False).replace("<", "\\u003c")  # no tag can open inside the data block
    parts = {"sub": sub, "body": "".join(body), "data": data}
    return re.sub(r"\{(sub|body|data)\}", lambda m: parts[m.group(1)], PAGE)  # one pass: user text can't hit a slot


def html(args):
    tags = args.tag.split(",")
    rows = [r for r in read_rows(args.results) if r["tag"] in tags and (not args.agent or r["agent"] == args.agent)]
    Path(args.out).write_text(render_html(rows, tags), encoding="utf-8")
    print(f"wrote {args.out} ({len(rows)} rows)")


def upload(args):
    import urllib.request
    tags = args.tag.split(",")
    keep = ("tag", "agent", "run", "id", "skill", "kind", "picked")  # prompt texts stay on this machine
    rows = [{k: r[k] for k in keep} for r in read_rows(args.results) if r["tag"] in tags and (not args.agent or r["agent"] == args.agent)]
    if not rows:
        sys.exit(f"no rows with tag {args.tag} in {args.results}")
    req = urllib.request.Request(args.server + "/api/reports", json.dumps(rows).encode(), {"Content-Type": "application/json"})
    try:
        res = json.load(urllib.request.urlopen(req, timeout=30))
    except urllib.error.HTTPError as e:
        sys.exit(f"upload failed: {e.code} {e.read().decode()[:200]}")
    print(f"{args.server}{res['url']}\n({len(rows)} rows; anyone with the link can view. delete: "
          f"curl -X DELETE -H 'Authorization: Bearer {res['delete_token']}' {args.server}/api/reports/{res['url'][3:]})")


# ---------- self-test ----------

def selftest():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        def mk(name, fm, nested=False):
            d = root / "skills" / name
            d.mkdir(parents=True)
            (d / "SKILL.md").write_text(fm)
            if nested:
                (d / "sub").mkdir()
                (d / "sub/SKILL.md").write_text("---\nname: x\n---\n")
        mk("good-one", "---\nname: good-one\ndescription: 사용자가 PDF 표를 CSV로 바꿔 달라고 하거나 표 추출이 필요할 때 쓴다. 이미지 OCR에는 쓰지 않는다.\n---\nbody")
        mk("EASY", '---\nname: EASY\ndescription: 뒤에 붙은 내용을 쉬운 말로 설명한다. "/EASY <질문>" 형태로 쓴다. 대상 무관하게 쓴다.\n---\n')
        mk("mismatch", "---\nname: other\ndescription: short\n---\n", nested=True)
        mk("badyaml", "---\nname: badyaml\ndescription: 예: 콜론 뒤 공백: 이런 문장은 깨진다\n---\n")
        mk("nofm", "just text")
        pl = root / "plug/skills/tidy"
        pl.mkdir(parents=True)
        (pl / "SKILL.md").write_text("---\nname: tidy\ndescription: x\n---\n")
        (root / ".claude/plugins").mkdir(parents=True)
        (root / ".claude/plugins/installed_plugins.json").write_text(json.dumps({"plugins": {"p@m": [{"installPath": str(root / "plug")}], "q@m": [{"installPath": "/nope"}]}}))
        (root / ".claude/settings.json").write_text(json.dumps({"enabledPlugins": {"p@m": True, "q@m": False}, "skillOverrides": {"p:tidy": "off"}}))
        assert [(s["name"], s["override"]) for s in discover(root, {"claude": []}, home=root)] == [("p:tidy", "off")]
        (root / ".claude/settings.json").unlink()
        skills = {s["dir"].split("/")[-1]: s for s in discover(root, {"claude": [root / "skills"]}, home=root)}
        msgs = {k: " ".join(m for _, m in check(v)) for k, v in skills.items()}
        assert msgs["good-one"] == "", msgs["good-one"]
        assert "slash-command only" in msgs["EASY"] and "lowercase" in msgs["EASY"]
        assert "folder name" in msgs["mismatch"] and "short" in msgs["mismatch"] and "nested" in msgs["mismatch"]
        assert "frontmatter" in msgs["nofm"]
        f = plain_fields('name: x\ndescription: |-\n  line one\n  line two\nlicense: MIT\nother: >\n  a\n  b\nq: "quoted"')
        assert f == {"name": "x", "description": "line one\nline two", "license": "MIT", "other": "a b", "q": "quoted"}, f
        try:
            import yaml  # noqa: F401
            assert "YAML" in msgs["badyaml"], msgs["badyaml"]
        except ImportError:
            pass
    skill_line = json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Skill", "input": {"skill": "EASY"}}]}})
    assert claude_pick(skill_line) == "EASY" and claude_pick("junk") is None and claude_pick('{"type":"result"}') is None
    cx = json.dumps({"type": "item.started", "item": {"type": "command_execution", "command": "/bin/zsh -lc 'cat /Users/u/.agents/skills/deep-research/SKILL.md'"}})
    assert codex_pick(cx) == "deep-research"
    assert codex_pick(json.dumps({"item": {"type": "command_execution", "command": "ls"}})) is None
    rows = [{"skill": "a", "kind": "pos", "id": "a/pos0", "picked": "a"}, {"skill": "a", "kind": "pos", "id": "a/pos0", "picked": "b"},
            {"skill": "a", "kind": "neg", "id": "a/neg0", "picked": "none"}, {"skill": "a", "kind": "neg", "id": "a/neg1", "picked": "c"}]
    s = stats(rows)["a"]
    assert (s["pos_fire"], s["pos_n"], s["neg_fire"], dict(s["stolen"]), dict(s["neg_to"]), s["flaky"]) == (1, 2, 0, {"b": 1}, {"c": 1}, {"a/pos0"})
    print("selftest ok")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["scan", "gen", "run", "report", "compare", "html", "upload", "selftest"])
    p.add_argument("--project", default=".", help="project root for .claude/.agents skills and settings")
    p.add_argument("--json", action="store_true")
    p.add_argument("--agent", choices=["claude", "codex"])
    p.add_argument("--suite", default="suite.json")
    p.add_argument("--out", default="suite.json")
    p.add_argument("--skills", help="comma-separated subset for gen")
    p.add_argument("--model", default=None, help="model for run (default: your CLI default); gen defaults to sonnet")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--tag", default="before")
    p.add_argument("--before", default="before")
    p.add_argument("--after", default="after")
    p.add_argument("--cwd", help="where the agent runs (default: an empty temp dir, so only user-level skills load)")
    p.add_argument("--results", default=str(RESULTS))
    p.add_argument("--server", default=SITE, help="report server for upload")
    args = p.parse_args()
    if args.cmd == "html" and args.out == "suite.json":
        args.out = "skillcheck_report.html"
    if args.cmd == "gen":
        args.model = args.model or "sonnet"
    if args.cmd == "run" and not args.agent:
        p.error("run needs --agent claude|codex")
    {"scan": scan, "gen": gen, "run": run, "report": report, "compare": compare, "html": html, "upload": upload}.get(args.cmd, lambda a: selftest())(args)


if __name__ == "__main__":
    sys.exit(main())
