#!/usr/bin/env python3
"""skillcheck report server — upload results, get a share link. Local prototype, stdlib only.

  python3 server.py [--port 8787] [--db reports.db]
  POST   /api/reports            body: JSON array of result rows → {"url", "delete_token"}
  GET    /r/<id>                 report page
  DELETE /api/reports/<id>       header  Authorization: Bearer <delete_token>

Only the fields the report needs are stored; prompt texts are dropped on upload.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from skillcheck import SITE, render_html

DEMO = "S1FWWO2UHQKwhlM3eBCXtw"  # id of the example report on the live server
CLI = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "skillcheck.py"), "rb").read()

MAX_BODY = 1_000_000
MAX_ROWS = 5000
FIELDS = {"tag": str, "agent": str, "run": int, "id": str, "skill": str, "kind": str, "picked": str}
ID_RE = re.compile(r"[A-Za-z0-9_-]{22}")
UPLOADS_PER_HOUR = 20
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000",  # ignored by browsers over plain http
}

LANDING = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>skillcheck — do your agent skills actually fire?</title>
<meta name="description" content="Measure whether your Claude Code and Codex skills really trigger in your own setup, next to all your other skills. Free, local, uses your own CLI login.">
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mute:#6b6b6b;--line:#e3e3e3;--code:#f4f4f4}
@media (prefers-color-scheme:dark){:root{--bg:#161616;--fg:#ececec;--mute:#9a9a9a;--line:#333;--code:#232323}}
body{background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif;margin:0 auto;max-width:720px;padding:32px 16px}
h1{font-size:28px;line-height:1.25;margin:0 0 12px}h2{font-size:18px;margin:32px 0 8px}p,li{color:var(--fg)}.mute{color:var(--mute)}
pre{background:var(--code);padding:12px 14px;border-radius:8px;overflow-x:auto;font-size:14px}code{font-size:14px}a{color:inherit}
</style></head><body>
<h1>Your skill passed eval. Does it fire in <em>your</em> setup?</h1>
<p>Official skill evals run each skill alone. In real use it sits next to dozens of other skills and plugins, and one of them quietly takes the request.
In our own test, 21/21 prompts fired in an isolated eval; the same prompts missed 5 times in the real harness.</p>
<p><strong>skillcheck</strong> runs your prompts through your real <code>claude</code> and <code>codex</code> CLIs, with all your skills loaded, and tells you which skill fired, which one stole the request, and whether your fix helped.</p>
<p><a href="/r/{demo}">See an example report</a> — two skills went from 0/4 and 1/4 to 4/4 after rewriting their descriptions.</p>
<h2>Try it (one file, Python 3 stdlib — <a href="https://github.com/Noem836/skillcheck">source on GitHub</a>)</h2>
<pre>curl -O https://raw.githubusercontent.com/Noem836/skillcheck/main/skillcheck.py
python3 skillcheck.py scan                      # static checks, no model calls
python3 skillcheck.py gen --skills my-skill     # draft should-fire / near-miss prompts
python3 skillcheck.py run --agent claude --tag before
python3 skillcheck.py report --tag before       # fire rate, false fires, who took it
python3 skillcheck.py upload --tag before       # optional share link</pre>
<h2>What it checks</h2>
<ul><li>Discovery per agent: Claude Code (user, project, plugins, <code>skillOverrides</code>) and Codex skill folders</li>
<li>Frontmatter, name/folder mismatch, nested SKILL.md, slash-only wording, <code>disable-model-invocation</code></li>
<li>Real trigger runs, repeated per prompt, so flaky skills show up as rates</li>
<li>Competition: which other skill grabbed the prompt</li>
<li>Before/after compare after you edit a description</li></ul>
<h2>Privacy</h2>
<p class="mute">Runs use your own CLI login on your machine; nothing is sent to us. Runs are locked down: Claude gets only the Skill tool, Codex runs without your MCP servers, web search or plugins.
<code>upload</code> is opt-in and sends only skill names and hit/miss rows, never prompt texts.</p>
</body></html>"""


def clean(rows):
    """Validated copy with only known fields, or raise ValueError."""
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_ROWS:
        raise ValueError(f"expected a list of 1..{MAX_ROWS} rows")
    out = []
    for r in rows:
        if not isinstance(r, dict):
            raise ValueError("row is not an object")
        row = {}
        for k, t in FIELDS.items():
            v = r.get(k)
            if type(v) is not t or (t is str and not 0 < len(v) <= 200) or (t is int and not 0 <= v < 1000):
                raise ValueError(f"bad field {k}")
            row[k] = v
        if row["kind"] not in ("pos", "neg"):
            raise ValueError("bad field kind")
        out.append(row)
    return out


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.db:
            self.db.execute("CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, del TEXT, created INT, rows TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS uploads (who TEXT, t REAL)")  # rate limit, survives restarts
            self.db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
            self.db.execute("INSERT OR IGNORE INTO meta VALUES ('ip_key', ?)", (secrets.token_hex(32),))
        self.ip_key = self.db.execute("SELECT v FROM meta WHERE k = 'ip_key'").fetchone()[0].encode()

    def who(self, ip):
        """Keyed hash: the db never holds raw IPs, and IPv4 can't be brute-forced back without the key."""
        return hmac.new(self.ip_key, ip.encode(), "sha256").hexdigest()

    def limited(self, who, now):
        with self.lock:
            n = self.db.execute("SELECT COUNT(*) FROM uploads WHERE who = ? AND t > ?", (who, now - 3600)).fetchone()[0]
        return n >= UPLOADS_PER_HOUR

    def add(self, rows, who):
        """(id, delete token), or None when this client is over the limit (checked again under the lock)."""
        rid, token, now = secrets.token_urlsafe(16), secrets.token_urlsafe(24), time.time()
        with self.lock, self.db:
            self.db.execute("DELETE FROM uploads WHERE t <= ?", (now - 3600,))
            if self.db.execute("SELECT COUNT(*) FROM uploads WHERE who = ?", (who,)).fetchone()[0] >= UPLOADS_PER_HOUR:
                return None
            self.db.execute("INSERT INTO uploads VALUES (?, ?)", (who, now))
            self.db.execute("INSERT INTO reports VALUES (?, ?, ?, ?)",
                            (rid, hashlib.sha256(token.encode()).hexdigest(), int(now), json.dumps(rows)))
        return rid, token

    def get(self, rid):
        with self.lock:
            row = self.db.execute("SELECT rows FROM reports WHERE id = ?", (rid,)).fetchone()
        return json.loads(row[0]) if row else None

    def delete(self, rid, token):
        with self.lock, self.db:
            row = self.db.execute("SELECT del FROM reports WHERE id = ?", (rid,)).fetchone()
            if not row or not hmac.compare_digest(row[0], hashlib.sha256(token.encode()).hexdigest()):
                return False
            self.db.execute("DELETE FROM reports WHERE id = ?", (rid,))
        return True


class Handler(BaseHTTPRequestHandler):
    store: Store = None
    timeout = 10  # drop clients that send too slowly
    server_version = "skillcheck"
    default_request_version = "HTTP/1.0"  # stdlib answers malformed lines as HTTP/0.9 = no headers at all
    sys_version = ""

    def send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def end_headers(self):  # every response, including the stdlib's own error pages (HEAD, PUT, bad request line)
        for k, v in HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def client_ip(self):
        # On Fly the socket peer is Fly's proxy, which sets Fly-Client-IP. check_web.py <url> tests spoofing.
        if os.environ.get("FLY_APP_NAME") and self.headers.get("Fly-Client-IP"):
            return self.headers["Fly-Client-IP"]
        return self.client_address[0]

    def rid(self, prefix):
        rid = self.path[len(prefix):] if self.path.startswith(prefix) else ""
        return rid if ID_RE.fullmatch(rid) else None

    def do_GET(self):
        if self.path == "/":
            return self.send(200, LANDING.replace("{site}", SITE).replace("{demo}", DEMO), "text/html; charset=utf-8")
        if self.path == "/skillcheck.py":
            return self.send(200, CLI, "text/x-python; charset=utf-8")
        rid = self.rid("/r/")
        rows = rid and self.store.get(rid)
        if not rows:
            return self.send(404, {"error": "not found"})
        tags = list(dict.fromkeys(r["tag"] for r in rows))
        self.send(200, render_html(rows, tags), "text/html; charset=utf-8")

    def do_POST(self):
        if self.path != "/api/reports":
            return self.send(404, {"error": "not found"})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self.send(415, {"error": "send application/json"})
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.send(411, {"error": "Content-Length required"})
        if not 0 < n <= MAX_BODY:
            return self.send(413, {"error": f"body must be 1..{MAX_BODY} bytes"})
        # ponytail: sqlite on one machine's volume; a second machine would need a shared db
        who = self.store.who(self.client_ip())
        if self.store.limited(who, time.time()):  # cheap reject before reading the body
            return self.send(429, {"error": "too many uploads, try later"})
        try:
            rows = clean(json.loads(self.rfile.read(n)))
        except (ValueError, UnicodeDecodeError, RecursionError) as e:
            return self.send(400, {"error": str(e)[:200]})
        added = self.store.add(rows, who)
        if not added:
            return self.send(429, {"error": "too many uploads, try later"})
        rid, token = added
        self.send(201, {"url": f"/r/{rid}", "delete_token": token})

    def do_DELETE(self):
        rid = self.rid("/api/reports/")
        auth = self.headers.get("Authorization", "")
        if not rid or not auth.startswith("Bearer ") or not self.store.delete(rid, auth[7:]):
            return self.send(404, {"error": "not found"})  # same answer for wrong id and wrong token
        self.send(200, {"deleted": True})

    def log_message(self, fmt, *args):  # no request paths (they are share links) in logs
        pass


def serve(port=8787, db="reports.db", host="127.0.0.1"):
    Handler.store = Store(db)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--db", default="reports.db")
    p.add_argument("--host", default="127.0.0.1", help="0.0.0.0 only inside a container")
    a = p.parse_args()
    print(f"listening on {a.host}:{a.port}", flush=True)
    serve(a.port, a.db, a.host).serve_forever()
