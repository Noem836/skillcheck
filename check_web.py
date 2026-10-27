#!/usr/bin/env python3
"""Attack the report server and assert each attack is refused.
  python3 check_web.py          → starts a throwaway local server and attacks it
  python3 check_web.py <url>    → attacks a running server (Docker container, or the deployed site)
"""
import json
import re
import socket
import ssl
import sys
import urllib.parse
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import server

ROW = {"tag": "t", "agent": "claude", "run": 0, "id": "a/pos0", "skill": "a", "kind": "pos", "picked": "a"}


def req(base, method, path, body=None, headers=None):
    data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.headers, resp.read().decode()  # case-insensitive (HTTP/2 lowercases)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


T = {}  # host, port, tls of the target


def conn(timeout):
    s = socket.create_connection((T["host"], T["port"]), timeout=timeout)
    return ssl.create_default_context().wrap_socket(s, server_hostname=T["host"]) if T["tls"] else s


def raw(data, wait=0.0):
    data = data.replace(b"Host: x", b"Host: " + T["host"].encode())
    s = conn(20)
    s.sendall(data)
    time.sleep(wait)
    try:
        return s.recv(4096).decode(errors="replace")
    except (socket.timeout, ConnectionResetError):
        return ""
    finally:
        s.close()


def main():
    httpd = None
    if len(sys.argv) > 1:
        base = sys.argv[1].rstrip("/")
    else:
        httpd = server.serve(0, str(Path(tempfile.mkdtemp()) / "r.db"))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
    u = urllib.parse.urlsplit(base)
    T.update(host=u.hostname, port=u.port or (443 if u.scheme == "https" else 80), tls=u.scheme == "https")
    results = []

    def check(name, ok):
        results.append(ok)
        print(f"{'ok  ' if ok else 'FAIL'} {name}")

    # normal flow; prompt text must not be stored
    code, h, body = req(base, "POST", "/api/reports", [{**ROW, "text": "SECRET-PROMPT-991"}])
    if code == 429:
        print("this IP is still rate-limited from an earlier run (limit persists for an hour); try later")
        return 2
    up = json.loads(body)
    check("upload works (201)", code == 201 and up["url"].startswith("/r/"))
    code, h, page = req(base, "GET", up["url"])
    check("report page 200", code == 200 and "<table>" in page)
    check("prompt text dropped", "SECRET-PROMPT-991" not in page)
    check("security headers", "script-src" not in h.get("Content-Security-Policy", "x") and
          "default-src 'none'" in h.get("Content-Security-Policy", "") and h.get("X-Content-Type-Options") == "nosniff"
          and "max-age" in h.get("Strict-Transport-Security", ""))
    check("server header hides version", "Python" not in h.get("Server", ""))

    # XSS in every text field
    evil = "</script><script>alert(1)</script><img src=x onerror=alert(1)>{body}{data}"
    code, _, body = req(base, "POST", "/api/reports", [{**ROW, "tag": evil, "agent": evil, "skill": evil, "picked": evil}])
    _, _, page = req(base, "GET", json.loads(body)["url"])
    check("XSS: no executable tag", page.count("<script") == 1 and not re.search(r"<(img|svg|iframe)\b", page)
          and not re.search(r"<[a-z]+[^>]*\son\w+=", page))

    # malformed uploads
    check("wrong content-type → 415", req(base, "POST", "/api/reports", b"[]", {"Content-Type": "text/plain"})[0] == 415)
    check("bad JSON → 400", req(base, "POST", "/api/reports", b"{nope")[0] == 400)
    check("deep nesting → 400", req(base, "POST", "/api/reports", b"[" * 200000 + b"]" * 200000)[0] in (400, 413))
    check("bool as run → 400", req(base, "POST", "/api/reports", [{**ROW, "run": True}])[0] == 400)
    check("unknown kind → 400", req(base, "POST", "/api/reports", [{**ROW, "kind": "x"}])[0] == 400)
    check("too many rows → 400", req(base, "POST", "/api/reports", [ROW] * 5001)[0] == 400)
    check("huge Content-Length → 413",
          "413" in raw(b"POST /api/reports HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                             b"Content-Length: 999999999\r\n\r\n").split("\r\n")[0])
    check("no Content-Length → 411",
          "411" in raw(b"POST /api/reports HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n").split("\r\n")[0])

    # id handling
    for p in ["/r/../../etc/passwd", "/r/' OR 1=1--", "/r/" + "A" * 22, "/r/%2e%2e%2fr.db", "/r/", "/r.db", "/../r.db"]:
        check(f"GET {p!r} → 404", req(base, "GET", urllib.request.quote(p, safe="/%'=")) [0] == 404)
    rid = up["url"][3:]
    check("DELETE no token → 404", req(base, "DELETE", "/api/reports/" + rid)[0] == 404)
    check("DELETE wrong token → 404", req(base, "DELETE", "/api/reports/" + rid, headers={"Authorization": "Bearer x"})[0] == 404)
    check("DELETE right token → 200", req(base, "DELETE", "/api/reports/" + rid,
                                          headers={"Authorization": "Bearer " + up["delete_token"]})[0] == 200)
    check("deleted report gone", req(base, "GET", up["url"])[0] == 404)
    check("other methods refused", req(base, "PUT", "/api/reports", [ROW])[0] in (404, 405, 501))

    # --- AI-facing pages and remote MCP ---
    for path in ("/llms.txt", "/robots.txt", "/sitemap.xml", "/guide/skill-not-triggering"):
        code, h, body = req(base, "GET", path)
        check(f"GET {path} 200 + CSP", code == 200 and "default-src 'none'" in h.get("Content-Security-Policy", "")
              and "{site}" not in body and "{demo}" not in body)
    check("report JSON for agents", req(base, "GET", "/r/" + "B" * 22 + ".json")[0] == 404)

    def rpc(msg, raw_body=None):
        return req(base, "POST", "/mcp", raw_body if raw_body is not None else msg)

    def tool(url):
        code, _, body = rpc({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                             "params": {"name": "check_skill_repo", "arguments": {"github_url": url}}})
        return code, (json.loads(body).get("result") or {}) if code == 200 else {}

    code, _, body = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    check("MCP initialize", code == 200 and json.loads(body)["result"]["serverInfo"]["name"] == "skillcheck")
    check("MCP notification → 202", rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})[0] == 202)
    check("MCP batch refused", rpc(None, b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]')[0] == 400)
    check("MCP big body → 413", rpc(None, b'{"a":"' + b"x" * 20000 + b'"}')[0] == 413)
    check("MCP unknown method", "-32601" in rpc({"jsonrpc": "2.0", "id": 2, "method": "resources/list"})[2])
    check("MCP bad args", "-32602" in rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                           "params": {"name": "check_skill_repo", "arguments": {"github_url": 5}}})[2])
    for bad in ("http://169.254.169.254/latest/meta-data", "https://github.com.evil.example/a/b", "https://github.com/../x",
                "https://github.com/a/..", "https://github.com/a/b/../../c", "https://github.com/a/b?x=1",
                "file:///etc/passwd", "https://raw.githubusercontent.com/a/b/HEAD/x", "https://user@github.com/a/b"):
        code, res = tool(bad)
        check(f"SSRF refused: {bad[:40]}", code == 200 and res.get("isError") is True and "must look like" in res["content"][0]["text"])
    for m in ("HEAD", "PUT", "OPTIONS"):
        check(f"{m} error page has CSP", "default-src 'none'" in (req(base, m, "/r/x")[1].get("Content-Security-Policy") or ""))
    for junk in (b"GARBAGE\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n"):
        r = raw(junk).lower()  # behind Fly the proxy rejects these itself with an empty 400: nothing to render
        check(f"malformed {junk[:14]!r} → CSP or empty 400", "content-security-policy: default-src 'none'" in r
              or (r.startswith("http/1.1 400") and "content-length: 0" in r))

    # slow / lying clients must not block others
    slow = threading.Thread(target=raw, args=(b"POST /api/reports HTTP/1.1\r\nHost: x\r\n", 12))
    lying = threading.Thread(target=raw, args=(b"POST /api/reports HTTP/1.1\r\nHost: x\r\nContent-Type: "
                                                     b"application/json\r\nContent-Length: 500\r\n\r\n[", 12))
    slow.start(), lying.start()
    time.sleep(1)
    t0 = time.time()
    check("server answers while slow clients hang", req(base, "GET", "/r/" + "B" * 22)[0] == 404 and time.time() - t0 < 3)
    slow.join(), lying.join()
    s = conn(30)
    s.sendall(b"GET /r/")  # never finish the request line
    t0 = time.time()
    try:
        closed = s.recv(10) == b""
    except (socket.timeout, ConnectionResetError):
        closed = False
    s.close()
    check(f"slow connection cut by server ({time.time() - t0:.0f}s)", closed and time.time() - t0 < 15)

    # rate limit last (it uses up this IP's quota)
    # each upload claims a new client IP; a server that trusts it would never return 429
    codes = [req(base, "POST", "/api/reports", [ROW], {"Fly-Client-IP": f"10.9.{i}.1", "X-Forwarded-For": f"10.8.{i}.1"})[0]
             for i in range(server.UPLOADS_PER_HOUR + 1)]
    check("rate limit → 429", 429 in codes)
    mcodes = [rpc({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "check_skill_repo",
                  "arguments": {"github_url": "x"}}})[0] for i in range(server.MCP_PER_HOUR + 1)]
    check("MCP tool rate limit → 429", 429 in mcodes)
    if httpd:  # unit: the fetcher never follows a redirect (would let a repo host bounce us anywhere)
        import http.server
        class Bounce(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/")
                self.end_headers()
            def log_message(self, *a):
                pass
        b = http.server.HTTPServer(("127.0.0.1", 0), Bounce)
        threading.Thread(target=b.handle_request, daemon=True).start()
        try:
            server.fetch(f"http://127.0.0.1:{b.server_port}/")
            followed = True
        except urllib.error.HTTPError as e:
            followed = e.code != 302
        check("MCP fetch does not follow redirects", not followed)

    if httpd:  # needs server internals: only against the throwaway local server
        httpd.shutdown()
        db = str(Path(tempfile.mkdtemp()) / "r.db")
        fresh = server.serve(0, db)
        threading.Thread(target=fresh.serve_forever, daemon=True).start()
        fbase = f"http://127.0.0.1:{fresh.server_address[1]}"
        box = []
        burst = [threading.Thread(target=lambda: box.append(req(fbase, "POST", "/api/reports", [ROW])[0])) for _ in range(30)]
        [t.start() for t in burst], [t.join() for t in burst]
        check(f"30 parallel uploads → {box.count(201)} accepted (≤ {server.UPLOADS_PER_HOUR})",
              0 < box.count(201) <= server.UPLOADS_PER_HOUR)
        fresh.shutdown()
        fresh.server_close()
        again = server.serve(0, db)
        threading.Thread(target=again.serve_forever, daemon=True).start()
        check("limit survives restart → 429",
              req(f"http://127.0.0.1:{again.server_address[1]}", "POST", "/api/reports", [ROW])[0] == 429)
        again.shutdown()
        import sqlite3
        whos = [w for (w,) in sqlite3.connect(db).execute("SELECT who FROM uploads")]
        check("db holds no raw IP", whos and not any("127.0.0.1" in w for w in whos))
    print(f"{sum(results)}/{len(results)} held")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
