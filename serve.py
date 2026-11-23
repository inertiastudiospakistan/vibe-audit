#!/usr/bin/env python3
"""
serve.py — one-click audit web UI (stdlib only).

    python3 serve.py [--port 8080]

Open http://127.0.0.1:8080, paste a GitHub URL (or owner/repo, or a local
folder path), click "Run audit", get the report. Local only — nothing
leaves your machine except the clone/download of the public repo you
asked for.
"""
import html
import os
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT_PY = os.path.join(HERE, "audit.py")
OUT_BASE = os.path.join(HERE, "web-audits")

PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>One-click audit</title></head>
<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:60px auto;padding:0 20px;color:#0f172a">
<h1 style="font-size:26px">One-click project audit</h1>
<p style="color:#475569">Paste a GitHub link, an <code>owner/repo</code>, or a folder path.
You get a senior-engineer review: stack, secrets, data security, auth,
payments, flows, data structure, code quality — with plain-English fixes
and copy-paste prompts for your AI to fix them.</p>
<form method="post" action="/audit">
<input name="source" placeholder="https://github.com/owner/repo  or  owner/repo  or  /path/to/project"
 style="width:100%;padding:12px;border:1px solid #cbd5e1;border-radius:10px;font-size:15px;box-sizing:border-box" required>
<button type="submit" style="margin-top:12px;padding:12px 22px;font-size:16px;font-weight:700;color:#fff;background:#0f766e;border:0;border-radius:10px;cursor:pointer">Run audit</button>
</form>
<p style="color:#64748b;font-size:14px">Try it on the built-in demo:
<a href="/audit?source=demo">audit the demo project</a> (7 planted problems).
No account, no upload, no install. Public repos need no token;
set GITHUB_TOKEN in the shell for private repos.</p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, "text/html", PAGE.encode())
            return
        if self.path.startswith("/audit"):
            self._run("")
            return
        if self.path.startswith("/report/"):
            rel = urllib.parse.unquote(self.path[len("/report/"):])
            path = os.path.join(OUT_BASE, rel)
            if os.path.isfile(path) and os.path.abspath(path).startswith(os.path.abspath(OUT_BASE)):
                with open(path, "rb") as fh:
                    self._send(200, "text/html", fh.read())
                return
            self._send(404, "text/plain", b"Report not found.")
            return
        self._send(404, "text/plain", b"Not found.")

    def do_POST(self):
        if self.path != "/audit":
            self._send(404, "text/plain", b"Not found.")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = urllib.parse.parse_qs(self.rfile.read(length).decode())
        source = (body.get("source", [""])[0] or "").strip()
        self._run(source)

    def _run(self, source):
        if self.path.startswith("/audit?"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            source = (q.get("source", [""])[0] or "").strip()
        if source == "demo":
            source = os.path.join(HERE, "test-project")
        if not source:
            self._send(400, "text/plain", b"Give me a GitHub URL, owner/repo, or folder path.")
            return
        run_id = time.strftime("%Y%m%d-%H%M%S")
        out_dir = os.path.join(OUT_BASE, run_id)
        try:
            r = subprocess.run([sys.executable, AUDIT_PY, source, "--out", out_dir],
                               capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            self._send(504, "text/plain", b"Audit timed out (5 min). Try a smaller repo.")
            return
        if r.returncode != 0:
            msg = (r.stderr or r.stdout or "Audit failed.").strip()
            self._send(400, "text/html",
                       f"<h1>Audit failed</h1><p>{html.escape(msg)}</p><p><a href='/'>Try again</a></p>".encode())
            return
        self.send_response(303)
        self.send_header("Location", f"/report/{run_id}/report.html")
        self.end_headers()

    def _send(self, code, ctype, data):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    port = 8080
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    os.makedirs(OUT_BASE, exist_ok=True)
    print(f"One-click audit running at http://127.0.0.1:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
