#!/usr/bin/env python3
"""
audit.py — one-click senior-engineer audit for ANY web project (vibe-coded or not).

Usage:
    python3 audit.py <source> [--out DIR] [--skip-deps] [--keep]

source: a local folder, a GitHub URL, owner/repo, any .git URL, or a .zip file.
Output: report.html (clean, shareable), report.md, report.json in --out
        (default: ./audit-output). Prints a one-line summary.

Stdlib only. No installs. No accounts. Public repos need no token;
set GITHUB_TOKEN for private repos.

What it checks (grouped like a senior engineer's review):
  Stack           languages, frameworks, DB, auth, payments, hosting, CI
  Secrets         keys/tokens/.env/private keys in code (incl. git-tracked .env)
  Data security   Supabase RLS, service_role exposure, PII, plaintext passwords,
                  backups, secrets in logs
  Auth & access   unprotected API routes, JWT without verify, weak session
                  secrets, open CORS
  Payments        Stripe webhook signature, idempotency, client-side prices
  Flows           signup/login/reset, upload limits, email verification,
                  checkout completeness
  Data structure  tables/models parsed from Prisma/SQL/Django/SQLAlchemy/
                  Mongoose, migrations, indexes, unique constraints
  Code quality    tests, CI, README, .gitignore, huge files, TODOs, bare
                  except, unpinned deps, OSV vulnerability lookup
  Deploy & ops    hosting config, health endpoint, error tracking
"""
import base64
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from datetime import datetime

VERSION = "2.0.0"

# ---------------------------------------------------------------- constants
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
             "build", ".next", ".turbo", "coverage", ".idea", ".vscode", "vendor"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
             ".ttf", ".eot", ".mp3", ".mp4", ".webm", ".pdf", ".zip", ".tar",
             ".gz", ".lockb", ".DS_Store"}
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue",
             ".svelte", ".json", ".toml", ".yaml", ".yml", ".md", ".txt",
             ".html", ".css", ".sql", ".prisma", ".rb", ".php", ".go", ".rs",
             ".java", ".kt", ".env", ".example", ".sh", ".ini", ".cfg",
             ".xml", ".graphql", ".lock"}

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    ("github-token", re.compile(r"(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}"), "GitHub token"),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    ("stripe-live-key", re.compile(r"sk_live_[A-Za-z0-9]{16,}"), "Stripe LIVE secret key"),
    ("stripe-test-key", re.compile(r"sk_test_[A-Za-z0-9]{16,}"), "Stripe test secret key"),
    ("openai-key", re.compile(r"sk-(proj-)?[A-Za-z0-9_-]{20,}"), "OpenAI-style secret key"),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key"),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"), "Private key"),
    ("jwt-token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT in code"),
    ("db-password-url", re.compile(r"(postgres|mysql|mongodb(\+srv)?)://[^:/?#\s]+:[^@/?#\s]+@"), "Database URL with password"),
    ("generic-password", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"), "Hardcoded password"),
    ("generic-secret", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"), "Hardcoded API key/secret"),
]

# ---------------------------------------------------------------- helpers
def esc(s):
    return html.escape(str(s))

def read_text(path, limit=2_000_000):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(limit)
    except OSError:
        return ""

def is_text_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in SKIP_EXTS:
        return False
    if ext in TEXT_EXTS:
        return True
    if ext == "":
        return os.path.basename(path) in {".env", "Dockerfile", "Makefile", "Gemfile", "Procfile", ".gitignore", ".dockerignore"}
    return ext not in {".exe", ".dll", ".so", ".dylib", ".bin", ".dat"}

def collect_files(root):
    """Walk root, return list of (relpath, abspath) for scannable text files."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != ".git"]
        for name in filenames:
            p = os.path.join(dirpath, name)
            if is_text_file(p):
                out.append((os.path.relpath(p, root), p))
    return out

def decode_jwt_role(token):
    """Return the role claim of a JWT, or None if it is not a JWT / undecodable."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("role")
    except Exception:
        return None

class Findings:
    def __init__(self):
        self.items = []
        self._seen = set()

    def add(self, fid, category, severity, title, where, what, why, fix, ai):
        key = (fid, where)
        if key in self._seen:
            return
        self._seen.add(key)
        self.items.append({
            "id": fid, "category": category, "severity": severity,
            "title": title, "where": where, "what": what, "why": why,
            "fix": list(fix), "ai": ai,
        })

    def counts(self):
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for it in self.items:
            if it["severity"] in c:
                c[it["severity"]] += 1
        return c

    def by_severity(self, sev):
        return [i for i in self.items if i["severity"] == sev]

# ---------------------------------------------------------------- fetching
def fetch_source(spec, tmpdir):
    """Return (local_path, display_name). Raises RuntimeError on failure."""
    spec = spec.strip().rstrip("/")
    if os.path.isdir(spec):
        return os.path.abspath(spec), os.path.basename(os.path.abspath(spec)) or spec
    if os.path.isfile(spec) and spec.lower().endswith(".zip"):
        dest = os.path.join(tmpdir, "src")
        with zipfile.ZipFile(spec) as z:
            z.extractall(dest)
        return _single_child(dest), os.path.basename(spec)
    m = re.match(r"^(?:https?://)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?$", spec)
    if not m:
        m = re.match(r"^([\w.-]+)/([\w.-]+)$", spec)
    if m:
        owner, repo = m.group(1), m.group(2)
        dest = os.path.join(tmpdir, "src")
        # Try git first (fast, exact), then tarball fallback.
        try:
            subprocess.run(["git", "clone", "--depth", "1",
                            f"https://github.com/{owner}/{repo}.git", dest],
                           check=True, capture_output=True, timeout=180)
            return dest, f"{owner}/{repo}"
        except Exception:
            pass
        token = os.environ.get("GITHUB_TOKEN", "")
        for branch in ("main", "master"):
            url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}"
            req = urllib.request.Request(url)
            if token:
                req.add_header("Authorization", f"token {token}")
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read()
                with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:gz") as t:
                    t.extractall(tmpdir)
                return _single_child(tmpdir), f"{owner}/{repo}"
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    continue
                raise RuntimeError(f"GitHub download failed ({e.code}) for {owner}/{repo}")
            except Exception:
                continue
        raise RuntimeError(f"Could not fetch {owner}/{repo} (tried git clone + tarball, branches main/master)")
    if spec.endswith(".git") or spec.startswith(("http://", "https://", "git@")):
        dest = os.path.join(tmpdir, "src")
        subprocess.run(["git", "clone", "--depth", "1", spec, dest],
                       check=True, capture_output=True, timeout=180)
        return dest, spec
    raise RuntimeError(f"Cannot use source: {spec!r} (need a local folder, a GitHub URL, owner/repo, a .git URL, or a .zip)")

def _single_child(path):
    """If path holds exactly one directory, descend into it (tarball/zip layout)."""
    try:
        kids = [os.path.join(path, k) for k in os.listdir(path)]
        dirs = [k for k in kids if os.path.isdir(k)]
        if len(dirs) == 1 and len(kids) == 1:
            return dirs[0]
    except OSError:
        pass
    return path

# ---------------------------------------------------------------- stack detection
def detect_stack(files, contents):
    """contents: dict relpath -> text. Returns a stack dict."""
    stack = {"languages": {}, "frameworks": [], "database": [], "auth": [],
             "payments": [], "hosting": [], "ci": [], "tests": 0,
             "has_readme": False, "has_gitignore": False, "has_env_example": False,
             "has_dockerfile": False, "deps_npm": {}, "deps_pypi": {}}
    by_ext = {}
    for rel, _ in files:
        ext = os.path.splitext(rel)[1].lower()
        by_ext[ext] = by_ext.get(ext, 0) + 1
        base = os.path.basename(rel)
        if base.lower().startswith("readme"):
            stack["has_readme"] = True
        if base == ".gitignore":
            stack["has_gitignore"] = True
        if base in (".env.example", ".env.sample"):
            stack["has_env_example"] = True
        if base == "Dockerfile" or base.startswith("Dockerfile."):
            stack["has_dockerfile"] = True
        if ".github/workflows" in rel and rel.endswith((".yml", ".yaml")):
            stack["ci"].append("GitHub Actions")
        if base in (".gitlab-ci.yml", "circle.yml") or ".circleci/" in rel:
            stack["ci"].append(base)
    lang_map = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
                ".ts": "TypeScript", ".tsx": "TypeScript", ".rb": "Ruby",
                ".php": "PHP", ".go": "Go", ".rs": "Rust", ".java": "Java",
                ".kt": "Kotlin", ".vue": "Vue", ".svelte": "Svelte"}
    for ext, n in by_ext.items():
        if ext in lang_map:
            stack["languages"][lang_map[ext]] = stack["languages"].get(lang_map[ext], 0) + n
    all_text = "\n".join(contents.values())
    def has(*needles):
        return any(n in all_text for n in needles)
    pkg = contents.get("package.json", "")
    if pkg:
        try:
            data = json.loads(pkg)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            stack["deps_npm"] = deps
            fw = {"next": "Next.js", "react": "React", "vue": "Vue",
                  "nuxt": "Nuxt", "svelte": "Svelte", "astro": "Astro",
                  "express": "Express", "@remix-run/react": "Remix",
                  "vite": "Vite", "tailwindcss": "Tailwind CSS"}
            for k, v in fw.items():
                if k in deps:
                    stack["frameworks"].append(v)
        except json.JSONDecodeError:
            pass
    req = contents.get("requirements.txt", "")
    if req:
        for line in req.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = re.split(r"[<>=!~\s\[]", line)[0]
            ver = re.search(r"==\s*([0-9][^\s;]*)", line)
            stack["deps_pypi"][name] = ver.group(1) if ver else ""
    if has("from django", "import django", "DJANGO_SETTINGS"):
        stack["frameworks"].append("Django")
    if has("from flask", "import Flask"):
        stack["frameworks"].append("Flask")
    if has("from fastapi", "import FastAPI"):
        stack["frameworks"].append("FastAPI")
    if has("supabase"):
        stack["database"].append("Supabase")
    if "schema.prisma" in contents or has("prisma"):
        stack["database"].append("Prisma")
    if has("drizzle-orm"):
        stack["database"].append("Drizzle")
    if has("mongoose"):
        stack["database"].append("MongoDB/Mongoose")
    if has("sqlalchemy"):
        stack["database"].append("SQLAlchemy")
    if has("firebase"):
        stack["database"].append("Firebase")
    if has("clerk", "@clerk"):
        stack["auth"].append("Clerk")
    if has("next-auth", "NextAuth"):
        stack["auth"].append("NextAuth")
    if has("auth0"):
        stack["auth"].append("Auth0")
    if has("passport"):
        stack["auth"].append("Passport.js")
    if has("stripe"):
        stack["payments"].append("Stripe")
    if has("paddle"):
        stack["payments"].append("Paddle")
    if has("lemonsqueezy"):
        stack["payments"].append("LemonSqueezy")
    if has("paypal"):
        stack["payments"].append("PayPal")
    if "vercel.json" in contents or has("vercel"):
        stack["hosting"].append("Vercel")
    if "netlify.toml" in contents:
        stack["hosting"].append("Netlify")
    if "wrangler.toml" in contents or "wrangler.json" in contents:
        stack["hosting"].append("Cloudflare Workers")
    if "render.yaml" in contents:
        stack["hosting"].append("Render")
    if "fly.toml" in contents:
        stack["hosting"].append("Fly.io")
    if stack["has_dockerfile"]:
        stack["hosting"].append("Docker")
    test_names = ("test_", "_test.", ".test.", ".spec.", "__tests__")
    stack["tests"] = sum(1 for rel, _ in files
                         if any(t in rel for t in test_names))
    stack["frameworks"] = sorted(set(stack["frameworks"]))
    stack["database"] = sorted(set(stack["database"]))
    stack["auth"] = sorted(set(stack["auth"]))
    stack["payments"] = sorted(set(stack["payments"]))
    stack["hosting"] = sorted(set(stack["hosting"]))
    stack["ci"] = sorted(set(stack["ci"]))
    return stack

# ---------------------------------------------------------------- checkers
def check_secrets(files, contents, root, f):
    """Secrets in code + committed .env + git-tracked .env."""
    for rel, _ in files:
        text = contents[rel]
        if rel.endswith((".md", ".lock")):
            continue
        for pid, pat, label in SECRET_PATTERNS:
            for m in pat.finditer(text):
                if pid == "jwt-token":
                    role = decode_jwt_role(m.group(0))
                    if role == "service_role":
                        f.add("secret-service-role", "Secrets", "critical",
                              "Supabase service_role key shipped in code",
                              f"{rel}:{text[:m.start()].count(chr(10)) + 1}",
                              "A service_role key bypasses ALL row-level security. Anyone who reads this file can read and write every row in the database.",
                              "This is the single most dangerous finding in a Supabase app. It turns the database into a public one.",
                              ["Move the key to a server-only env var (SUPABASE_SERVICE_ROLE_KEY) that is never bundled into client code.",
                               "Rotate the key in the Supabase dashboard (Settings → API → service_role → Rotate).",
                               "Use the anon key in the browser, and run privileged work through a server route or Edge Function."],
                              f"In {rel}, remove the hardcoded Supabase service_role JWT and replace it with a server-only environment variable (SUPABASE_SERVICE_ROLE_KEY) loaded on the server only. Then rotate the key in the Supabase dashboard. Never import it in client-side code.")
                    continue  # anon/user JWTs are not secrets
                if pid == "openai-key" and m.group(0).startswith("sk-proj-"):
                    label = "OpenAI project key"
                line = text[:m.start()].count("\n") + 1
                sev = "critical" if pid in ("stripe-live-key", "private-key", "aws-access-key", "github-token") else "high"
                f.add(f"secret-{pid}", "Secrets", sev, f"{label} in code",
                      f"{rel}:{line}",
                      f"A {label.lower()} is written directly in the code. Anyone with repo access (or the built app, if this ships to the browser) can use it.",
                      "Leaked keys are how apps get drained: stolen cloud keys have produced five-figure bills in days, and a leaked Stripe key lets anyone refund or charge.",
                      ["Move the value to an environment variable and read it with os.environ / process.env.",
                       "Rotate/revoke the leaked key now — deleting it from the file is not enough, it stays in git history.",
                       "Add the file to .gitignore and check git history for the key (git log -S '<key>')."],
                      f"In {rel} line {line}, remove the hardcoded {label.lower()} and read it from an environment variable instead. Then rotate/revoke the key with its provider.")
        if os.path.basename(rel) == ".env":
            f.add("secret-env-committed", "Secrets", "critical", "Committed .env file",
                  rel, "A .env file with real secrets is committed to the repo.",
                  "This is the classic leak: the file is in git history forever, and anyone who clones the repo gets the keys.",
                  ["Delete the file from git (git rm --cached .env) and add .env to .gitignore.",
                   "Rotate every key that was in the file.",
                   "Commit a .env.example with placeholder values instead."],
                  f"Remove {rel} from git tracking (git rm --cached {rel}), add .env to .gitignore, rotate every key that was inside it, and add a .env.example with placeholders.")
        if rel == ".gitignore" and ".env" not in text:
            f.add("secret-env-not-ignored", "Secrets", "medium", ".env not gitignored",
                  rel, ".gitignore does not exclude .env files.",
                  "One accidental commit is all it takes to publish every secret.",
                  ["Add a line with `.env` (and `.env.*` except `.env.example`) to .gitignore."],
                  "Add `.env` to .gitignore so secret files can never be committed by accident.")
    # .env tracked in git history?
    if os.path.isdir(os.path.join(root, ".git")):
        try:
            r = subprocess.run(["git", "-C", root, "ls-files"],
                               capture_output=True, text=True, timeout=20)
            tracked = [l for l in r.stdout.splitlines() if os.path.basename(l).startswith(".env") and l != ".env.example"]
            for t in tracked:
                f.add("secret-env-tracked", "Secrets", "critical",
                      "Secret file tracked by git", t,
                      "A .env-style file is tracked by git, so its secrets are in the repo history.",
                      "Even if the file is deleted later, the keys stay recoverable from git history.",
                      ["git rm --cached the file, add it to .gitignore, and rotate every key in it.",
                       "For a public repo, also purge it from history (git filter-repo) or assume the keys are public."],
                      f"Untrack {t} with git rm --cached, add it to .gitignore, and rotate every key that was in it.")
        except Exception:
            pass

def check_data_security(files, contents, stack, f):
    all_text = "\n".join(contents.values())
    uses_supabase = "Supabase" in stack["database"]
    if uses_supabase:
        rls = bool(re.search(r"(?i)enable row level security|create policy|ROW LEVEL SECURITY", all_text))
        if not rls:
            f.add("data-rls-unverified", "Data security", "high",
                  "Supabase in use, no RLS evidence in repo — verify in dashboard",
                  "(repo-wide)",
                  "The code uses Supabase but no migration or SQL file in the repo turns on row-level security. Tables may be open to anyone with the anon key.",
                  "This is the most common vibe-coded data breach: thousands of Supabase databases were found publicly readable in 2026 because tables created by agents skip RLS by default.",
                  ["Open the Supabase dashboard → Table Editor → each table → enable RLS.",
                   "Add a policy per table (e.g. users can only read their own rows: auth.uid() = user_id).",
                   "Add the RLS SQL to a migration file in the repo so it is versioned, not just a dashboard click."],
                  "For every Supabase table, enable row-level security and add a policy that restricts rows to their owner (auth.uid() = user_id or equivalent). Put the SQL in a migration file in the repo so it is versioned.")
    if re.search(r"(?i)password\s*=\s*[^=].{0,40}", all_text):
        for rel, _ in files:
            text = contents[rel]
            if re.search(r"(?i)(user\.password\s*=|password\s*=\s*req\.body|password\s*:\s*req\.body)", text) and "hash" not in text.lower() and "bcrypt" not in text.lower() and "argon" not in text.lower():
                f.add("data-plaintext-password", "Data security", "high",
                      "Password stored without hashing (verify)", rel,
                      "A password looks like it is saved directly, with no hashing step visible in the same file.",
                      "A database leak then exposes every user's real password — and people reuse passwords everywhere.",
                      ["Hash passwords with bcrypt/argon2 before storing (never store the raw password).",
                       "Force a password reset for existing users if any were stored this way."],
                      f"In {rel}, hash the password with bcrypt or argon2 before saving it to the database. Never store or log the raw password.")
                break
    if re.search(r"(?i)(console\.log|print)\s*\(.*(req\.body|password|secret|api_key|access_token)", all_text):
        f.add("data-secret-in-logs", "Data security", "medium",
              "Sensitive data may be logged", "(code)",
              "Code logs request bodies or user objects, which often contain passwords, tokens or personal data.",
              "Logs get shipped to third-party services and stored forever — a password in a log is a password leaked.",
              ["Remove sensitive fields before logging (log ids, not bodies).",
               "Add a log-redaction helper that strips password/token/secret keys."],
              "Find every console.log/print that logs req.body, user objects, passwords or tokens, and remove the sensitive fields before logging.")
    if re.search(r"(?i)(localStorage|sessionStorage)\.(setItem|getItem).*token", all_text):
        f.add("data-token-localstorage", "Data security", "medium",
              "Auth token stored in localStorage", "(code)",
              "Tokens in localStorage can be read by any script running on the page (including a malicious dependency).",
              "An XSS flaw or a compromised package then steals every logged-in session.",
              ["Store session tokens in httpOnly cookies set by the server instead."],
              "Move auth tokens out of localStorage into httpOnly cookies set by the server.")
    if stack["database"] and not re.search(r"(?i)backup|pg_dump|snapshot", all_text):
        f.add("data-no-backup", "Data security", "low",
              "No backup visible in the repo", "(repo-wide)",
              "The app has a database but no backup script, schedule or config is visible.",
              "One bad migration or deleted table, and the data is gone for good.",
              ["Enable automatic backups in the database provider (Supabase: daily backups on Pro; or a nightly pg_dump to object storage).",
               "Test a restore once — a backup nobody has restored is a hope, not a backup."],
              "Add an automatic daily database backup (provider setting or a nightly pg_dump script) and test restoring from it once.")
    if re.search(r"(?i)\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b", all_text):
        f.add("data-card-number", "Data security", "high",
              "Card-number pattern in code", "(code)",
              "Something that looks like a credit-card number appears in the code or test data.",
              "Real card numbers must never sit in a repo — PCI rules and fraud risk.",
              ["Remove real card numbers; use test cards (4242…) for tests.",
               "Never store card numbers — let Stripe/Paddle hold them."],
              "Remove any real credit-card numbers from the code and tests; use test card numbers only, and never store card numbers yourself.")

def check_auth(files, contents, stack, f):
    all_text = "\n".join(contents.values())
    if re.search(r"jwt\.decode\([^)]*verify\s*=\s*False", all_text) or "verify_signature\": False" in all_text or "verify_signature': False" in all_text:
        f.add("auth-jwt-no-verify", "Auth & access", "critical",
              "JWT decoded without signature verification", "(code)",
              "A JWT is decoded with verification turned off, so anyone can forge a token claiming to be any user.",
              "Authentication is effectively absent: a forged token gets admin access.",
              ["Verify the signature with the real secret/public key on every decode.",
               "Never accept alg=none or unverified tokens."],
              "Find the jwt.decode call with verification disabled and verify the signature with the real secret or public key. Never accept unverified tokens.")
    # API routes without auth (heuristic, labelled as verify)
    route_files = [rel for rel, _ in files
                   if ("/api/" in rel or "routes/" in rel or "views.py" in rel or "routers/" in rel)
                   and rel.endswith((".py", ".js", ".ts", ".tsx"))]
    for rel in route_files:
        base = os.path.basename(rel).lower()
        if any(k in base for k in ("webhook", "health", "public", "cron", "callback")):
            continue
        text = contents[rel]
        writes = bool(re.search(r"(?i)\b(insert|update|delete|create|save|remove)\b", text))
        calls_out = bool(re.search(r"(?i)(fetch\(|axios|requests\.|httpx\.)", text))
        auth_ref = bool(re.search(r"(?i)(auth|session|token|requireAuth|getServerSession|login_required|Depends\(|clerk|withAuth)", text))
        if (writes or calls_out) and not auth_ref:
            f.add("auth-route-no-auth", "Auth & access", "high",
                  "API route with no auth check (verify)", rel,
                  "This API route writes data or calls other services but shows no sign of checking who is calling it.",
                  "If it really is open, anyone on the internet can trigger the same writes the app does.",
                  ["Add an auth check at the top of the route (session/token verification).",
                   "If the route is meant to be public, add rate limiting and keep it read-only."],
                  f"In {rel}, add an authentication check at the top of the route (verify the session or token) before any database write or external call. If the route must stay public, add rate limiting and make it read-only.")
    if re.search(r"(?i)(SECRET_KEY|SESSION_SECRET|JWT_SECRET)\s*=\s*['\"][^'\"]{1,15}['\"]", all_text) or re.search(r"(?i)secret\s*=\s*['\"](secret|change-me|changeme|dev-secret)['\"]", all_text):
        f.add("auth-weak-secret", "Auth & access", "high",
              "Weak or placeholder session secret", "(code)",
              "A session/JWT secret is short or a guessable placeholder like 'secret' or 'change-me'.",
              "Anyone who guesses it can forge sessions for any user.",
              ["Generate a long random secret (32+ bytes) and put it in an env var.",
               "Rotate it and invalidate old sessions."],
              "Replace the short or placeholder session/JWT secret with a long random value (32+ bytes) stored in an environment variable, and invalidate existing sessions.")
    if re.search(r"(?i)(Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*|origin\s*:\s*['\"]\*['\"])", all_text) and re.search(r"(?i)credentials", all_text):
        f.add("auth-cors-wildcard", "Auth & access", "high",
              "CORS allows any origin with credentials", "(code)",
              "The API allows any website to call it with the user's credentials.",
              "A malicious site can make the browser send the user's session to your API and read the result.",
              ["Restrict CORS to your own domains only.",
               "Never combine Access-Control-Allow-Origin: * with credentials."],
              "Restrict CORS to your own domains only, and never combine a wildcard origin with credentials.")
    if stack["auth"] and not os.path.exists("middleware"):
        pass  # too noisy to flag; dashboard protection is checked in flows

def check_payments(files, contents, stack, f):
    # Only run payment checks when real payment SDK/API code exists.
    # A mere mention of "Stripe" in docs or marketing copy does not count.
    code = "\n".join(t for rel, t in contents.items() if not rel.endswith(".md"))
    uses_stripe = bool(re.search(
        r"(?i)(import stripe|from stripe|require\(['\"]stripe|new Stripe\(|stripe\.(checkout|webhooks|billing)|api\.stripe\.com)",
        code))
    if not uses_stripe:
        return
    all_text = "\n".join(contents.values())
    has_webhook = bool(re.search(r"(?i)webhook", all_text))
    verified = bool(re.search(r"construct_event|verify.*signature|stripe\.webhooks\.constructEvent", all_text))
    if has_webhook and not verified:
        f.add("pay-webhook-unverified", "Payments", "high",
              "Stripe webhook without signature verification", "(code)",
              "A Stripe webhook endpoint exists but no signature check is visible.",
              "Anyone can POST a fake 'payment succeeded' event and get the product for free.",
              ["Verify the signature with stripe.webhooks.constructEvent(rawBody, sig, endpointSecret) on every webhook.",
               "Use the raw request body — a parsed JSON body breaks the signature."],
              "In the Stripe webhook handler, verify the signature with stripe.webhooks.constructEvent using the raw request body and the endpoint secret, and reject any request that fails verification.")
    if not has_webhook:
        f.add("pay-no-webhook", "Payments", "high",
              "Stripe used but no webhook handler found", "(repo-wide)",
              "Payments are taken but there is no webhook endpoint to hear about them.",
              "Failed payments, refunds and disputes never reach the app — paid users can stay locked out, and refunded users keep access.",
              ["Add a webhook endpoint for checkout.session.completed, invoice.payment_failed and charge.refunded.",
               "Update the user's access from the webhook, never from the browser redirect alone."],
              "Add a Stripe webhook endpoint handling checkout.session.completed, invoice.payment_failed and charge.refunded, and update user access from webhook events — never from the browser redirect alone.")
    if re.search(r"(?i)checkout\.sessions\.create", all_text) and "idempotency" not in all_text.lower():
        f.add("pay-no-idempotency", "Payments", "medium",
              "Checkout without idempotency key", "(code)",
              "Stripe checkout sessions are created without an idempotency key.",
              "A retried request (double-click, network retry) can create a duplicate charge.",
              ["Pass idempotencyKey (e.g. the user's id + cart id) when creating checkout sessions and payment intents."],
              "Pass an idempotency key (user id + cart/order id) when creating Stripe checkout sessions and payment intents so retries cannot double-charge.")
    for rel, _ in files:
        text = contents[rel]
        if re.search(r"(?i)(price|amount)\s*[:=]\s*\d{3,}", text) and ("client" in rel or "components" in rel or "pages" in rel or "src/" in rel):
            if "stripe" not in text.lower():
                f.add("pay-client-price", "Payments", "medium",
                      "Price set in client-side code", rel,
                      "A price or amount is written in code that ships to the browser.",
                      "A user can change it in devtools and pay less.",
                      ["Keep all prices on the server (Stripe Price IDs in the database).",
                       "The client only ever sends a price ID, never an amount."],
                      f"In {rel}, remove the hardcoded price/amount and use a Stripe Price ID stored on the server instead. The client must never decide what something costs.")
                break

def check_flows(files, contents, stack, f):
    all_text = "\n".join(contents.values())
    rels = [r for r, _ in files]
    def exists(*needles):
        return any(any(n in r for n in needles) for r in rels) or any(n in all_text for n in needles)
    has_signup = exists("signup", "sign-up", "register", "createUser", "signUp")
    has_login = exists("login", "sign-in", "signin", "signIn")
    has_reset = exists("reset-password", "forgot-password", "forgot_password", "password-reset")
    has_upload = exists("upload", "multer", "uploadthing", "UploadButton")
    has_email = exists("sendgrid", "resend", "nodemailer", "smtplib", "send_mail", "@sendgrid")
    has_checkout = exists("checkout", "Checkout")
    if has_signup and not has_reset and (
            re.search(r'type\s*=\s*["\']password["\']', all_text) or "email/password" in all_text.lower()):
        f.add("flow-no-password-reset", "Flows", "medium",
              "Signup exists but no password reset", "(repo-wide)",
              "Users can create accounts with a password but there is no way to recover a forgotten one.",
              "Locked-out users email support or leave — and support tickets cost more than the fix.",
              ["Add a forgot-password page that emails a time-limited reset link.",
               "Never reveal whether an email is registered in the reset response."],
              "Add a forgot-password flow: a page that emails a time-limited reset link, and a reset page that sets the new password. Do not reveal whether an email is registered.")
    if has_upload and not re.search(r"(?i)(maxFileSize|maxSize|fileSize|accept\s*[:=]|allowed.*types|fileType)", all_text):
        f.add("flow-upload-no-limits", "Flows", "medium",
              "File upload without size/type limits", "(code)",
              "The app accepts uploads but no size or file-type limit is visible.",
              "One user can upload a 2GB file and fill the disk, or upload an executable that gets served back.",
              ["Limit uploads (e.g. 5MB, images/PDF only) on the server — client-side checks alone are not enough.",
               "Store uploads outside the web root and serve them with the right content type."],
              "Add server-side upload limits (maximum file size and allowed file types) and store uploads outside the web root.")
    if has_email and has_signup and not re.search(r"(?i)(verify.*email|email.*verif|confirm.*email)", all_text):
        f.add("flow-no-email-verify", "Flows", "low",
              "No email verification after signup", "(repo-wide)",
              "Accounts are created without confirming the email address.",
              "Anyone can register with someone else's email, and password resets go nowhere.",
              ["Send a verification link at signup and require it before sensitive actions."],
              "Send an email verification link at signup and require a verified email before sensitive actions like password changes.")
    if has_checkout and "Stripe" in stack["payments"] and not re.search(r"(?i)webhook", all_text):
        pass  # covered by pay-no-webhook
    if has_login and not re.search(r"(?i)(rate.?limit|throttl|lockout|attempts)", all_text):
        f.add("flow-login-no-rate-limit", "Flows", "low",
              "Login without rate limiting", "(code)",
              "The login flow shows no rate limiting or lockout.",
              "Attackers can try thousands of passwords against an account.",
              ["Add rate limiting on login (e.g. 5 attempts per 15 minutes per IP/account).",
               "Add a CAPTCHA after repeated failures."],
              "Add rate limiting to the login endpoint (for example 5 attempts per 15 minutes per IP and per account) and a CAPTCHA after repeated failures.")

def parse_data_structure(files, contents):
    """Return (tables, notes). tables: list of {name, columns, source}."""
    tables = []
    for rel, _ in files:
        text = contents[rel]
        if rel.endswith("schema.prisma"):
            for m in re.finditer(r"model\s+(\w+)\s*\{([^}]*)\}", text):
                cols = [c.strip().split()[0] for c in m.group(2).splitlines()
                        if c.strip() and not c.strip().startswith(("@", "//"))]
                tables.append({"name": m.group(1), "columns": cols, "source": rel})
        if rel.endswith(".sql"):
            for m in re.finditer(r"(?i)CREATE TABLE (?:IF NOT EXISTS )?\"?(\w+)\"?\s*\((.*?)\);", text, re.S):
                cols = [c.strip().split()[0].strip('"') for c in m.group(2).split(",")
                        if c.strip()]
                tables.append({"name": m.group(1), "columns": cols, "source": rel})
        if rel.endswith(".py"):
            for m in re.finditer(r"class\s+(\w+)\s*\([^)]*(?:Base|Model|models\.Model)\b[^)]*\):", text):
                body = text[m.end():m.end() + 2000]
                cols = re.findall(r"^\s{4}(\w+)\s*=\s*(?:Column|models\.)", body, re.M)
                if cols:
                    tables.append({"name": m.group(1), "columns": cols, "source": rel})
        if rel.endswith((".js", ".ts")):
            for m in re.finditer(r"new\s+(?:mongoose\.)?Schema\s*\(\s*\{(.*?)\}\s*\)", text, re.S):
                cols = re.findall(r"(\w+)\s*:", m.group(1))
                tables.append({"name": "(mongoose schema)", "columns": cols, "source": rel})
    # de-dupe by name+source
    seen = set()
    out = []
    for t in tables:
        k = (t["name"], t["source"])
        if k not in seen:
            seen.add(k)
            out.append(t)
    return out

def check_data_structure(files, contents, stack, tables, f):
    all_text = "\n".join(contents.values())
    if not tables:
        return
    has_migrations = any("migration" in r.lower() for r, _ in files) or "migrations" in all_text.lower()
    if not has_migrations:
        f.add("ds-no-migrations", "Data structure", "medium",
              "Database models exist but no migrations", "(repo-wide)",
              "Tables are defined in code but there is no migration system visible.",
              "Schema changes are made by hand, so production and development drift apart and a deploy can break the app.",
              ["Add migrations (Prisma migrate, Alembic, Django migrations, or SQL migration files).",
               "Never edit production tables by hand."],
              "Add a migration system for the database (Prisma migrate, Alembic, Django migrations or SQL migration files) and make every schema change through it.")
    for t in tables:
        cols_lower = [c.lower() for c in t["columns"]]
        if t["name"].lower() in ("user", "users", "account", "accounts"):
            if "email" in cols_lower and not re.search(r"(?i)unique.*email|email.*unique|@unique", all_text):
                f.add("ds-email-not-unique", "Data structure", "medium",
                      "Users table: email not marked unique", t["source"],
                      "The users table has an email column with no unique constraint visible.",
                      "Duplicate accounts for the same email break login, password reset and billing.",
                      ["Add a unique constraint/index on the email column.",
                       "Deduplicate existing rows first."],
                      f"In {t['source']}, add a unique constraint on the email column of the users table (after deduplicating any existing duplicate emails).")
        if "created_at" not in cols_lower and "createdat" not in cols_lower:
            f.add("ds-no-created-at", "Data structure", "low",
                  f"Table '{t['name']}' has no created_at column", t["source"],
                  f"The {t['name']} table has no created_at timestamp.",
                  "Without it, debugging ('when did this break?') and sorting/auditing become guesswork.",
                  ["Add created_at (and updated_at) columns with defaults."],
                  f"Add created_at and updated_at timestamp columns with defaults to the {t['name']} table.")
            break

def check_code_quality(files, contents, stack, f):
    rels = [r for r, _ in files]
    if stack["tests"] == 0:
        f.add("q-no-tests", "Code quality", "medium",
              "No tests at all", "(repo-wide)",
              "The repo contains no test files.",
              "Every change is a guess: nothing catches a regression before users do.",
              ["Add a small test suite for the critical paths first (auth, payments, main flows).",
               "Run tests in CI on every push."],
              "Add automated tests for the critical paths first (authentication, payments, main user flows) and run them in CI on every push.")
    elif stack["tests"] < 5:
        f.add("q-few-tests", "Code quality", "low",
              "Very few tests", "(repo-wide)",
              f"Only {stack['tests']} test file(s) found for the whole project.",
              "Most of the app is untested, so regressions slip through.",
              ["Add tests for the next feature you touch, and for every bug you fix."],
              "Add tests for the critical paths (authentication, payments, main flows) — start with one test per critical path.")
    if not stack["ci"]:
        f.add("q-no-ci", "Code quality", "low",
              "No CI configured", "(repo-wide)",
              "No continuous-integration config (GitHub Actions, GitLab CI, etc.) was found.",
              "Broken code can be merged and deployed without anything ever running the tests.",
              ["Add a CI workflow that installs, lints and tests on every pull request."],
              "Add a CI workflow (for example GitHub Actions) that installs dependencies, runs the linter and runs the tests on every pull request.")
    if not stack["has_readme"]:
        f.add("q-no-readme", "Code quality", "low",
              "No README", "(repo-wide)",
              "There is no README explaining what the project is or how to run it.",
              "Nobody — including future-you — can set the project up without reading all the code.",
              ["Write a short README: what it does, how to install, how to run, how to test."],
              "Write a README with what the project does, how to install it, how to run it, and how to run the tests.")
    if not stack["has_gitignore"]:
        f.add("q-no-gitignore", "Code quality", "medium",
              "No .gitignore", "(repo-wide)",
              "There is no .gitignore file.",
              "Secrets, build output and dependency folders get committed by accident.",
              ["Add a .gitignore for the stack (node_modules, .env, __pycache__, dist, .next, etc.)."],
              "Add a .gitignore covering node_modules, .env, __pycache__, dist and build folders for this stack.")
    if not stack["has_env_example"] and any("process.env" in c or "os.environ" in c or "os.getenv" in c for c in contents.values()):
        f.add("q-no-env-example", "Code quality", "medium",
              "No .env.example", "(repo-wide)",
              "The code reads environment variables but there is no .env.example listing them.",
              "A new developer (or a new deploy) has to guess which variables the app needs.",
              ["Commit a .env.example with every required variable and a placeholder value."],
              "Commit a .env.example listing every environment variable the app needs, with placeholder values.")
    big = [(r, contents[r].count("\n") + 1) for r, _ in files
           if contents[r].count("\n") + 1 > 500 and r.endswith((".py", ".js", ".ts", ".tsx", ".jsx"))]
    for rel, n in sorted(big, key=lambda x: -x[1])[:5]:
        f.add("q-huge-file", "Code quality", "low",
              f"Very large file: {n} lines", rel,
              f"{rel} is {n} lines long.",
              "Huge files are hard to review, hard to test, and where bugs hide.",
              ["Split it by responsibility (routes / logic / data access).",
               "Extract the biggest function first."],
              f"Split {rel} ({n} lines) by responsibility — routes, business logic and data access in separate files — starting with the largest function.")
    todos = sum(c.count("TODO") + c.count("FIXME") for c in contents.values())
    if todos > 10:
        f.add("q-many-todos", "Code quality", "low",
              f"{todos} TODO/FIXME markers", "(repo-wide)",
              f"{todos} TODO/FIXME comments are scattered through the code.",
              "Unfinished work that nobody tracks becomes permanent behaviour.",
              ["Turn real TODOs into issues; delete the ones that will never happen."],
              f"Turn the {todos} TODO/FIXME comments into tracked issues, and delete the ones that will never be done.")
    for rel, _ in files:
        text = contents[rel]
        if re.search(r"except\s*:\s*\n\s*pass", text) or re.search(r"except\s+Exception\s*:\s*\n\s*pass", text):
            f.add("q-bare-except", "Code quality", "medium",
                  "Errors swallowed silently", rel,
                  "A try/except block catches errors and does nothing with them.",
                  "Failures become invisible: the app looks fine while data is silently lost.",
                  ["Log the error, or re-raise it. Never `except: pass`."],
                  f"In {rel}, remove the silent except/pass block — log the error or re-raise it so failures are visible.")
            break
    req = contents.get("requirements.txt", "")
    if req and any(re.match(r"^[A-Za-z0-9_.-]+\s*$", l.strip()) for l in req.splitlines() if l.strip() and not l.startswith("#")):
        f.add("q-unpinned-deps", "Code quality", "medium",
              "Unpinned Python dependencies", "requirements.txt",
              "requirements.txt lists packages without pinned versions.",
              "A fresh install can pull a breaking major version and the app stops working.",
              ["Pin every dependency (package==version) and regenerate with pip freeze."],
              "Pin every dependency in requirements.txt to an exact version (package==version).")
    pkg = contents.get("package.json", "")
    if pkg:
        try:
            data = json.loads(pkg)
            if "test" not in data.get("scripts", {}):
                f.add("q-no-test-script", "Code quality", "low",
                      "No test script in package.json", "package.json",
                      "package.json has no `test` script.",
                      "There is no standard way to run the tests, so nobody runs them.",
                      ["Add a `test` script that runs the test suite."],
                      "Add a `test` script to package.json that runs the test suite.")
        except json.JSONDecodeError:
            pass

def check_deploy(files, contents, stack, f):
    all_text = "\n".join(contents.values())
    has_backend = bool(stack["frameworks"]) or "server" in all_text.lower()
    if has_backend and not stack["hosting"] and not stack["has_dockerfile"]:
        f.add("ops-no-hosting-config", "Deploy & ops", "low",
              "No hosting/deploy config", "(repo-wide)",
              "The app has a backend but no hosting config (Vercel, Render, Dockerfile, etc.) is visible.",
              "Deploys are manual and unrepeatable — the app works on one machine and nowhere else.",
              ["Add a deploy config (Dockerfile or a host config) and document the deploy steps."],
              "Add a deployment config (a Dockerfile or a hosting config for the chosen host) and document the deploy steps in the README.")
    if not re.search(r"(?i)(sentry|bugsnag|rollbar|posthog)", all_text):
        f.add("ops-no-error-tracking", "Deploy & ops", "low",
              "No error tracking", "(repo-wide)",
              "No error-tracking service (Sentry, etc.) is wired in.",
              "Production crashes are invisible until a user complains.",
              ["Add Sentry (free tier) with release tracking."],
              "Add an error-tracking service such as Sentry (free tier) so production crashes are reported automatically.")
    if not re.search(r"(?i)(/health|healthz|health_check|/api/health)", all_text):
        f.add("ops-no-health-endpoint", "Deploy & ops", "low",
              "No health endpoint", "(repo-wide)",
              "No /health endpoint exists for the host to check the app is alive.",
              "Hosts and load balancers cannot tell a hung app from a healthy one.",
              ["Add a GET /health endpoint that returns 200 and checks the database."],
              "Add a GET /health endpoint that returns 200 and verifies the database connection.")

def check_osv(stack, f):
    """Query OSV for known vulnerabilities in npm + PyPI deps (one batch call)."""
    queries = []
    for name, ver in list(stack["deps_npm"].items())[:30]:
        v = re.sub(r"^[\^~>=< ]+", "", ver or "")
        if v and re.match(r"^\d", v):
            queries.append({"package": {"name": name, "ecosystem": "npm"}, "version": v})
    for name, ver in list(stack["deps_pypi"].items())[:30]:
        if ver:
            queries.append({"package": {"name": name, "ecosystem": "PyPI"}, "version": ver})
    if not queries:
        return "no-deps"
    try:
        body = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch",
                                     data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        found = 0
        for q, res in zip(queries, data.get("results", [])):
            vulns = res.get("vulns", [])
            for v in vulns[:2]:
                found += 1
                if found > 10:
                    break
                name = q["package"]["name"]
                vid = v.get("id", "unknown")
                summary = v.get("summary", "Known vulnerability")
                f.add(f"osv-{vid}", "Secrets", "high",
                      f"Vulnerable dependency: {name} ({vid})", "(dependencies)",
                      f"{name} has a known vulnerability: {summary}.",
                      "Known vulnerabilities are the easiest way in — attackers scan for them automatically.",
                      [f"Upgrade {name} to a fixed version (check the OSV entry for {vid}).",
                       "Run the audit again after upgrading."],
                      f"Upgrade {name} to a version that fixes {vid} ({summary}), then re-run this audit to confirm.")
        return "ok"
    except Exception:
        return "offline"

# ---------------------------------------------------------------- scoring
SEV_WEIGHT = {"critical": 15, "high": 7, "medium": 3, "low": 1}

def score_project(f, stack, tables, osv_status):
    score = 100
    for it in f.items:
        score -= SEV_WEIGHT.get(it["severity"], 0)
    bonus = 0
    if stack["tests"] >= 5:
        bonus += 3
    if stack["ci"]:
        bonus += 2
    if stack["has_env_example"]:
        bonus += 2
    if stack["has_readme"]:
        bonus += 1
    if tables:
        bonus += 2
    score = max(0, min(100, score + min(bonus, 10)))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade

def plain_summary(f, stack, tables):
    """Top-3 plain-language issues for the owner, plus what to do first."""
    crit = f.by_severity("critical")
    high = f.by_severity("high")
    top = (crit + high)[:3]
    lines = []
    for it in top:
        lines.append(f"{it['title']} — {it['what']}")
    if not top:
        med = f.by_severity("medium")
        top = med[:3]
        for it in top:
            lines.append(f"{it['title']} — {it['what']}")
    if not lines:
        lines.append("Nothing serious found. The project looks healthy — keep the habits that got it here (tests, RLS, no secrets in code).")
    first = "Fix the critical items first (above), then the high ones — in that order."
    return lines, first

# ---------------------------------------------------------------- reports
SEV_COLOR = {"critical": "#B91C1C", "high": "#C2410C", "medium": "#A16207", "low": "#475569"}

def render_html(project, when, f, stack, tables, score, grade, osv_status):
    counts = f.counts()
    summary, first = plain_summary(f, stack, tables)
    def sev_badge(s):
        return f'<span style="background:{SEV_COLOR[s]};color:#fff;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase">{s}</span>'
    cards = ""
    for sev in ("critical", "high", "medium", "low"):
        items = f.by_severity(sev)
        if not items:
            continue
        cards += f'<h2 style="margin:28px 0 8px">{sev_badge(sev)} {len(items)} finding{"s" if len(items) != 1 else ""}</h2>'
        for it in items:
            fix_steps = "".join(f"<li>{esc(s)}</li>" for s in it["fix"])
            cards += f"""
<div style="border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;margin:10px 0;background:#fff">
  <div style="display:flex;justify-content:space-between;gap:12px;align-items:baseline">
    <strong style="font-size:15px">{esc(it['title'])}</strong>{sev_badge(it['severity'])}
  </div>
  <div style="color:#64748b;font-size:13px;margin-top:4px">{esc(it['where'])} &middot; {esc(it['category'])}</div>
  <p style="margin:10px 0 4px"><b>What this means:</b> {esc(it['what'])}</p>
  <p style="margin:4px 0"><b>Why it matters:</b> {esc(it['why'])}</p>
  <p style="margin:8px 0 4px"><b>Fix it:</b></p>
  <ol style="margin:4px 0 4px 18px">{fix_steps}</ol>
  <details style="margin-top:10px"><summary style="cursor:pointer;color:#0f766e;font-weight:600">Give this to your AI (copy-paste prompt)</summary>
  <pre style="background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;white-space:pre-wrap;font-size:13px">{esc(it['ai'])}</pre>
  <button onclick="navigator.clipboard.writeText(this.previousElementSibling.innerText)" style="cursor:pointer;padding:6px 12px;border-radius:8px;border:1px solid #cbd5e1;background:#f8fafc">Copy prompt</button></details>
</div>"""
    if not f.items:
        cards = '<p style="color:#166534;font-weight:600">No findings. Nothing to fix — nice work.</p>'
    stack_rows = ""
    def row(k, v):
        return f'<tr><td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;color:#64748b">{k}</td><td style="padding:6px 10px;border-bottom:1px solid #e2e8f0">{v}</td></tr>'
    stack_rows += row("Languages", ", ".join(f"{k} ({v} files)" for k, v in sorted(stack["languages"].items(), key=lambda x: -x[1])) or "—")
    stack_rows += row("Frameworks", ", ".join(stack["frameworks"]) or "—")
    stack_rows += row("Database", ", ".join(stack["database"]) or "—")
    stack_rows += row("Auth", ", ".join(stack["auth"]) or "—")
    stack_rows += row("Payments", ", ".join(stack["payments"]) or "—")
    stack_rows += row("Hosting", ", ".join(stack["hosting"]) or "—")
    stack_rows += row("CI", ", ".join(stack["ci"]) or "none")
    stack_rows += row("Tests", f"{stack['tests']} test file(s)")
    stack_rows += row("Vulnerability check", {"ok": "OSV lookup ran", "offline": "skipped — offline", "no-deps": "no versioned dependencies found"}[osv_status])
    tables_html = ""
    if tables:
        trows = "".join(f"<tr><td style='padding:6px 10px;border-bottom:1px solid #e2e8f0'>{esc(t['name'])}</td><td style='padding:6px 10px;border-bottom:1px solid #e2e8f0'>{esc(', '.join(t['columns']))}</td><td style='padding:6px 10px;border-bottom:1px solid #e2e8f0;color:#64748b'>{esc(t['source'])}</td></tr>" for t in tables)
        tables_html = f"""<h2 style="margin-top:32px">Data structure — tables found ({len(tables)})</h2>
<table style="width:100%;border-collapse:collapse;font-size:14px"><tr><th style="text-align:left;padding:6px 10px">Table</th><th style="text-align:left;padding:6px 10px">Columns</th><th style="text-align:left;padding:6px 10px">Defined in</th></tr>{trows}</table>"""
    all_ai = "\n\n".join(f"{i+1}. {it['ai']}" for i, it in enumerate(f.items))
    ai_section = ""
    if f.items:
        ai_section = f"""<h2 style="margin-top:32px">Give this to your AI agent (all fixes in one prompt)</h2>
<p>Copy this into Claude Code, Codex, Qoder or OpenCode with the repo open:</p>
<pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:10px;white-space:pre-wrap;font-size:13px">You are a senior software engineer fixing this project. Work through these findings in order (critical first). For each one, make the change, run the tests, and confirm the finding is gone before moving on. Do not skip any. Do not introduce new dependencies unless needed.

{esc(all_ai)}</pre>
<button onclick="navigator.clipboard.writeText(this.previousElementSibling.innerText)" style="cursor:pointer;padding:8px 16px;border-radius:8px;border:1px solid #cbd5e1;background:#f8fafc">Copy full prompt</button>"""
    summary_html = "".join(f"<li>{esc(s)}</li>" for s in summary)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit — {esc(project)}</title></head>
<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:860px;margin:0 auto;padding:24px;color:#0f172a;background:#f8fafc">
<div style="display:flex;gap:20px;align-items:center;background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:20px">
  <div style="font-size:52px;font-weight:800;line-height:1;text-align:center;min-width:110px">{score}<div style="font-size:13px;color:#64748b;font-weight:600">/ 100 &middot; grade {grade}</div></div>
  <div><h1 style="margin:0 0 6px;font-size:22px">Audit: {esc(project)}</h1>
  <div style="color:#64748b;font-size:14px">{esc(when)} &middot; {counts['critical']} critical &middot; {counts['high']} high &middot; {counts['medium']} medium &middot; {counts['low']} low</div></div>
</div>
<h2 style="margin-top:28px">In plain English</h2>
<ul>{summary_html}</ul>
<p><b>What to do first:</b> {esc(first)}</p>
<h2 style="margin-top:28px">Stack</h2>
<table style="width:100%;border-collapse:collapse;font-size:14px;background:#fff;border:1px solid #e2e8f0;border-radius:12px">{stack_rows}</table>
{tables_html}
{cards}
{ai_section}
<p style="color:#64748b;font-size:12px;margin-top:36px">How the score works: start at 100, minus 15 per critical, 7 per high, 3 per medium, 1 per low; plus up to 10 for good habits (tests, CI, .env.example, README, migrations). Some findings are heuristics labelled "verify" — confirm before changing code. This audit reads code and config; it cannot see dashboard settings (Supabase RLS, hosting) — those are flagged for a human to check.</p>
</body></html>"""

def render_md(project, when, f, stack, tables, score, grade, osv_status):
    counts = f.counts()
    summary, first = plain_summary(f, stack, tables)
    lines = [f"# Audit: {project}", "", f"**Score: {score}/100 (grade {grade})** — {when}",
             f"**{counts['critical']} critical · {counts['high']} high · {counts['medium']} medium · {counts['low']} low**", "",
             "## In plain English", ""]
    lines += [f"- {s}" for s in summary]
    lines += ["", f"**What to do first:** {first}", "", "## Stack", ""]
    lines += [f"- Languages: {', '.join(f'{k} ({v})' for k, v in stack['languages'].items()) or '—'}",
              f"- Frameworks: {', '.join(stack['frameworks']) or '—'}",
              f"- Database: {', '.join(stack['database']) or '—'}",
              f"- Auth: {', '.join(stack['auth']) or '—'}",
              f"- Payments: {', '.join(stack['payments']) or '—'}",
              f"- Hosting: {', '.join(stack['hosting']) or '—'}",
              f"- CI: {', '.join(stack['ci']) or 'none'}",
              f"- Tests: {stack['tests']} test file(s)", ""]
    if tables:
        lines += ["## Data structure", ""]
        for t in tables:
            lines.append(f"- **{t['name']}** ({t['source']}): {', '.join(t['columns'])}")
        lines.append("")
    for sev in ("critical", "high", "medium", "low"):
        items = f.by_severity(sev)
        if not items:
            continue
        lines.append(f"## {sev.upper()} ({len(items)})")
        lines.append("")
        for it in items:
            lines.append(f"### {it['title']} — {it['where']}")
            lines.append("")
            lines.append(f"**What this means:** {it['what']}")
            lines.append(f"**Why it matters:** {it['why']}")
            lines.append("**Fix it:**")
            for s in it["fix"]:
                lines.append(f"1. {s}")
            lines.append("")
            lines.append("**Give this to your AI:**")
            lines.append("```")
            lines.append(it["ai"])
            lines.append("```")
            lines.append("")
    if f.items:
        lines.append("## Give this to your AI agent (all fixes)")
        lines.append("")
        lines.append("```")
        lines.append("You are a senior software engineer fixing this project. Work through these findings in order (critical first). For each one, make the change, run the tests, and confirm the finding is gone before moving on.")
        lines.append("")
        for i, it in enumerate(f.items):
            lines.append(f"{i+1}. {it['ai']}")
        lines.append("```")
    return "\n".join(lines)

# ---------------------------------------------------------------- main
def run_audit(source, out_dir, skip_deps=False, keep=False):
    tmpdir = tempfile.mkdtemp(prefix="audit-")
    try:
        root, name = fetch_source(source, tmpdir)
        files = collect_files(root)
        contents = {rel: read_text(p) for rel, p in files}
        f = Findings()
        stack = detect_stack(files, contents)
        check_secrets(files, contents, root, f)
        check_data_security(files, contents, stack, f)
        check_auth(files, contents, stack, f)
        check_payments(files, contents, stack, f)
        check_flows(files, contents, stack, f)
        tables = parse_data_structure(files, contents)
        check_data_structure(files, contents, stack, tables, f)
        check_code_quality(files, contents, stack, f)
        check_deploy(files, contents, stack, f)
        osv_status = "no-deps" if skip_deps else check_osv(stack, f)
        score, grade = score_project(f, stack, tables, osv_status)
        when = datetime.now().strftime("%Y-%m-%d %H:%M")
        os.makedirs(out_dir, exist_ok=True)
        html_path = os.path.join(out_dir, "report.html")
        md_path = os.path.join(out_dir, "report.md")
        json_path = os.path.join(out_dir, "report.json")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html(name, when, f, stack, tables, score, grade, osv_status))
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(render_md(name, when, f, stack, tables, score, grade, osv_status))
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump({"project": name, "when": when, "score": score, "grade": grade,
                       "counts": f.counts(), "files_scanned": len(files),
                       "stack": stack, "tables": tables, "findings": f.items,
                       "osv_status": osv_status}, fh, indent=2)
        return {"name": name, "files": len(files), "score": score, "grade": grade,
                "counts": f.counts(), "out": out_dir, "html": html_path,
                "md": md_path, "json": json_path}
    finally:
        if not keep:
            shutil.rmtree(tmpdir, ignore_errors=True)

def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    source = argv[1]
    out_dir = "audit-output"
    skip_deps = False
    keep = False
    i = 2
    while i < len(argv):
        if argv[i] == "--out" and i + 1 < len(argv):
            out_dir = argv[i + 1]
            i += 2
        elif argv[i] == "--skip-deps":
            skip_deps = True
            i += 1
        elif argv[i] == "--keep":
            keep = True
            i += 1
        else:
            print(f"Unknown option: {argv[i]}")
            return 2
    try:
        r = run_audit(source, out_dir, skip_deps=skip_deps, keep=keep)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    c = r["counts"]
    print(f"{r['name']}: {r['files']} files — score {r['score']}/100 (grade {r['grade']}) — "
          f"critical={c['critical']} high={c['high']} medium={c['medium']} low={c['low']}")
    print(f"Report: {r['html']}")
    print(f"Markdown: {r['md']}")
    print(f"JSON: {r['json']}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
