# Vibe-code rescue — audit tool v2 (23 Nov 2026)

A one-click senior-engineer audit for ANY web project — vibe-coded or not.
Stdlib-only Python, no installs, no accounts, no money spent.

## Request an audit

First 5 audits are free, then $49 (including a human check of your Supabase dashboard — the one thing a scanner cannot see).

**Request one here: https://forms.gle/pKDLBtsbxF8gc8SB7**

Or run it yourself — one command, below.

## Use it (one command)

```bash
python3 audit.py <source>
```

`source` is a local folder, a GitHub URL, `owner/repo`, any `.git` URL, or a `.zip`.
It prints a score and writes `audit-output/report.html` (+ `.md` and `.json`).

```bash
python3 audit.py https://github.com/owner/repo
python3 audit.py ./my-project
python3 audit.py owner/repo --out ./my-audit
python3 audit.py ./my-project --skip-deps   # skip the OSV vulnerability lookup
```

## Or one click in the browser

```bash
python3 serve.py
# open http://127.0.0.1:8080 — paste a URL, click Run audit, get the report
```

## What it checks (9 areas, like a senior engineer's review)

| Area | Examples |
|---|---|
| Stack | languages, frameworks, DB, auth, payments, hosting, CI |
| Secrets | keys/tokens/.env/private keys in code, .env tracked by git |
| Data security | Supabase RLS (verify in dashboard), service_role exposure, plaintext passwords, PII in logs, backups |
| Auth & access | API routes with no auth check, JWT without verification, weak session secrets, open CORS |
| Payments | Stripe webhook signature, idempotency, prices set in client code |
| Flows | signup without password reset, uploads without limits, login without rate limiting |
| Data structure | tables parsed from Prisma/SQL/Django/SQLAlchemy/Mongoose, migrations, unique email, created_at |
| Code quality | tests, CI, README, .gitignore, huge files, bare except, unpinned deps, OSV vulnerability lookup |
| Deploy & ops | hosting config, health endpoint, error tracking |

## The report

`report.html` is a single clean file, no external assets:

- **Score 0–100 + grade** (critical −15, high −7, medium −3, low −1; +up to 10 for good habits)
- **In plain English** — the top issues in words a non-technical owner understands
- **Stack table** and **data-structure tables** found in the code
- Every finding: what it means, why it matters, numbered fix steps, and a **copy-paste prompt for your AI** (Claude Code / Codex / Qoder / OpenCode) — plus one combined prompt for all fixes
- Findings labelled "verify" are heuristics — confirm before changing code. The audit reads code and config; it cannot see dashboard settings (Supabase RLS, hosting), which are flagged for a human to check.

## Verified 23 Nov 2026

- **test-project** (14 files, planted problems in every area): 29 findings across all 9 areas — 4 critical, 6 high, 9 medium, 10 low. Score 0/100, grade F. Every planted issue caught. Sample: `sample-report.html`
- **clean-project** (15 files, well-kept): 0 findings. Score 100/100, grade A.
- **Nodefield, local** (64 files): 95/100, grade A — 0 critical, 0 high. Real gaps only: no tests, no `.env.example`, `.env` not in `.gitignore`, 844-line server.py.
- **Nodefield via GitHub URL** (clone, 62 files): 91/100, grade A — 0 critical, 0 high. Clone + audit of a remote repo works.
- **Web UI**: form loads, demo audit runs, report generated with all AI prompts.
- **OSV vulnerability lookup**: VERIFIED 23 Nov ~20:10 PKT — the earlier "offline" runs were transient (network approval was pending on the first runs); the full CLI audit now returns osv_status "ok" and flags the planted vulnerable deps (lodash 4.17.15 ×2, requests 2.19.0 ×2). test-project is now 33 findings, still 0/100 F.

## How the first paid audit works ($49)

1. Client sends a repo link or zip.
2. Run: `python3 audit.py <link> --out audit-<client>`
3. Human pass: verify Supabase dashboard RLS/policies, confirm each critical finding is real, add the one-line fix.
4. Deliver `report.html` + a 2-line summary of what breaks first.

## What it is NOT

- Not a guarantee the app is secure. Dashboard settings, auth config and backend logic need the human pass.
- Not the control-layer products yet. The scanner's checks are the seed list for the pre-commit reviewer (Track B).

## Next steps (needs his call)

1. Offer the audit where broken-app owners already look: whocanfixmyapp.com directory (79 companies listed) + a short post in the Lovable/Bolt community.
2. Price: $49 audit, $79–$199 fix for the critical items found.
3. If rescue gets no takers in 2 weeks, the audit becomes the free funnel for Track B (one-click lockdown generator).
