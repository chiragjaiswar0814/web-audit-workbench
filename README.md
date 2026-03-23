# Web Security Review Workbench

A local, Linux-friendly web application for **safe, passive** security reviews of **explicitly authorized** web targets.

Web Security Review Workbench is intended for internal security engineering workflows where you want consistent, repeatable observations (headers, cookies, TLS metadata, basic discovery) without running any offensive tooling.

## Safety & Authorization

This application is **passive-only** by design.

- It performs **non-destructive** requests using **GET / HEAD** (and **OPTIONS** only when available).
- It does **not** include exploit code, brute force, fuzzing, port scanning, subdomain enumeration, credential attacks, malware behavior, payloads, or persistence techniques.

Only scan targets you **own** or are **explicitly authorized** to assess.

## Features

- Target management (name, base URL, owner, environment, notes; active/archived)
- Passive checks:
  - Security headers analysis (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy)
  - Cookie flag review (Secure, HttpOnly, SameSite)
  - HTML form discovery (counts and basic metadata)
  - `OPTIONS` method summary (if supported)
  - HTTPS usage check
  - TLS certificate metadata summary (issuer, subject, validity window) when accessible
  - Server banner exposure detection (if present)
  - `robots.txt` and `security.txt` presence checks
- Transparent scoring and severity ratings (low/medium/high)
- Scan history and detailed findings view
- Dashboard with severity breakdown and common missing headers
- Professional HTML report per scan (print-friendly, suitable for “Print → Save as PDF”)

## Folder structure

- `app/` FastAPI application code
- `templates/` Jinja2 templates
- `static/` CSS/JS assets
- `instance/` SQLite database (local, not committed)
- `tests/` pytest tests

## Quick start (Linux)

Prerequisites:

- Python 3.10+
- `python3-venv`

```bash
git clone <your-repo-url>
cd web-audit-workbench

# Option A: Makefile
make install
make run

# Option B: run.sh
chmod +x run.sh
./run.sh
```

Open:

- http://127.0.0.1:8000

The SQLite database will be created at `instance/workbench.sqlite3`.

## How passive scanning works

For each manually added target, the scanner performs a small set of **read-only** checks:

- Fetches the base URL with **HEAD** (fallback to **GET** if needed)
- Optionally attempts **OPTIONS** to list supported methods (no state-changing methods are used)
- Parses response headers and cookies
- If HTML is available, parses for `<form>` elements
- Attempts to check `robots.txt` and `/.well-known/security.txt` / `/security.txt`
- If HTTPS, retrieves **certificate metadata** via a standard TLS handshake (no exploitation)

Timeouts, SSL errors, and unreachable hosts are handled gracefully and recorded as findings. Each scan also stores a small “observations snapshot” so reports remain useful even if the target changes later.

## Troubleshooting

- If `python3` is missing:
  - Debian/Ubuntu: `sudo apt-get install -y python3 python3-venv`
- If install fails due to build tools:
  - This project uses stable, commonly available packages. Ensure `pip` is up to date.
- If a target times out:
  - Increase timeout in `app/scanner.py` (defaults are conservative)

## Running tests

```bash
make test
```

## Future improvements

- Auth/user accounts (local-only)
- More nuanced scoring profiles per environment
- Additional passive checks (e.g., caching headers, CORS configuration summary)
- Optional local PDF generation (adds heavier dependencies; the current report supports print-to-PDF)
