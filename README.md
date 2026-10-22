# Gauntlet

**Contract-driven DAST for web apps** — it combines OWASP ZAP with a custom, deterministic access-control tester to find the authorization and tenant-isolation bugs that scanners and static analysis miss, and writes a plain-language report anyone can read.

[![CI](https://github.com/gioeleBrancaleoni/gauntlet/actions/workflows/ci.yml/badge.svg)](https://github.com/gioeleBrancaleoni/gauntlet/actions/workflows/ci.yml)
![license: MIT](https://img.shields.io/badge/license-MIT-blue)
![python: >=3.12](https://img.shields.io/badge/python->=3.12-blue)

---

## ⚠️ Responsible-use disclaimer

> **Use Gauntlet ONLY on systems you own, or that you have explicit, written authorization to test.**
>
> - **Throwaway dev/staging environments only. NEVER in production.** The active scan (only with `--aggressive`) sends real attack traffic and can create data, mutate state, or degrade the service.
> - Scanning third-party systems without authorization is **illegal** in many jurisdictions and can carry criminal and civil consequences.
> - The `allowed_targets` allowlist is fail-closed, but it **cannot** tell a production target from a disposable one on its own: it is **your** responsibility to list only throwaway targets.
> - The authors accept no liability for improper or unauthorized use. Use is entirely at your own risk (see [LICENSE](LICENSE)).

---

## What it is

Gauntlet runs a dynamic security scan (DAST) against a web application you control and produces a report that explains, for every issue: *what was found*, *how serious it is*, *how to fix it*, and *what you risk if you ignore it*.

It combines **two engines**:

- **OWASP ZAP** (in a Docker container) for classic web vulnerabilities: injection, XSS, missing security headers, misconfigurations, path traversal, SSRF, and more.
- **A custom, deterministic access-control tester** (direct HTTP client) — the crown jewel: **cross-tenant isolation**. Using two real accounts and a *seed-marker ownership oracle*, it confirms, without guesswork, whether one customer can read or modify another customer's data.

**Why it's different:** it finds authorization and tenant-isolation bugs (horizontal BOLA/IDOR, vertical privilege escalation, JWT flaws) that static analysis and plain scanners structurally cannot see — and it confirms each one against a known seeded marker, so a reported leak is a **real leak, with zero false positives**.

Everything is driven by a per-project **contract** (`gauntlet.yaml`), which makes the skill portable across projects without touching its code.

---

## Demonstrations

The reports below come from running Gauntlet against **intentionally vulnerable** targets, locally in Docker. They show what the skill actually finds on a real app. See [`examples/README.md`](examples/README.md) for the full index.

### crAPI — authenticated, level 2 (multi-tenant, BOLA/IDOR, JWT)

- Contract: [`examples/crapi/gauntlet.yaml`](examples/crapi/gauntlet.yaml)
- Command: `CRAPI_A_PW=… CRAPI_B_PW=… gauntlet run --project examples/crapi --level 2`
- Full report: [`examples/results/crapi-level2-report.md`](examples/results/crapi-level2-report.md)

**Result: 12 issues — 3 CRITICAL, 3 medium, 5 low, 1 info.** The three criticals are the headline, and every one of them is confirmed by a deterministic oracle:

| # | Critical finding | How it was confirmed | Confidence |
|:-:|---|---|:-:|
| 1 | **Cross-tenant BOLA/IDOR** — `cliente_b` reads `cliente_a`'s vehicle-location endpoint | `200` response containing `cliente_a`'s seeded ownership marker (the leaked `email`) | 100% |
| 2 | **Cross-tenant BOLA/IDOR** (symmetric) — `cliente_a` reads `cliente_b`'s vehicle-location endpoint | `200` response containing `cliente_b`'s seeded marker | 100% |
| 3 | **JWT `alg=none` accepted** — the server honors an unsigned, forged token | forged token with `alg: none` + empty signature returns the protected resource | 100% |

Findings 1 and 2 are the point of the whole tool: each is a genuine tenant-isolation break, confirmed because the attacker account received a `200` **and** the victim's known seed marker appeared in the body — not an inference, an actual leak. Real excerpt of the tool's evidence for finding 1:

```
GET .../identity/api/v2/vehicle/<uuid>/location as 'cliente_b' -> 200;
marker 'gauntlet-a@example.com' present in the body (extract:
'{"carId":"<uuid>","vehicleLocation":{"id":5,"latitude":"37.406769",
"longitude":"-94.705528"},"fullName":"Gauntlet A","email":"gauntlet-a@example.com"}').
```

The third critical is a JWT weakness: the server accepts a token forged with `alg: none` and an empty signature (same payload, no signature), meaning anyone can mint a valid token for any user. As the report puts it:

```
JWT alg=none accepted  — CRITICAL
The server accepted a JWT forged with an 'alg: none' header and an empty
signature (same payload as the real token): the GET on the protected endpoint
responded 200 with the expected content. The token signature is not verified:
anyone can craft a valid token with any identity and privilege.
Check source: JWT weakness check · detection confidence: 100%.
```

The remaining issues (missing headers, server version leak, CSP) come from ZAP's passive scan. At level 2 the intrusive active scan does **not** run by default — it requires `--aggressive`.

### OWASP Juice Shop — blind, level 1 (unauthenticated)

- Contract: [`examples/juiceshop/gauntlet.yaml`](examples/juiceshop/gauntlet.yaml)
- Command: `gauntlet run --project examples/juiceshop --level 1`
- Full report: [`examples/results/juiceshop-level1-report.md`](examples/results/juiceshop-level1-report.md)

**Result: 262 issues — 0 critical, 0 high, 170 medium, 92 info**, all from ZAP's automated pass over the public surface, with no login.

| Count | Finding | Severity |
|---:|---|---|
| 94 | Cross-Domain Misconfiguration (CORS `Access-Control-Allow-Origin: *`) | medium |
| 76 | Content Security Policy (CSP) Header Not Set | medium |
| 68 | Modern Web Application (informational) | info |
| 24 | User Agent Fuzzer (informational) | info |

The high counts come from the same defect (a missing or permissive header) repeating across many resources of the SPA — expected behavior for a surface-wide scan. Level 1 does not authenticate, so it exercises neither token auth nor the tenant-isolation test: those are what crAPI demonstrates.

---

## Capabilities / attack coverage

- **Classic web vulnerabilities** (ZAP): injection, XSS, missing security headers, misconfigurations, path traversal, SSRF, and more.
- **Horizontal cross-tenant BOLA/IDOR** — confirmed with a *seed-marker ownership oracle* (a `200` is reported only when the victim's known marker is in the body).
- **Sequential-ID IDOR fuzzing** — probes IDs neighboring a known resource and flags a leak via an *owner-field oracle* when a different owner appears.
- **Vertical privilege escalation** — probes administrative endpoints as a normal user.
- **JWT weaknesses** — `alg=none` acceptance and weak/guessable HMAC signing secrets.
- **CORS misconfiguration** — a deliberately foreign probe origin is sent; flagged only when the server reflects it (worst case: reflected origin **with** credentials).
- **Open redirect** — an off-origin canary is injected into declared redirect endpoints; confirmed only when the `Location` header points back to the canary's host (exact origin match, never a substring).
- **Mass assignment** — *(aggressive, consented)* writes an operator-declared forbidden field (e.g. `role`/`isAdmin`) and re-reads the resource; confirmed only when the injected value is actually persisted.
- **Login rate-limiting** — *(aggressive)* repeated failed logins with no throttling or `429`.
- **Verbose error / stack-trace disclosure** — malformed IDs that make the app leak stack traces or internal errors.
- **Authenticated scanning (bearer token *or* session cookie)** — ZAP's Replacer add-on injects the captured `Authorization: Bearer <token>` **or** `Cookie` on every scan request, so the authenticated surface is actually exercised, whether the app uses a token or a cookie session.
- **Full catalog:** [docs/checks.md](docs/checks.md) — all 18 checks with each oracle, severity, confidence and false-positive analysis.

---

## The four attacker levels

Gauntlet models the attacker's posture as four increasing levels of knowledge (each includes the previous one's capabilities):

| Level | Name | Knowledge | Automated engine |
|:-:|---|---|---|
| 1 | **blind** | no credentials, no docs | spider + passive scan on the public surface (active scan only with `--aggressive`) |
| 2 | **authenticated user** | valid credentials for the two accounts | authentication + **cross-tenant access-control tests** |
| 3 | **+ documentation** | + API/endpoint docs (`docs_path`) | same engine as level 2 |
| 4 | **+ source** | + application source code (`src_path`) | same engine as level 2 |

Stated honestly: **the automated engine is identical for levels 2, 3 and 4.** Levels 3 and 4 do not expand the automated scan on their own — they mean the orchestrator (Claude) reads the documentation and source to *direct additional manual testing* (endpoints the spider missed, resources to seed, new access-control cases). The level flag records which material is available for that work.

---

## Safety model

- **Fail-closed allowlist (origin-exact).** Every request that sends traffic (spider, active scan, reachability preflight) passes the gate first. A target is allowed **only** if its normalized origin (scheme + host + port) exactly matches an `allowed_targets` entry — never by substring (`http://localhost:8081.evil.com` does **not** match `http://localhost:8081`). A different scheme or port is a different origin and is rejected; a missing contract or unextractable origin is rejected. There is no "production detection" heuristic: anything not explicitly allowlisted is refused.
- **Dev/staging only.** The allowlist is the only barrier; it is on you to list only disposable targets.
- **Non-destructive by default.** Without `--aggressive`, a run is non-destructive: it runs the ZAP spider, relies on the **passive scan**, and runs access-control checks **read-only**. The intrusive **active scan** and **cross-tenant writes** run **only** with `--aggressive` (a single, upfront batch consent). The flag never widens the allowlist.

---

## Global installation

Gauntlet is installed **once** on the machine and then used from **any** project, at two independent layers:

1. **Global CLI** — the `gauntlet` command lands on your PATH and works from any folder.
2. **Claude Code skill** — `SKILL.md` is registered in `~/.claude/skills/gauntlet/`, so Claude Code discovers the skill in **every** project without copying it per project.

**Prerequisites:** Docker running (needed at runtime), Python ≥ 3.12, and **pipx** or **pip**. The installer checks these and warns clearly, but does not install Python or Docker for you.

### One line (no clone needed)

Install the CLI **and** the Claude Code skill in a single command, straight from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/gioeleBrancaleoni/gauntlet/main/scripts/install.sh | sh
```

It installs the `gauntlet` CLI with **pipx** (from the public repo) and downloads `SKILL.md` into `~/.claude/skills/gauntlet/`. Want to read it before running? Pipe it to a file first, review, then run.

Just the CLI (no skill), if that is all you need:

```bash
pipx install git+https://github.com/gioeleBrancaleoni/gauntlet.git
```

### From a clone

```bash
./scripts/install.sh
```

Same two layers, idempotent (re-run to update). `install.sh` auto-detects whether it is run from a cloned repo or piped from the web, so the one command above and this one share the same script.

### Manual equivalent

```bash
# 1. Global CLI (usable from any project as `gauntlet run ...`)
pipx install .            # or, without pipx:  pip install --user .

# 2. Skill discovered by Claude Code in every project
mkdir -p ~/.claude/skills/gauntlet && cp SKILL.md ~/.claude/skills/gauntlet/
```

### Windows

One line (no clone), in PowerShell:

```powershell
irm https://raw.githubusercontent.com/gioeleBrancaleoni/gauntlet/main/scripts/install.ps1 | iex
```

Or from a clone:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

`-ExecutionPolicy Bypass` runs the script **without** changing the system policy. It registers the skill in `%USERPROFILE%\.claude\skills\gauntlet\`. (The one-liner path is **not yet verified on a real Windows machine** — see below.)

### OS compatibility

- **Tested on macOS (Unix):** `./scripts/install.sh` runs natively; Linux is expected to behave the same way.
- **The Python test suite is cross-platform.**
- **Not yet tested on Windows:** `install.ps1` and the Windows runtime path are provided but **not verified on a real Windows machine**. (On WSL2 or Git Bash you can use `./scripts/install.sh` as on Linux.)

**Docker is required at runtime** either way: the OWASP ZAP daemon runs in a container during every scan. The ZAP Docker image is pulled automatically on the **first run** (not by the installer).

---

## Usage

```bash
gauntlet run --project <path> --level <N> [--aggressive]
```

- `--project` — the folder that contains `gauntlet.yaml`.
- `--level` — attacker knowledge level, `1` to `4` (see above).
- `--aggressive` — enables the destructive steps (ZAP active scan, cross-tenant writes). It is a single upfront batch consent; without it the run is non-destructive.

Per-project setup, after the one-time global install, is just:

1. a `gauntlet.yaml` contract in the project folder (start from [`gauntlet.example.yaml`](gauntlet.example.yaml));
2. the account passwords exported as environment variables (never in the YAML).

The report is written to `<project>/gauntlet-runs/<timestamp>/report.md`, alongside a self-contained `report.html` (no external assets, openable in any browser), and both paths are printed on screen.

Gauntlet also works as a **Claude Code skill**: ask in natural language ("scan my staging app for access-control bugs") and Claude orchestrates the run — including the level-3/4 manual testing that reads your docs and source.

> **Model note.** Gauntlet performs *legitimate, authorized* DAST against your own apps, but the security-testing prompts are **often refused by some models' safeguards** — in practice **Opus 5.5 and Fable frequently decline them**. The skill is **tested and working on Opus 4.8**. If your model refuses, either switch to Opus 4.8, or just run the CLI directly (`gauntlet run ...`) with a prepared `gauntlet.yaml` — the CLI does the scanning and needs no model at all. Ready-to-paste, well-framed prompts that models recognize as authorized testing are in [docs/prompts.md](docs/prompts.md).

> The report can contain **extracts of real responses, PII, or tokens** from the evidence of confirmed findings. Treat it as a confidential document and review it before sharing.

---

## Report language

Reports auto-localize to the system language, with **English as the fallback** when the system language is not supported (currently Italian and English). Force a language with `--report-lang {auto,it,en}`. Note: the text of ZAP's own alerts is passed through as ZAP provides it (English); only Gauntlet's own strings and findings are localized.

---

## The contract (`gauntlet.yaml`)

The contract describes what you may attack, how to reach it, how to authenticate, and which two different-customer accounts to use for tenant-isolation testing. A compact, annotated example (see [`gauntlet.example.yaml`](gauntlet.example.yaml) for the full one):

```yaml
name: example-app

# Fail-closed allowlist: only these origins (scheme + host + port) may receive
# traffic. Everything else is rejected. Use ONLY throwaway dev/stage targets.
allowed_targets:
  - http://localhost:8081
  - http://host.docker.internal:8081   # same target as seen from the ZAP container

# How the target is reachable: localhost | docker | vpn (context hint).
reachability: localhost

login:
  method: json                                   # form | json | token | session
  login_url: http://localhost:8081/api/auth/login
  username_field: email
  password_field: password
  logged_in_indicator: '"token"'                 # proves a successful login
  token_path: data.token                         # dot-path to the token (json/token)

# Two DIFFERENT-customer accounts: required for cross-tenant isolation testing.
accounts:
  - label: customer_a
    username: a@example.com
    password_env: EXAMPLE_A_PW                    # the password lives in this env var
    tenant_id: tenant-a
    seeded_resources:
      - kind: invoice
        id: inv-a-0001
        url_template: /api/invoices/{id}
        seed_marker: SEED-A-0001-marker           # ownership oracle for the cross-tenant test
  - label: customer_b
    username: b@example.com
    password_env: EXAMPLE_B_PW
    tenant_id: tenant-b
    seeded_resources:
      - kind: order
        id: 1001
        url_template: /api/orders/{id}
        owner_field: customer_email               # owner-field oracle for sequential-IDOR
        enumerate: true                           # probe neighboring IDs (optional)

# Optional: used to direct level-3/4 manual testing.
docs_path: ./docs
src_path: ./src
# Optional: endpoints for the vertical privilege-escalation probe.
admin_endpoints:
  - /api/admin/users
exclusions:
  - /health
  - /metrics
```

**Secrets never live in the YAML:** the contract references only the **name** of the environment variable holding the password (`password_env`), resolved at runtime. The optional `enumerate` / `owner_field` fields on a seeded resource enable sequential-ID IDOR fuzzing; `admin_endpoints` (at the project level) feeds the vertical privilege-escalation probe.

**Login methods** (`login.method`):

- `form` — form-encoded credentials; the session is captured from the response cookies.
- `json` / `token` — JSON credentials; the bearer token is extracted from `token_path` (a dot-path in the JSON response) and sent as `Authorization: Bearer <token>`.
- `session` — login that sets a **session cookie**. Success means HTTP `2xx` **and** the cookie named in `success_cookie` is present; no body token or `logged_in_indicator` is required. For `session`, `success_cookie` is **required**, while `password_field` and `logged_in_indicator` are **optional** — omit them for e.g. an email-only login. `login.extra.body_format` selects the request encoding (`json`, the default, or `form`) and `login.extra.body` adds fixed body fields. The body sent contains only the configured fields: the username always, the password only when `password_field` is set (and non-empty). The account password still comes from `password_env` — never written in the YAML.

---

## Known limitations

- **Reachability check.** `reachability: vpn` and `localhost` use a plain TCP connection check (the value is a context hint, not a different mechanism). Only `docker` is special-cased: a `host.docker.internal` host is mapped to `127.0.0.1` for the host-side connection check.
- **Vertical escalation probe.** The admin-endpoint list is generic unless you set `admin_endpoints` in the contract; targets with different admin routes may need it tuned.
- **Windows untested.** `install.ps1` and the Windows runtime path are provided but not yet verified on a real Windows machine.

---

## Development

```bash
pip install -e ".[dev]"
pytest -q      # 279 passing
```

The pure modules (contract, safety, alert normalization, levels, preflight, report, i18n) are unit-tested in isolation; Docker, ZAP, and the network are never touched by the suite (they are mocked).

## License

[MIT](LICENSE) © gioeleBrancaleoni
