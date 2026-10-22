# Gauntlet — catalog of security checks

This document is the complete, code-grounded catalog of every security check
Gauntlet performs. Each entry is taken directly from the implementing module;
the oracle conditions below are the exact conditions the code evaluates.

## Two engines, one philosophy

Gauntlet runs on two complementary engines:

1. **OWASP ZAP** (`gauntlet/zap_runner.py`) — a ZAP daemon in Docker that finds
   the *classic* web vulnerabilities (injection, XSS, missing security headers,
   misconfiguration, path traversal, SSRF, …) through spidering, passive
   scanning and (only when explicitly authorized) active scanning. ZAP's own
   risk and confidence values are carried through unchanged.
2. **A custom access-control & auth tester** (`gauntlet/access_control.py`,
   `gauntlet/jwt_checks.py`, `gauntlet/cors_checks.py`,
   `gauntlet/ratelimit_checks.py`, `gauntlet/error_disclosure_checks.py`,
   `gauntlet/open_redirect_checks.py`, `gauntlet/mass_assignment_checks.py`) — a
   set of focused probes written around **deterministic oracles**.

**No-false-positive philosophy.** The custom engine is built so that a finding
is *confirmed*, not *inferred*. A high-value finding is emitted only when the
code observes a specific, load-bearing piece of evidence — a victim's known
marker in the response body, a forged unsigned token being accepted, a foreign
origin being reflected with credentials, a recomputed HMAC matching the real
signature. A bare status code is **never** enough: a `2xx` on its own, an empty
list, a `302` to a login page — none of these produce a finding. Where an oracle
is deterministic the finding carries **confidence 1.0** (safe to act on
directly); where the detection is necessarily observational or pattern-based the
confidence is **below 1.0** and the wording is deliberately cautious.

The **no-false-positive-by-construction** guarantee applies only to Gauntlet's
own oracle-confirmed findings (`source != "zap"`). ZAP findings (check 15–16)
may also carry confidence `1.0`, but that value is **ZAP-adjudicated**, not
oracle-confirmed by Gauntlet: `normalize_alert` maps ZAP's own "confirmed"/"user
confirmed" confidence string to `1.0`. A ZAP `1.0` therefore means "ZAP is
confident", not "Gauntlet proved it with a load-bearing oracle" — triage ZAP
findings by ZAP's own assessment, independently of this guarantee.

Every request from either engine first passes the **fail-closed allowlist**
(`gauntlet/safety.py`): traffic is sent only to origins whose normalized
scheme+host+port exactly matches an `allowed_targets` entry. Anything else is
skipped without sending a byte. Redirects are never followed, so a `302` to a
login page is never mistaken for a `2xx`.

Internal severity labels in the source are Italian
(`critica`/`alta`/`media`/`bassa`/`info`); this document uses their English
equivalents **Critical / High / Medium / Low / Info**.

---

## Summary table

| Check | Source | Level / Mode | Severity | Confidence | Oracle type |
|---|---|---|---|---|---|
| Horizontal cross-tenant BOLA/IDOR | access-control | L2–4, default (read) | Critical | 1.0 | deterministic |
| Sequential-ID IDOR | access-control | L2–4, default (read) | Critical | 1.0 | deterministic |
| Missing / broken authentication | access-control | L2–4, default (read) | Critical | 1.0 | deterministic |
| Cross-tenant write (confirmed) | access-control | L2–4, `--aggressive` (write) | Critical | 1.0 | deterministic |
| Cross-tenant write (unconfirmed) | access-control | L2–4, `--aggressive` (write) | High | 0.5 | bounded (status-only) |
| Vertical privilege escalation | access-control | L2–4, default (read) | High | 0.6 | observational |
| Missing-marker advisory (not a vuln) | access-control | L2–4, default | Info | 1.0 | advisory |
| JWT `alg=none` accepted | jwt | L2–4 + token login, default (read) | Critical | 1.0 | deterministic (negative control) |
| JWT signature unverified / unauthenticated | jwt | L2–4 + token login, default (read) | High | 0.6 | bounded (control also accepted) |
| JWT weak HMAC secret | jwt | L2–4 + token login, default (read) | Critical | 1.0 | deterministic |
| CORS reflected origin + credentials | cors | Any level (1–4), default (read) | Critical | 1.0 | deterministic |
| CORS reflected origin, no credentials | cors | Any level (1–4), default (read) | High | 1.0 | deterministic |
| CORS wildcard `*` | cors | Any level (1–4), default (read) | Medium | 1.0 | deterministic |
| Login rate-limiting absence | rate-limit | Any level, `--aggressive` only | High | 0.6 | observational |
| Verbose error / stack-trace disclosure | error-disclosure | L2–4, default (read) | Medium | 0.7 | observational (pattern) |
| Open redirect (canary Location oracle) | open-redirect | Any level (1–4), default (read), only if `redirect_probes` set | High | 1.0 | deterministic |
| Mass assignment (forbidden-field write+read) | mass-assignment | L2–4, `--aggressive` only, only if `mass_assignment` set | High | 1.0 | deterministic |
| ZAP classic (passive) | zap | Any level, default | Info/Low/Medium/High | ZAP's own (0.0–1.0) | ZAP engine |
| ZAP classic (active) | zap | Any level, `--aggressive` only | Info/Low/Medium/High | ZAP's own (0.0–1.0) | ZAP engine |

"Level/Mode" reflects `gauntlet/levels.py` (`actions_for`) and the wiring in
`gauntlet/cli.py`: `run_access_control` is enabled at level ≥ 2; spider and
passive scan run at every level; active scan and all `--aggressive` steps run
only when the `--aggressive` flag (the single upfront batch consent) is set.

---

## Access-control & authentication

These live in `gauntlet/access_control.py`. The tester builds an
`OwnershipMap` from the configured accounts and their seeded resources, then
runs horizontal, sequential-IDOR, missing-auth and vertical probes. Default mode
is `read-only` (GET only); write probes run only in `write` mode, and each write
additionally passes `confirm_destructive`.

### 1. Horizontal cross-tenant BOLA/IDOR (seed-marker oracle)

- **Finding source:** access-control
- **What it probes:** For each resource seeded under tenant A, the same GET is
  replayed with tenant B's authenticated session — can one customer reach
  another customer's object?
- **When it runs:** Levels 2–4 (`run_access_control`), default/read-only.
- **Oracle (confirmed when):** in `_run_horizontal`, the attacker's GET returns
  **2xx AND** the victim's marker appears in the response body
  (`_is_2xx(response) and _body_contains_marker(response, marker)`). The marker
  **must be an explicit `resource.seed_marker`** (`marker = resource.seed_marker
  or None`). The id is **no longer** used as a fallback marker: `resource.id` is
  also interpolated into the request URL, so a `2xx` body that merely echoes the
  requested id (a soft-404, a self-link, an error envelope) would falsely
  "confirm" a leak. If a resource has no explicit `seed_marker` the leak test is
  **skipped** and only the info advisory is emitted (see check 7). `401/403/404`
  or a `2xx` with no marker (including an empty list) is "denied": no finding. A
  finding is never raised on status code alone.
- **Severity / confidence:** Critical / **1.0** (`_horizontal_finding`).
- **Trustworthiness:** Deterministic — no false positive by construction. The
  adversarial scenario (a public/anonymous page, an empty response, or a
  soft-404/error envelope echoing the requested id, all returning `2xx`) is
  precluded because the decider is an **operator-declared** marker that is *not*
  derived from the URL: a foreign tenant's response must literally contain A's
  distinctive `seed_marker` to be reported. Because the id is never used as the
  oracle, an id reflected in the body (e.g. `{"error":"invoice-2024 not found"}`)
  can no longer trigger a false Critical. If no explicit marker is available the
  leak test is skipped entirely (see check 7).

### 2. Sequential-ID IDOR (owner-field oracle)

- **Finding source:** access-control
- **What it probes:** For an enumerable numeric resource, the owner probes
  neighboring IDs (`id ± enumerate_count`) in read-only mode, looking for
  someone else's object reachable by guessing the ID.
- **When it runs:** Levels 2–4, default/read-only. Active only when
  `resource.enumerate` is true, `resource.owner_field` is declared, and the id is
  decimal (`resource.id.isdecimal()`); otherwise skipped.
- **Oracle (confirmed when):** `_run_sequential_idor` first GETs the account's
  **own** seeded resource (allowlist-gated) and reads *its* `owner_field` value →
  `self_owner` — the probing account's owner identity **in the same namespace as
  the field**. A neighbor GET (as the owner) is then a confirmed IDOR only when
  it returns **2xx AND** its `owner_field` value is **present and different from
  `self_owner`** (`leaked_owner is not None and leaked_owner != self_owner`). The
  comparison is value-against-value in the same field — **not** against the
  account's `username`, which may live in a different namespace (e.g. an email
  username vs a numeric `user_id`) and would then *always* differ, flagging the
  account's own adjacent objects. If `self_owner` cannot be determined (the
  own-resource GET is not `2xx`, or its `owner_field` is absent/empty) the test
  is **skipped** — the oracle cannot be established, so nothing is asserted. A
  missing field on the neighbor, a value equal to `self_owner`, or a non-JSON
  body → no finding. Every URL (own resource and each neighbor) passes the
  allowlist gate before any request.
- **Severity / confidence:** Critical / **1.0** (`_sequential_idor_finding`).
- **Trustworthiness:** Deterministic — no false positive by construction. The
  adversarial scenario (reading one's own adjacent object, or an endpoint that
  returns `2xx` with no ownership data) cannot trigger it: the neighbor's
  owner-field value must differ from the probing account's *own* owner value,
  read back from its own seeded resource in the same field. If ownership cannot
  be established on the account's own resource, there is no oracle and the test
  is skipped.

### 3. Missing / broken authentication (anonymous + marker)

- **Finding source:** access-control
- **What it probes:** Each seeded resource that declares a `seed_marker` is
  requested with a **fully anonymous** session — no `Authorization` header, no
  cookies (`_ANONYMOUS_SESSION`) — to see whether protected content is served to
  an unauthenticated client.
- **When it runs:** Levels 2–4, default/read-only (`_run_missing_auth`).
- **Oracle (confirmed when):** the anonymous GET returns **2xx AND** the
  resource's `seed_marker` appears in the body
  (`_is_2xx(response) and _body_contains_marker(response, marker)`). Only an
  explicit `seed_marker` qualifies (no fallback-id here); resources without one
  are skipped. `401/403` or a `2xx` with no marker (empty page/list) → no
  finding.
- **Severity / confidence:** Critical / **1.0** (`_anonymous_finding`).
- **Trustworthiness:** Deterministic — no false positive by construction. The
  adversarial scenario (a public landing page or empty body returning `2xx` to
  an anonymous client) is precluded because the protected resource's distinctive
  marker must be present in the anonymous response. Like the horizontal check,
  it requires an explicit `seed_marker` (there is no id fallback anywhere): an id
  echoed in the body can never act as the oracle.

### 4. Cross-tenant write — confirmed (write mode)

- **Finding source:** access-control
- **What it probes:** In `write` mode, the attacker tenant sends a PATCH to the
  victim's resource with a probe marker in the body, testing write-side IDOR.
- **When it runs:** Levels 2–4, **`--aggressive` only** (write mode), and each
  attempt passes `confirm_destructive` first.
- **Oracle (confirmed when):** the PATCH returns 2xx **and** a re-GET of the same
  URL **as the owner** shows the probe marker in the body
  (`_write_took_effect`: `_is_2xx(verify) and _body_contains_marker(verify, _WRITE_PROBE_MARKER)`).
  Only then is the Critical finding emitted.
- **Severity / confidence:** Critical / **1.0** (`_horizontal_write_finding`,
  `confirmed=True`).
- **Trustworthiness:** Deterministic — no false positive by construction. A
  `2xx` from the PATCH is *not* trusted on its own: the mutation must be
  independently verified by reading the victim's resource back as its owner and
  finding the probe marker. If the owner session is unavailable or the re-read
  does not show the marker, the Critical claim is not made (see check 5).

### 5. Cross-tenant write — unconfirmed (write mode)

- **Finding source:** access-control
- **What it probes:** Same PATCH as check 4, but where the mutation could not be
  independently verified on the victim's resource.
- **When it runs:** Levels 2–4, **`--aggressive` only**.
- **Oracle:** PATCH returned 2xx but `_write_took_effect` returned `False`
  (owner re-GET impossible, or marker absent). Explicitly labelled NOT CONFIRMED.
- **Severity / confidence:** High / **0.5** (`_horizontal_write_finding`,
  `confirmed=False`).
- **Trustworthiness:** Bounded, not deterministic. A `2xx` PATCH may reflect a
  no-op, an echo, or an accepted-but-ignored write; the code deliberately refuses
  to call this Critical and drops both the severity and the confidence. Residual
  risk: the server accepted the request shape but the effect on the victim's data
  is unproven — this warrants manual confirmation.

### 6. Vertical privilege escalation

- **Finding source:** access-control
- **What it probes:** Each authenticated (normal-user) session performs GETs
  against a list of known administrative endpoints — generic admin paths plus a
  set of privileged CMS/headless-API paths, merged with any
  `contract.admin_endpoints` (`_admin_endpoints_for`). A normal user reaching
  these is escalation.
- **When it runs:** Levels 2–4, default/read-only (`_run_vertical`). Each URL is
  allowlist-gated before probing.
- **Oracle:** the normal-user GET to an admin endpoint returns **2xx**
  (`_is_2xx(response)`).
- **Severity / confidence:** High / **0.6** (`_vertical_finding`).
- **Trustworthiness:** Observational — confidence intentionally below 1.0. There
  is no ownership/marker oracle here; the signal is "status 2xx on a known admin
  path." Adversarial false-positive vector: a path assumed to be admin-only may
  in fact be legitimately readable by a normal user on this particular app (a
  public `/settings`-style endpoint, a documented read API, a soft 200 page).
  The oracle *bounds* the risk — the endpoint list is curated to paths a normal
  user genuinely should not read, and only *real* admin endpoints are tested
  (merely *discovered* endpoints are never fed here) — but it does not *preclude*
  a false positive, hence 0.6 and cautious wording that warrants human review.

### 7. Missing-marker advisory (not a vulnerability)

- **Finding source:** access-control
- **What it probes:** When a seeded resource declares no explicit `seed_marker`,
  the horizontal leak test cannot run deterministically (the id is never used as
  a fallback marker).
- **When it runs:** Levels 2–4, default (`_needs_marker_finding`).
- **Oracle:** `resource.seed_marker` is absent/empty (`marker is None`).
- **Severity / confidence:** Info / **1.0**.
- **Trustworthiness:** This is an advisory, not a vulnerability claim: it asks
  the operator to declare a `seed_marker` so the leak test can run. It never
  asserts a leak, so it cannot be a false positive in the security sense.

---

## JWT

In `gauntlet/jwt_checks.py`. Run at authenticated levels (≥ 2) **only for
token-based login** (the bearer is a real JWT), against the primary account and
one of its seeded resources used as a probe. Non-destructive (GET only). The
probe URL is allowlist-gated before any request; a malformed token simply
returns `[]`.

### 8. JWT `alg=none` accepted

- **Finding source:** jwt
- **What it probes:** Forges a token with header `{"alg":<variant>,"typ":"JWT"}`,
  the **same payload** as the real token, and an **empty signature** (the
  `base64url(header).base64url(payload).` form), then sends it as
  `Authorization: Bearer` to the probe. Each of the case variants `none`, `None`,
  `NONE` is tried (some servers match the algorithm case-insensitively); the
  first variant accepted yields a single finding noting which variant worked.
- **When it runs:** Levels 2–4 + token login, default/read-only
  (`_check_alg_none`).
- **Negative control first:** before trusting an accepted `alg=none` token,
  `_check_alg_none` sends a **negative control** — a token with the **same `alg`
  as the real token** but a deliberately **corrupted signature**
  (`_control_token`) — to the same (already allowlist-gated) probe. This proves
  the server *normally rejects* a bad signature. Only if the control is rejected
  is an accepted `alg=none` variant meaningful.
- **Oracle (confirmed when):** the control is **rejected** (not `2xx`, or marker
  absent) **AND** a forged `alg=none` variant response is **2xx AND** the known
  marker appears in the body (`_is_2xx(response) and marker in response.text`).
  If no marker is known the check is deterministically disabled and returns `[]`
  — acceptance is never asserted on status code alone.
- **Severity / confidence:** Critical / **1.0** (`_alg_none_finding`).
- **If the control is *also* accepted:** the endpoint does not verify the token
  signature at all / is effectively unauthenticated. The precise mechanism is
  ambiguous (it may be a public endpoint rather than `alg=none` specifically), so
  the Critical `alg=none` claim is **not** made; instead a softer finding
  "Endpoint does not verify the token signature / unauthenticated access" is
  emitted at **High / 0.6** (`_unverified_finding`).
- **Trustworthiness:** Deterministic — no false positive by construction. The
  negative control removes the key adversarial vector: an unauthenticated or
  public probe endpoint would accept *any* token (including the corrupted-signature
  control), and that case is now diverted to the softer 0.6 finding instead of a
  false `alg=none` Critical. A Critical is raised only when the server rejects a
  bad signature yet accepts an unsigned `alg=none` token returning the marker —
  unambiguous proof that signature verification is specifically bypassable.

### 9. JWT weak HMAC secret

- **Finding source:** jwt
- **What it probes:** Only when the real token's `alg` is `HS256`/`HS384`/`HS512`,
  the signature is replayed against a small embedded wordlist of common/default
  signing secrets: the HMAC over `header.payload` is recomputed with each
  candidate (stdlib `hmac`/`hashlib`) and compared to the token's actual
  signature. For `RS*`/`ES*`/`none` the check is skipped (not applicable).
- **When it runs:** Levels 2–4 + token login, default/read-only
  (`_check_weak_secret`).
- **Oracle (confirmed when):** a candidate secret's recomputed base64url HMAC
  equals the token's signature under a constant-time compare
  (`hmac.compare_digest(_b64url_encode(digest), actual_signature)`).
- **Severity / confidence:** Critical / **1.0** (`_weak_secret_finding`).
- **Trustworthiness:** Deterministic — no false positive by construction. A match
  means the candidate secret *is* the signing key: it reproduces the exact
  signature byte-for-byte. There is no probabilistic step; it either matches or
  it does not. (This is a *local* cryptographic check and sends no forged request
  for this finding.)

---

## CORS

In `gauntlet/cors_checks.py`. Sends each origin a GET carrying a deliberately
**foreign** `Origin` header (a reserved RFC 2606 example domain,
`PROBE_ORIGIN`) and judges only by the returned CORS headers. Non-destructive
(GET only), allowlist-gated, and — unlike the access-control checks — it does
**not** depend on authentication, so it runs at **every level (1–4)**. Origins
tested are `allowed_targets` plus the login URL's origin, deduplicated.

The order in `_classify` matters: wildcard is evaluated before credentialed
reflection (with `ACAO: *` browsers ignore credentials anyway).

### 10. CORS reflected foreign origin + credentials

- **Finding source:** cors
- **What it probes:** Whether the server reflects the foreign probe origin *and*
  allows credentials — the worst case (any site can read authenticated
  responses).
- **When it runs:** Any level, default/read-only.
- **Oracle (confirmed when):** `Access-Control-Allow-Origin == PROBE_ORIGIN`
  **AND** `Access-Control-Allow-Credentials` (trimmed, lowercased) `== "true"`.
- **Severity / confidence:** Critical / **1.0** (`cors_credentialed`).
- **Trustworthiness:** Deterministic — no false positive by construction. A
  correct server never reflects a foreign origin; at most it reflects a
  *configured* trusted origin, which is not the probe. Reflecting *our*
  unregistrable example origin is indiscriminate reflection (a bug), not an
  allowlist decision.

### 11. CORS reflected foreign origin, no credentials

- **Finding source:** cors
- **Oracle:** `ACAO == PROBE_ORIGIN` and credentials **not** `true`.
- **When it runs:** Any level, default.
- **Severity / confidence:** High / **1.0** (`cors_reflect`).
- **Trustworthiness:** Deterministic — same reasoning as check 10; the foreign
  probe origin was reflected, which a correct server never does.

### 12. CORS wildcard `*`

- **Finding source:** cors
- **Oracle:** `ACAO == "*"`.
- **When it runs:** Any level, default.
- **Severity / confidence:** Medium / **1.0** (`cors_wildcard`).
- **Trustworthiness:** Deterministic — the header literally is `*`. Severity is
  Medium because browsers ignore credentials under a wildcard; it is a real
  permissive-config observation, not an inference. An `ACAO` present but equal to
  neither the probe nor `*` (a configured trusted origin) yields **no finding**.

---

## Operational / configuration

### 13. Login rate-limiting absence

- **Finding source:** rate-limit (`gauntlet/ratelimit_checks.py`)
- **What it probes:** Sends a few consecutive **failed** logins (real username,
  a deliberately wrong probe password — never a real authentication) and watches
  for any throttling signal.
- **When it runs:** **`--aggressive` only**, at any level (gated by `aggressive
  and contract.accounts` in the CLI; not by the authenticated level). It is
  destructive-ish because repeated failed logins can trigger account lockout;
  attempts are few, sequential and capped (`_MAX_ATTEMPTS = 20`, default 8). The
  login URL is allowlist-gated first.
- **Oracle:** after N received responses, **none** returned HTTP `429` nor
  carried a `Retry-After` header (`_is_throttled`). If *any single* attempt shows
  throttling → no finding. If zero responses were received (transport errors
  only) → no finding (nothing asserted).
- **Severity / confidence:** High / **0.6** (`_no_ratelimit_finding`).
- **Trustworthiness:** Observational — confidence below 1.0 by design. It is an
  observation over N attempts, not a proof. Adversarial false-positive vector: a
  limiter with a higher threshold, or an IP-based limiter with a wide window,
  may simply not trip within so few attempts — so "no throttling observed in N
  attempts" is not "the login definitely has no rate limiting." Moreover the
  oracle only recognises `429` and `Retry-After` as throttling signals: a server
  that throttles by other means (an HTTP `403`/lockout, a CAPTCHA challenge, or a
  custom "too many attempts" body with a `200`/`4xx` status) would be **missed**
  and could yield a finding even though a limiter exists. The wording is
  deliberately bounded to the N attempts actually made, and the finding warrants
  human confirmation.

### 14. Verbose error / stack-trace disclosure

- **Finding source:** error-disclosure (`gauntlet/error_disclosure_checks.py`)
- **What it probes:** Requests known protected resources with a **deliberately
  malformed id** (a quote, a URL-encoded null byte, a very long string — built in
  the CLI from the primary account's seeded resources) and searches the body for
  *specific* error signatures (not generic words).
- **When it runs:** Levels 2–4 (authenticated), default/read-only; GETs made as
  the resource owner; each probe URL allowlist-gated.
- **Oracle:** the response body matches one of the curated signatures in
  `_first_signature` — framework/language tracebacks (Python `Traceback …`,
  `SyntaxError:`, JS `ReferenceError:`, a JSON `"stack"` field adjacent to a real
  frame marker, Java stack frames), and database/ORM errors (`SQLSTATE`, MySQL
  `ER_*`, Oracle `ORA-#####`, `PG::`, `SequelizeDatabaseError`, MySQL error
  text). Two signatures are **error-gated** (considered only when the status is
  ≥ 400): filesystem paths (`/home/`, `/usr/`, `/var/`; `/app/` is deliberately
  excluded to avoid SPA route collisions), and the MySQL `ER_*` error code —
  because `ER_[A-Z]…` also matches ordinary application constants (e.g. an
  `ER_MODEL` enum value) that can legitimately appear in a normal `2xx` body. The
  evidence reports only the matched signature snippet (capped at 160 chars),
  never the full body.
- **Severity / confidence:** Medium / **0.7** (`_disclosure_finding`).
- **Trustworthiness:** Observational / pattern-based — confidence below 1.0 by
  design. The signatures are curated and specific to keep false positives low,
  but they cannot eliminate them: a legitimate response could by chance contain a
  signature string (an asset path, or the word "MySQL" in an informational
  message). The error-gating of the ambiguous filesystem-path signature removes
  the most common false-positive vector (a `/home/…`-looking string on a normal
  `2xx` page), but the pattern approach only *bounds* the risk — hence 0.7 and
  cautious wording. Warrants human confirmation.

---

## ZAP classic vulnerabilities

In `gauntlet/zap_runner.py`. ZAP crawls the target (spider) and reports findings
from passive analysis of that traffic; active scanning (intrusive payloads such
as SQLi and command injection) runs only under `--aggressive`. Every
traffic-sending operation (`spider`, `active_scan`) passes the allowlist gate
first; active scanning additionally requires destructive confirmation.

### 15. ZAP passive-scan findings

- **Finding source:** zap
- **What it probes:** Classic web issues surfaced passively from spider traffic:
  injection indicators, XSS, missing/weak security headers, misconfigurations,
  path traversal, SSRF, information leaks, and more.
- **When it runs:** Any level (spider + passive scan run by default), default /
  non-destructive. No intrusive payloads are sent.
- **Oracle:** ZAP's own detection. `normalize_alert` maps ZAP risk →
  severity (`informational→Info`, `low→Low`, `medium→Medium`, `high→High`); an
  unknown/absent risk degrades to Info (never inflated). **Critical is never
  emitted by ZAP** — it is reserved for confirmed access-control findings.
- **Severity / confidence:** Info / Low / Medium / High, per ZAP's risk; **ZAP's
  own confidence**, mapped to a float (`false positive→0.0`, `low→0.25`,
  `medium→0.5`, `high→0.75`, `confirmed`/`user confirmed→1.0`; unknown → 0.5).
- **Trustworthiness:** These carry ZAP's engine confidence, not Gauntlet's
  deterministic-oracle guarantee. Treat them according to the confidence value on
  each finding; lower-confidence ZAP alerts warrant human triage.

### 16. ZAP active-scan findings

- **Finding source:** zap
- **What it probes:** The same classes of classic vulnerabilities, but surfaced
  by *active* scanning — ZAP sends intrusive payloads (SQLi, command injection,
  etc.) to exercise the authenticated surface.
- **When it runs:** Any level, **`--aggressive` only** (destructive); gated by
  the allowlist and by destructive confirmation before any traffic.
- **Oracle / severity / confidence:** identical normalization to check 15
  (`normalize_alert`); severity from ZAP risk (never Critical), confidence from
  ZAP's confidence string.
- **Trustworthiness:** As with passive findings, these carry ZAP's own
  confidence. Active scanning exercises more of the app and tends to produce
  higher-confidence results, but they remain ZAP-adjudicated, not
  deterministic-oracle findings.

> Note: Gauntlet also emits an **informational** "discovered surface" item
> (`source="zap"`, Info, confidence 1.0) at levels 3–4 listing endpoints found in
> docs/source that were added as ZAP seeds. It is transparency, not a
> vulnerability: discovered endpoints — lacking an owner and a marker — are never
> turned into access-control findings.

---

## Open redirect

In `gauntlet/open_redirect_checks.py`. For each template in
`contract.redirect_probes` the module injects a deliberately **foreign** canary
destination (`PROBE_DESTINATION`, a reserved RFC 2606 example domain) in place of
the `{payload}` placeholder, resolves the template against the app's base URL and
sends a single GET **without following redirects** (`follow_redirects=False`), so
the original redirect response stays inspectable. Non-destructive (GET only),
allowlist-gated before every request, and — like CORS — it does **not** depend on
authentication, so it runs at **every level (1–4)**. At authenticated levels the
primary account's session headers/cookies are forwarded so probes also reach
pages behind login. The module is **opt-in**: with no `redirect_probes` configured
it sends no traffic and emits nothing.

### 17. Open redirect (canary Location oracle)

- **Finding source:** open-redirect
- **What it probes:** Whether an endpoint that builds its redirect from a
  user-controlled parameter (typically `?next=`, `?url=`, `?returnTo=`) will send
  the victim to an attacker-chosen host — the basis for credible phishing, OAuth/
  SSO token theft and filter bypass. The canary destination is injected
  URL-encoded into each template.
- **When it runs:** Any level (1–4), default/read-only, **only when
  `redirect_probes` is configured** (the module no-ops otherwise).
- **Oracle (confirmed when):** the response is a redirect
  (`300 <= status < 400`) **AND** carries a `Location` header **AND** that
  `Location`'s host (`netloc`) equals the canary's host
  (`urlsplit(location).netloc.lower() == _PROBE_HOST`). The `netloc` comparison
  catches `https://canary/…`, `http://canary/…` and the protocol-relative
  `//canary/…`. A **relative** `Location` (empty `netloc`: the app stays on its
  own host) or one to a **different** origin produces **no finding** — a bare
  redirect status is never enough.
- **Severity / confidence:** High / **1.0** (`_finding`).
- **Trustworthiness:** Deterministic — no false positive by construction. The
  decider is **exact netloc equality** against an unregistrable example host we
  injected: a correct app validates the destination and either stays on its own
  host (relative `Location`) or redirects to a configured origin — never to our
  canary. Only a `Location` whose host literally equals the canary's confirms the
  app followed the unvalidated input, so a relative or different-origin redirect
  can never trigger a false High.

---

## Mass assignment

In `gauntlet/mass_assignment_checks.py`. For each probe in
`contract.mass_assignment` the module tries to write an **operator-declared**
forbidden field (e.g. `role`) to a sentinel value (e.g. `admin`) on an update
endpoint, then re-reads the resource to confirm the write actually took effect.
It is **destructive** (it writes), so it runs **`--aggressive` only**; it is
authenticated (the CLI forwards the primary account's session headers/cookies,
as the JWT/error-disclosure blocks do); and it is **opt-in**: with no
`mass_assignment` configured the module sends no traffic and emits nothing.
Every request passes the fail-closed allowlist first (evaluated on the
contract's original URL, before any host-side docker remap), and every write is
gated by destructive confirmation (`confirm_destructive`): without an explicit
go-ahead no request is sent — not even the pre-GET. After the probe the original
value is restored best-effort.

### 18. Mass assignment (forbidden-field write + read oracle)

- **Finding source:** mass-assignment
- **What it probes:** Whether an update endpoint merges the whole request body
  without filtering assignable fields, letting the client set a protected
  attribute it should only be able to read (privilege/ownership/internal-state
  escalation, e.g. `role=admin`). The field and value are **operator-declared**
  in the contract (`MassAssignmentProbe`), never guessed.
- **When it runs:** Levels 2–4 (authenticated), **`--aggressive` only**, and
  **only when `mass_assignment` is configured** (the module no-ops otherwise).
  The CLI forwards the primary account's session headers/cookies; each write
  additionally passes `confirm_destructive`.
- **Oracle (confirmed when):** a two-step *write + re-read* oracle in
  `_probe_one`: a pre-GET reads the field's initial value (`original`), a write
  (`PATCH` by default) sets **only** the forbidden field to the sentinel value,
  and a re-GET reads it back (`current`). The finding is emitted only when
  `current is not None and str(current) == str(forbidden_value) and (original is
  None or str(original) != str(forbidden_value))` — i.e. the re-read field is
  **present** and reflects the sentinel, **AND** that value is a real change. A
  write that returns `2xx` but does not actually mutate the field, a re-GET where
  the field is **absent or `null`** (`_field_value` returns `None` in both
  cases, and the `current is not None` guard rejects it — even when the sentinel
  itself is `None`), or a resource that already held that value, all produce
  **no finding** — it is never raised on the write's status alone.
- **Typed sentinel:** `forbidden_value` keeps its YAML/JSON type and is sent as a
  **typed JSON value** in the write body (`json={forbidden_field: forbidden_value}`),
  not coerced to a string. A boolean `forbidden_value: true` is sent as a JSON
  boolean `true` (not the string `"True"`), an integer stays an integer, and a
  bare word like `admin` stays a string — so the probe exercises the field with
  the real type the API expects. The confirmation compares with `str(...)` on
  both sides, so a present falsy sentinel (e.g. `false`, `0`) still confirms when
  reflected; only an absent/`null` re-read is rejected (by the guard above).
- **Severity / confidence:** High / **1.0** (`_finding`).
- **Trustworthiness:** Deterministic — no false positive by construction. The
  decider is the re-read of an operator-declared forbidden field reflecting the
  exact sentinel value we wrote, and only when that represents a real change from
  the pre-existing value. A bare `2xx` from the update, an accepted-but-ignored
  write, or a field that already carried the value cannot trigger it: the
  sentinel must be observed on the resource after the write.

---

## Confidence & false positives

**Safe to act on directly (deterministic oracle, confidence 1.0).** These are
*confirmed*, not inferred — the code observed load-bearing evidence, and by
construction they have no false positives. This guarantee covers Gauntlet's own
oracle findings only (`source != "zap"`); a ZAP `1.0` is ZAP-adjudicated (see
below), not oracle-confirmed:

- Horizontal cross-tenant BOLA/IDOR (marker in body)
- Sequential-ID IDOR (owner-field names a different owner)
- Missing / broken authentication (anonymous request returns the marker)
- Cross-tenant write **confirmed** (owner re-read shows the probe marker)
- JWT `alg=none` accepted (unsigned token returns the marker)
- JWT weak HMAC secret (recomputed HMAC equals the real signature)
- CORS reflected origin + credentials / reflected origin / wildcard (header
  values read directly)
- Open redirect (redirect `Location`'s host equals the injected canary host)
- Mass assignment (forbidden field reflected on re-read as a real change)

**Warrant human confirmation (observational or bounded, confidence < 1.0).**
The oracle *bounds* the risk but does not *preclude* a false positive:

- Vertical privilege escalation — 0.6 (status-only on a known admin path; the
  path may be legitimately readable)
- Login rate-limiting absence — 0.6 (observation over N attempts; a
  higher-threshold or IP-window limiter may not trip)
- Verbose error / stack-trace disclosure — 0.7 (curated patterns can still match
  a legitimate response by chance)
- Cross-tenant write **unconfirmed** — 0.5 (PATCH `2xx` with the mutation
  unproven on the victim's data)
- JWT signature unverified / unauthenticated endpoint — 0.6 (the negative control
  was *also* accepted, so the mechanism is ambiguous: not asserted as `alg=none`)

**ZAP findings carry ZAP's own confidence.** Passive and active ZAP alerts are
adjudicated by the ZAP engine, not by Gauntlet's deterministic oracles; each
finding's confidence float reflects ZAP's assessment (0.0 for a self-declared
false positive up to 1.0 for a ZAP-confirmed alert). Triage them according to
that value.
