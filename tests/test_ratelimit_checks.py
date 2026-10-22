"""Test del modulo sull'assenza di rate limiting sul login (``gauntlet.ratelimit_checks``).

Il controllo è **aggressive-only** e volutamente *destructive-ish*: invia alcuni
tentativi di login FALLITI consecutivi (password deliberatamente errata) e
osserva se il server applica un qualche throttling (HTTP ``429`` o header
``Retry-After``). È un'osservazione su N tentativi, non una prova assoluta:
confidenza ``~0.6`` e formulazione prudente ("nessun throttling osservato in N
tentativi"). Verificato contro un server finto (``pytest-httpserver``), senza
alcun socket reale.

Il gate allowlist fail-closed è sempre la prima barriera: un ``login_url`` fuori
allowlist non deve produrre alcuna richiesta.
"""

import pytest
from werkzeug.wrappers import Response

from gauntlet import ratelimit_checks
from gauntlet.contract import Account, Contract, LoginConfig


def _login_cfg(login_url: str, method: str = "json") -> LoginConfig:
    return LoginConfig(
        method=method,
        login_url=login_url,
        username_field="email",
        password_field="password",
        logged_in_indicator='"token"',
        token_path="token",
    )


def _contract(allowed_targets: list[str], login_url: str) -> Contract:
    return Contract(
        name="test",
        allowed_targets=allowed_targets,
        reachability="localhost",
        login=_login_cfg(login_url),
        accounts=[Account(label="a", username="a@x", password_env="A_PW")],
    )


def _run(httpserver, *, allowed=None, attempts=8, lang="it", method="json"):
    login_url = httpserver.url_for("/login")
    allowed_targets = allowed if allowed is not None else [httpserver.url_for("/")]
    return ratelimit_checks.run(
        _login_cfg(login_url, method),
        "a@x",
        contract=_contract(allowed_targets, login_url),
        reachability="localhost",
        attempts=attempts,
        lang=lang,
    )


def test_no_throttling_all_401_is_flagged(httpserver):
    # Server che non limita: ogni tentativo fallito riceve 401, mai 429.
    httpserver.expect_request("/login", method="POST").respond_with_data(
        "bad credentials", status=401
    )

    findings = _run(httpserver, attempts=6)

    assert len(findings) == 1
    assert findings[0].severity == "alta"
    # Osservazione su N tentativi: confidenza esplicitamente < 1.0.
    assert abs(findings[0].confidence - 0.6) < 0.05
    assert findings[0].source == "rate-limit"


def test_429_within_attempts_no_finding(httpserver):
    # Appena compare un 429 (throttling) il controllo non segnala nulla.
    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        if state["n"] >= 3:
            return Response("slow down", status=429)
        return Response("bad credentials", status=401)

    httpserver.expect_request("/login", method="POST").respond_with_handler(handler)

    findings = _run(httpserver, attempts=8)

    assert findings == []


def test_retry_after_header_counts_as_throttling(httpserver):
    # Anche un Retry-After (senza 429 esplicito) è un segnale di throttling.
    def handler(request):
        return Response("too many", status=503, headers={"Retry-After": "30"})

    httpserver.expect_request("/login", method="POST").respond_with_handler(handler)

    findings = _run(httpserver, attempts=5)

    assert findings == []


def test_off_allowlist_login_sends_no_request(httpserver):
    # login_url fuori allowlist => nessun tentativo parte.
    hits: list[int] = []

    def handler(request):
        hits.append(1)
        return Response("bad credentials", status=401)

    httpserver.expect_request("/login", method="POST").respond_with_handler(handler)

    findings = _run(
        httpserver, allowed=["http://altro-host-non-consentito:9999"], attempts=5
    )

    assert findings == []
    assert hits == []


def test_uses_wrong_password_probe_never_authenticates(httpserver):
    # La password inviata è SEMPRE la sonda errata: non si autentica mai davvero.
    seen: list[dict] = []

    def handler(request):
        seen.append(request.get_json(silent=True) or {})
        return Response("bad credentials", status=401)

    httpserver.expect_request("/login", method="POST").respond_with_handler(handler)

    _run(httpserver, attempts=4)

    assert seen  # qualche tentativo è partito
    assert all(b.get("password") == "gauntlet-wrong-password-probe" for b in seen)
    assert all(b.get("email") == "a@x" for b in seen)


def test_attempts_are_bounded(httpserver):
    # Un attempts assurdo viene limitato: non si martella il login all'infinito.
    hits: list[int] = []

    def handler(request):
        hits.append(1)
        return Response("bad credentials", status=401)

    httpserver.expect_request("/login", method="POST").respond_with_handler(handler)

    _run(httpserver, attempts=10_000)

    assert 0 < len(hits) <= ratelimit_checks._MAX_ATTEMPTS


def test_finding_localized_english(httpserver):
    httpserver.expect_request("/login", method="POST").respond_with_data(
        "bad credentials", status=401
    )

    findings = _run(httpserver, attempts=4, lang="en")

    assert len(findings) == 1
    assert "rate limiting" in findings[0].title.lower()
