"""Test del controllo di configurazione CORS (``gauntlet.cors_checks``).

L'oracolo è **deterministico**: la gravità del finding dipende solo dagli header
CORS restituiti a una GET con un header ``Origin`` chiaramente estraneo
(:data:`gauntlet.cors_checks.PROBE_ORIGIN`). Un server CORS corretto non riflette
mai un'origine estranea, quindi non produce finding.

Si usa ``pytest-httpserver`` per restituire header CORS controllati.
"""

import re

from werkzeug.wrappers import Response

from gauntlet import cors_checks
from gauntlet.contract import Account, Contract, LoginConfig

PROBE = cors_checks.PROBE_ORIGIN


def _contract(allowed_targets: list[str], login_url: str) -> Contract:
    return Contract(
        name="test",
        allowed_targets=allowed_targets,
        reachability="localhost",
        login=LoginConfig(
            method="json",
            login_url=login_url,
            username_field="email",
            password_field="password",
            logged_in_indicator='"token"',
            token_path="token",
        ),
        accounts=[
            Account(label="cliente_a", username="a@x", password_env="A_PW"),
        ],
    )


def _run(httpserver, headers=None, status=200):
    """Registra la radice con gli header CORS dati ed esegue il controllo."""
    httpserver.expect_request("/", method="GET").respond_with_data(
        "ok", status=status, headers=headers or {}
    )
    httpserver.expect_request(re.compile(r".*")).respond_with_data("ok", status=200)
    origin = httpserver.url_for("/").rstrip("/")
    contract = _contract([origin], login_url=f"{origin}/login")
    return cors_checks.run([origin], contract, "localhost")


def test_reflect_origin_with_credentials_is_critica(httpserver):
    findings = _run(
        httpserver,
        headers={
            "Access-Control-Allow-Origin": PROBE,
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert len(findings) == 1
    assert findings[0].source == "cors"
    assert findings[0].severity == "critica"
    assert findings[0].confidence == 1.0


def test_reflect_origin_without_credentials_is_alta(httpserver):
    findings = _run(
        httpserver, headers={"Access-Control-Allow-Origin": PROBE}
    )
    assert len(findings) == 1
    assert findings[0].source == "cors"
    assert findings[0].severity == "alta"


def test_wildcard_is_media(httpserver):
    # Anche con Allow-Credentials dichiarato, il wildcard resta 'media': i
    # browser ignorano le credenziali quando ACAO è '*'.
    findings = _run(
        httpserver,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert len(findings) == 1
    assert findings[0].source == "cors"
    assert findings[0].severity == "media"


def test_no_acao_header_is_no_finding(httpserver):
    # CORS corretto: nessun header ACAO sul traffico cross-origin => nessun finding.
    findings = _run(httpserver, headers={})
    assert findings == []


def test_echoes_only_configured_origin_is_no_finding(httpserver):
    # Un server corretto riflette solo un'origine *configurata* (non la sonda
    # estranea): l'oracolo non scatta.
    findings = _run(
        httpserver,
        headers={
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert findings == []


def test_localized_in_english(httpserver):
    httpserver.expect_request("/", method="GET").respond_with_data(
        "ok", headers={"Access-Control-Allow-Origin": PROBE,
                       "Access-Control-Allow-Credentials": "true"}
    )
    httpserver.expect_request(re.compile(r".*")).respond_with_data("ok")
    origin = httpserver.url_for("/").rstrip("/")
    contract = _contract([origin], login_url=f"{origin}/login")

    findings = cors_checks.run([origin], contract, "localhost", lang="en")
    assert len(findings) == 1
    assert "credential" in findings[0].title.lower()


def test_offallowlist_target_sends_no_request(httpserver):
    # Il target e l'origine di login puntano al server finto, ma l'allowlist del
    # contratto è un'altra origine: il gate fail-closed salta ogni sonda =>
    # nessun finding e nessun traffico verso il server finto.
    httpserver.expect_request(re.compile(r".*")).respond_with_data(
        "ok", headers={"Access-Control-Allow-Origin": PROBE,
                       "Access-Control-Allow-Credentials": "true"}
    )
    origin = httpserver.url_for("/").rstrip("/")
    contract = _contract(
        ["http://example.invalid:9999"], login_url="http://example.invalid:9999/login"
    )

    findings = cors_checks.run([origin], contract, "localhost")

    assert findings == []
    assert len(httpserver.log) == 0


def test_login_url_origin_is_probed(httpserver):
    # Se il login_url ha un'origine CONSENTITA, viene sondata anche quella
    # (oltre ai targets). Qui targets è vuoto ma login_url punta al server.
    httpserver.expect_request("/", method="GET").respond_with_data(
        "ok", headers={"Access-Control-Allow-Origin": PROBE}
    )
    httpserver.expect_request(re.compile(r".*")).respond_with_data("ok")
    origin = httpserver.url_for("/").rstrip("/")
    contract = _contract([origin], login_url=f"{origin}/api/login")

    findings = cors_checks.run([], contract, "localhost")
    assert len(findings) == 1
    assert findings[0].severity == "alta"
