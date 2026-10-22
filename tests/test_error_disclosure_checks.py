"""Test del modulo sulla divulgazione di errori/stack trace (``gauntlet.error_disclosure_checks``).

Il controllo è **read-only** (solo GET) e di default: richiede risorse protette
note con un ``id`` deliberatamente malformato e cerca nel corpo *firme specifiche*
di stack trace / errori di framework (non parole generiche). È basato su pattern:
confidenza ``~0.7`` e formulazione prudente. Verificato contro un server finto
(``pytest-httpserver``), senza alcun socket reale.

Il gate allowlist fail-closed è sempre la prima barriera: una probe URL fuori
allowlist non deve produrre alcuna richiesta.
"""

import pytest
from werkzeug.wrappers import Response

from gauntlet import error_disclosure_checks
from gauntlet.contract import Account, Contract, LoginConfig


def _contract(allowed_targets: list[str]) -> Contract:
    return Contract(
        name="test",
        allowed_targets=allowed_targets,
        reachability="localhost",
        login=LoginConfig(
            method="token",
            login_url="http://localhost/login",
            username_field="email",
            password_field="password",
            logged_in_indicator='"token"',
            token_path="token",
        ),
        accounts=[Account(label="a", username="a@x", password_env="A_PW")],
    )


def _run(httpserver, *, allowed=None, lang="it"):
    probe = httpserver.url_for("/probe")
    allowed_targets = allowed if allowed is not None else [httpserver.url_for("/")]
    return error_disclosure_checks.run(
        [probe],
        {"Authorization": "Bearer x"},
        contract=_contract(allowed_targets),
        reachability="localhost",
        lang=lang,
    )


def test_python_traceback_is_flagged(httpserver):
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        "Traceback (most recent call last):\n  File \"/app/main.py\", line 5\n",
        status=500,
    )

    findings = _run(httpserver)

    assert len(findings) == 1
    assert findings[0].severity == "media"
    assert findings[0].source == "error-disclosure"
    # Pattern-based: confidenza esplicitamente < 1.0.
    assert abs(findings[0].confidence - 0.7) < 0.05
    # L'evidenza riporta la firma, non l'intero corpo.
    assert "Traceback (most recent call last)" in findings[0].evidence


def test_sqlstate_is_flagged(httpserver):
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        '{"message":"error: SQLSTATE[42000]: syntax error near ..."}', status=500
    )

    findings = _run(httpserver)

    assert len(findings) == 1
    assert findings[0].severity == "media"
    assert "SQLSTATE" in findings[0].evidence


def test_clean_json_error_no_finding(httpserver):
    # Una risposta di errore pulita non contiene firme specifiche => nessun finding.
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        '{"error":"Not Found"}', status=404, content_type="application/json"
    )

    assert _run(httpserver) == []


def test_spa_route_on_200_is_not_flagged(httpserver):
    # Regressione: una risposta 200 che contiene un percorso tipo filesystem
    # (una rotta SPA) NON deve generare un finding. La firma del percorso vale
    # SOLO su risposte di errore (>= 400); '/app/' è inoltre escluso del tutto.
    body = '<a href="/app/dashboard">Dashboard</a> <link href="/usr/share/x.css">'
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        body, status=200, content_type="text/html"
    )

    assert _run(httpserver) == []


def test_filesystem_path_on_error_status_is_flagged(httpserver):
    # Controprova: lo stesso tipo di percorso ('/home/'/'/var/') su una risposta
    # di ERRORE (500) è invece un indizio di dump e viene segnalato.
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        "Error loading /home/app/service/handler.py: boom", status=500
    )

    findings = _run(httpserver)

    assert len(findings) == 1
    assert findings[0].severity == "media"


def test_legit_json_stack_field_is_not_flagged(httpserver):
    # Regressione: un campo JSON legittimo chiamato "stack" (valore-array, nessun
    # frame reale) NON deve generare un finding.
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        '{"stack":["python","fastapi"]}', status=200, content_type="application/json"
    )

    assert _run(httpserver) == []


def test_real_json_stack_dump_is_flagged(httpserver):
    # Controprova: un vero dump con campo "stack" adiacente a un frame è segnalato.
    body = (
        '{"error":"boom","stack":"Error: boom\\n    at handler (/srv/app.js:10:5)"}'
    )
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        body, status=500, content_type="application/json"
    )

    findings = _run(httpserver)

    assert len(findings) == 1
    assert "stack" in findings[0].evidence.lower()


def test_er_constant_on_200_is_not_flagged(httpserver):
    # Regressione (catalogo): una normale costante applicativa 'ER_*' (es.
    # ER_MODEL) su una risposta 200 NON deve generare un finding. La firma del
    # codice errore MySQL ER_* è ora error-gated (vale SOLO su stato >= 400).
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        '{"type": "ER_MODEL", "data": {"name": "Order"}}',
        status=200,
        content_type="application/json",
    )

    assert _run(httpserver) == []


def test_er_mysql_error_on_error_status_is_flagged(httpserver):
    # Controprova: lo stesso ER_* su una risposta di ERRORE (500) è invece un
    # plausibile codice errore MySQL e viene segnalato.
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        '{"message": "ER_PARSE_ERROR: You have an error in your SQL"}',
        status=500,
        content_type="application/json",
    )

    findings = _run(httpserver)

    assert len(findings) == 1
    assert findings[0].severity == "media"


def test_off_allowlist_sends_no_request(httpserver):
    hits: list[str] = []

    def handler(request):
        hits.append(request.path)
        return Response("Traceback (most recent call last):", status=500)

    httpserver.expect_request("/probe", method="GET").respond_with_handler(handler)

    findings = _run(httpserver, allowed=["http://altro-host-non-consentito:9999"])

    assert findings == []
    assert hits == []


def test_finding_localized_english(httpserver):
    httpserver.expect_request("/probe", method="GET").respond_with_data(
        "Traceback (most recent call last):\n", status=500
    )

    findings = _run(httpserver, lang="en")

    assert len(findings) == 1
    assert "stack trace" in findings[0].title.lower()
