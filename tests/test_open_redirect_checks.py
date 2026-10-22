"""Test del controllo open redirect (``gauntlet.open_redirect_checks``).

L'oracolo è **deterministico**: un finding scatta solo quando l'endpoint
risponde con un redirect (``3xx``) e un header ``Location`` che punta
all'origine del canary estraneo (:data:`gauntlet.open_redirect_checks.PROBE_DESTINATION`).
Un redirect verso l'host stesso, un path relativo o lo stato senza redirect
non producono alcun finding (zero falsi positivi).

Si usa ``pytest-httpserver`` per restituire header ``Location`` controllati.
"""

import re

from gauntlet import open_redirect_checks
from gauntlet.contract import Account, Contract, LoginConfig

PROBE = open_redirect_checks.PROBE_DESTINATION


def _contract(
    allowed_targets: list[str], login_url: str, redirect_probes: list[str]
) -> Contract:
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
        redirect_probes=redirect_probes,
    )


def _run(
    httpserver,
    *,
    status=302,
    location=None,
    probes=None,
    allowed=None,
    body="",
):
    """Registra un handler catch-all e lancia il controllo open redirect."""
    headers = {"Location": location} if location is not None else {}
    httpserver.expect_request(re.compile(r".*")).respond_with_data(
        body, status=status, headers=headers
    )
    base = httpserver.url_for("/").rstrip("/")
    allowed_targets = allowed if allowed is not None else [base]
    probes = probes if probes is not None else ["/go?next={payload}"]
    contract = _contract(allowed_targets, f"{base}/login", probes)
    return open_redirect_checks.run(base, contract, "localhost")


def test_redirect_to_canary_is_finding(httpserver):
    findings = _run(httpserver, status=302, location=PROBE)
    assert len(findings) == 1
    assert findings[0].source == "open-redirect"
    assert findings[0].severity == "alta"
    assert findings[0].confidence == 1.0


def test_protocol_relative_location_is_finding(httpserver):
    # Location protocol-relative //canary/x: urlsplit dà netloc == canary.
    findings = _run(httpserver, status=302, location="//gauntlet-redirect-probe.example/x")
    assert len(findings) == 1
    assert findings[0].source == "open-redirect"
    assert findings[0].severity == "alta"


def test_relative_location_same_host_is_no_finding(httpserver):
    # Location relativo (stesso host, netloc vuoto): nessun redirect off-origin.
    findings = _run(httpserver, status=302, location="/landing")
    assert findings == []


def test_redirect_to_different_origin_is_no_finding(httpserver):
    # Redirect verso un'origine diversa dal canary: non è l'oracolo.
    findings = _run(httpserver, status=302, location="https://other.example/landing")
    assert findings == []


def test_no_redirect_status_is_no_finding(httpserver):
    # 200 senza redirect: nessun finding anche se un Location fosse presente.
    findings = _run(httpserver, status=200, location=PROBE)
    assert findings == []


def test_empty_redirect_probes_makes_no_request(httpserver):
    httpserver.expect_request(re.compile(r".*")).respond_with_data(
        "", status=302, headers={"Location": PROBE}
    )
    base = httpserver.url_for("/").rstrip("/")
    contract = _contract([base], f"{base}/login", redirect_probes=[])

    findings = open_redirect_checks.run(base, contract, "localhost")

    assert findings == []
    assert len(httpserver.log) == 0


def test_offallowlist_probe_sends_no_request(httpserver):
    # base_url punta al server finto, ma l'allowlist è un'altra origine: il gate
    # fail-closed salta ogni probe => nessun traffico e nessun finding.
    httpserver.expect_request(re.compile(r".*")).respond_with_data(
        "", status=302, headers={"Location": PROBE}
    )
    base = httpserver.url_for("/").rstrip("/")
    contract = _contract(
        ["http://example.invalid:9999"],
        "http://example.invalid:9999/login",
        redirect_probes=["/go?next={payload}"],
    )

    findings = open_redirect_checks.run(base, contract, "localhost")

    assert findings == []
    assert len(httpserver.log) == 0


def test_localized_in_english(httpserver):
    httpserver.expect_request(re.compile(r".*")).respond_with_data(
        "", status=302, headers={"Location": PROBE}
    )
    base = httpserver.url_for("/").rstrip("/")
    contract = _contract([base], f"{base}/login", ["/go?next={payload}"])

    findings = open_redirect_checks.run(base, contract, "localhost", lang="en")
    assert len(findings) == 1
    assert "redirect" in findings[0].title.lower()


def test_transport_error_is_skipped():
    # Nessun server in ascolto: l'errore di trasporto non deve sollevare.
    base = "http://127.0.0.1:9"  # porta discard, connessione rifiutata
    contract = _contract([base], f"{base}/login", ["/go?next={payload}"])

    findings = open_redirect_checks.run(base, contract, "localhost")
    assert findings == []


def test_lookalike_host_is_no_finding(httpserver):
    # Host che SEMBRA il canary ma non lo è: l'oracolo usa uguaglianza esatta
    # sul netloc, quindi nessun finding (zero falsi positivi).
    findings = _run(
        httpserver,
        status=302,
        location="https://gauntlet-redirect-probe.example.evil.example/x",
    )
    assert findings == []


def test_http_scheme_canary_is_finding(httpserver):
    # L'oracolo è indipendente dallo schema: anche http:// verso il canary.
    findings = _run(
        httpserver,
        status=302,
        location="http://gauntlet-redirect-probe.example/landing",
    )
    assert len(findings) == 1
    assert findings[0].source == "open-redirect"
