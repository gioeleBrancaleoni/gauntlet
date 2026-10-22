"""Test del controllo di autenticazione mancante/rotta (``gauntlet.access_control``).

Complemento del test cross-tenant: una risorsa protetta risponde a una richiesta
ANONIMA (nessun token, nessun cookie)? L'oracolo è lo stesso del resto del
modulo e resta **deterministico**: un finding ``critica`` nasce solo quando la
GET anonima riceve ``2xx`` **e** nel corpo compare il marcatore noto del seed
della risorsa. Status da solo (401/403) o marcatore assente => nessun finding.

Si usa ``pytest-httpserver`` come server finto: l'identità (o la sua assenza) è
distinta dalla presenza dell'header ``Authorization``.
"""

import re

import pytest
from werkzeug.wrappers import Response

from gauntlet.access_control import run
from gauntlet.authn import Session
from gauntlet.contract import Account, Contract, LoginConfig, Resource

TOKEN_A = "token-cliente-a"
TOKEN_B = "token-cliente-b"

# Titolo del finding di autenticazione mancante (distinto da quello cross-tenant).
_NOAUTH_TITLE_IT = "Risorsa accessibile senza autenticazione"


def _contract(allowed_targets: list[str], accounts: list[Account]) -> Contract:
    return Contract(
        name="test",
        allowed_targets=allowed_targets,
        reachability="localhost",
        login=LoginConfig(
            method="json",
            login_url="http://localhost/login",
            username_field="email",
            password_field="password",
            logged_in_indicator='"token"',
            token_path="token",
        ),
        accounts=accounts,
    )


def _session(label: str, token: str) -> Session:
    return Session(cookies={}, headers={"Authorization": f"Bearer {token}"}, label=label)


def _accounts(order_url_template: str) -> list[Account]:
    return [
        Account(
            label="cliente_a",
            username="a@example.com",
            password_env="A_PW",
            tenant_id="tenant-a",
            seeded_resources=[
                Resource(
                    kind="order",
                    id="1",
                    url_template=order_url_template,
                    seed_marker="SEED-A",
                )
            ],
        ),
        Account(
            label="cliente_b",
            username="b@example.com",
            password_env="B_PW",
            tenant_id="tenant-b",
            seeded_resources=[],
        ),
    ]


def _register_catch_all_404(httpserver) -> None:
    httpserver.expect_request(re.compile(r".*")).respond_with_data(
        "not found", status=404
    )


@pytest.fixture
def sa() -> Session:
    return _session("cliente_a", TOKEN_A)


@pytest.fixture
def sb() -> Session:
    return _session("cliente_b", TOKEN_B)


def _noauth(findings):
    return [f for f in findings if f.title == _NOAUTH_TITLE_IT]


def test_anonymous_marker_served_is_critica(httpserver, sa, sb):
    # La risorsa protetta serve il marcatore a chi NON presenta Authorization:
    # autenticazione mancante confermata dall'oracolo => 'critica'. I titolari
    # (con Bearer) ricevono 403, così il test cross-tenant non introduce rumore.
    def handler(request):
        if request.headers.get("Authorization") is None:
            return Response(
                '{"id": 1, "owner": "tenant-a", "marker": "SEED-A"}',
                status=200,
                content_type="application/json",
            )
        return Response("forbidden", status=403)

    httpserver.expect_request("/orders/1", method="GET").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    noauth = _noauth(findings)
    assert len(noauth) == 1
    assert noauth[0].severity == "critica"
    assert noauth[0].source == "access-control"
    assert noauth[0].confidence == 1.0
    assert "orders/1" in noauth[0].url


def test_anonymous_401_is_not_a_finding(httpserver, sa, sb):
    # La risorsa nega l'accesso anonimo (401): nessun finding di auth mancante.
    def handler(request):
        if request.headers.get("Authorization") is None:
            return Response("unauthorized", status=401)
        return Response(
            '{"id": 1, "marker": "SEED-A"}', status=200,
            content_type="application/json",
        )

    httpserver.expect_request("/orders/1", method="GET").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert _noauth(findings) == []


def test_anonymous_2xx_without_marker_is_not_a_finding(httpserver, sa, sb):
    # La GET anonima riceve 200 ma con un corpo privo del marcatore (pagina/di
    # errore generica, lista vuota): l'oracolo non si fida del solo status =>
    # nessun finding di auth mancante.
    def handler(request):
        if request.headers.get("Authorization") is None:
            return Response("[]", status=200, content_type="application/json")
        return Response(
            '{"id": 1, "marker": "SEED-A"}', status=200,
            content_type="application/json",
        )

    httpserver.expect_request("/orders/1", method="GET").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert _noauth(findings) == []


def test_anonymous_request_carries_no_auth_and_no_cookies(httpserver, sa, sb):
    # Prova che la sonda anonima non inoltra NÉ Authorization NÉ cookie.
    seen: dict = {}

    def handler(request):
        if request.headers.get("Authorization") is None:
            seen["auth"] = request.headers.get("Authorization")
            seen["cookie"] = request.headers.get("Cookie")
            return Response(
                '{"marker": "SEED-A"}', status=200, content_type="application/json"
            )
        return Response("forbidden", status=403)

    httpserver.expect_request("/orders/1", method="GET").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    run(sessions={"cliente_a": sa, "cliente_b": sb}, accounts=accts, contract=contract)

    assert seen.get("auth") is None
    assert seen.get("cookie") is None


def test_anonymous_localized_in_english(httpserver, sa, sb):
    def handler(request):
        if request.headers.get("Authorization") is None:
            return Response(
                '{"marker": "SEED-A"}', status=200, content_type="application/json"
            )
        return Response("forbidden", status=403)

    httpserver.expect_request("/orders/1", method="GET").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
        lang="en",
    )

    en = [f for f in findings if f.title == "Resource accessible without authentication"]
    assert len(en) == 1
    assert en[0].severity == "critica"


def test_anonymous_offallowlist_url_sends_no_request(httpserver, sa, sb):
    # url_template assoluto sul server finto ma allowlist su un'altra origine:
    # il gate fail-closed salta la sonda anonima => nessun finding, nessun traffico.
    def leaker(request):
        return Response(
            '{"marker": "SEED-A"}', status=200, content_type="application/json"
        )

    httpserver.expect_request(re.compile(r".*")).respond_with_handler(leaker)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract(["http://example.invalid:9999"], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert _noauth(findings) == []
    assert len(httpserver.log) == 0
