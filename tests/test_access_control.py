"""Test del tester di controllo-accessi (``gauntlet.access_control``).

Questa è la prova del gioiello della corona: rilevare quando un cliente
(tenant) raggiunge i dati di un altro cliente. L'oracolo è *di proprietà* e
*deterministico*: un leak è confermato solo quando il tenant attaccante riceve
``2xx`` **e** nella risposta compare il marcatore noto del seed della vittima.
Status ``401/403/404`` e risposte prive del marcatore (lista vuota compresa)
sono classificati come "negato": nessun finding. Questo evita sia i falsi
positivi (flag su solo status) sia i falsi negativi (``200`` su pagina di login
anonima).

Si usa ``pytest-httpserver`` come server multi-tenant finto. L'identità del
chiamante è distinta dal token ``Authorization: Bearer`` della sua
:class:`Session`.
"""

import re

import pytest
from werkzeug.wrappers import Response

from gauntlet.access_control import _WRITE_PROBE_MARKER, OwnershipMap, run
from gauntlet.authn import Session
from gauntlet.contract import Account, Contract, LoginConfig, Resource

TOKEN_A = "token-cliente-a"
TOKEN_B = "token-cliente-b"


def _contract(allowed_targets: list[str], accounts: list[Account]) -> Contract:
    """Contratto minimo per i test: porta l'allowlist usata dal gate di ``run``.

    Le origini dei server finti vanno elencate in ``allowed_targets``, altrimenti
    il gate fail-closed salta (giustamente) il traffico legittimo del test.
    """
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
    """Due clienti diversi: A possiede ``/orders/1`` con marcatore ``SEED-A``."""
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
    """Qualunque path non esplicitamente gestito risponde 404.

    Serve a tenere pulito il test verticale: gli endpoint admin/Directus che il
    tester sonda non esistono su questo server finto e devono dare 404 (non il
    500 di default di un handler assente).
    """
    httpserver.expect_request(re.compile(r".*")).respond_with_data(
        "not found", status=404
    )


@pytest.fixture
def sa() -> Session:
    return _session("cliente_a", TOKEN_A)


@pytest.fixture
def sb() -> Session:
    return _session("cliente_b", TOKEN_B)


# --- i due test del brief ------------------------------------------------


def test_confirmed_cross_tenant_leak_flagged(httpserver, sa, sb):
    # A possiede /orders/1 con marcatore "SEED-A"; B riesce a leggerlo (bug).
    httpserver.expect_request("/orders/1", method="GET").respond_with_data(
        '{"id": 1, "owner": "tenant-a", "marker": "SEED-A"}',
        content_type="application/json",
    )
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert any(
        f.severity == "critica" and "orders/1" in f.description for f in findings
    )


def test_denied_access_not_flagged(httpserver, sa, sb):
    # B riceve 403 sulle risorse di A; A (proprietario) le legge regolarmente.
    def handler(request):
        if request.headers.get("Authorization") == f"Bearer {TOKEN_A}":
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

    assert findings == []


def test_confirmed_leak_localized_in_english(httpserver, sa, sb):
    # Con lang="en" il finding del leak confermato è reso in inglese.
    httpserver.expect_request("/orders/1", method="GET").respond_with_data(
        '{"id": 1, "owner": "tenant-a", "marker": "SEED-A"}',
        content_type="application/json",
    )
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
        lang="en",
    )

    leak = [f for f in findings if f.severity == "critica"]
    assert leak
    assert leak[0].title == "Confirmed cross-tenant access (IDOR/BOLA)"
    assert "read resource" in leak[0].description
    # Nessun residuo italiano nelle stringhe nostre.
    assert "tenant" in leak[0].description and "ha letto" not in leak[0].description


# --- rafforzamento dell'oracolo di proprietà -----------------------------


def test_2xx_without_marker_is_not_a_leak(httpserver, sa, sb):
    # B riceve 200 ma con una lista vuota: nessun dato di A => NON è un leak.
    # Dimostra che l'oracolo non si fida del solo status code.
    def handler(request):
        if request.headers.get("Authorization") == f"Bearer {TOKEN_A}":
            return Response(
                '{"id": 1, "marker": "SEED-A"}', status=200,
                content_type="application/json",
            )
        return Response("[]", status=200, content_type="application/json")

    httpserver.expect_request("/orders/1", method="GET").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert findings == []


def test_ownership_map_resolves_owner_and_other_tenants():
    accts = _accounts("http://x/orders/{id}")
    omap = OwnershipMap(accts)
    (owner_label, resource) = omap.entries[0]
    assert owner_label == "cliente_a"
    assert omap.other_labels("cliente_a") == ["cliente_b"]


def test_resource_without_marker_does_not_false_positive(httpserver, sa, sb):
    # Risorsa SENZA seed_marker e con id generico "1": B riceve 200 con un corpo
    # in cui "1" compare solo per caso (page=1). Non deve mai essere "critica";
    # deve invece comparire una nota info che chiede di dichiarare un seed_marker.
    httpserver.expect_request("/orders/1", method="GET").respond_with_data(
        '{"count": 10, "page": 1, "data": []}', content_type="application/json"
    )
    _register_catch_all_404(httpserver)
    accts = [
        Account(
            label="cliente_a",
            username="a@example.com",
            password_env="A_PW",
            tenant_id="tenant-a",
            seeded_resources=[
                Resource(
                    kind="order",
                    id="1",  # id generico: NON è un oracolo sicuro
                    url_template=httpserver.url_for("/orders/{id}"),
                    seed_marker=None,  # nessun marcatore dichiarato
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

    contract = _contract([httpserver.url_for("/")], accts)
    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert not any(f.severity == "critica" for f in findings)
    assert any(
        f.severity == "info" and "seed_marker" in f.description for f in findings
    )


# --- test verticale (escalation di privilegi) ----------------------------


def test_resource_without_marker_reflected_id_is_not_a_leak(httpserver, sa, sb):
    # GAP 1 (regressione): risorsa SENZA seed_marker, id distintivo
    # "invoice-2024" (che il VECCHIO ripiego-id avrebbe usato come marcatore:
    # len>=8, non tutto cifre). B riceve 2xx con un corpo che riflette l'id
    # richiesto ({"error":"invoice-2024 not found"} — soft-404/envelope): col
    # vecchio oracolo sarebbe stata una falsa 'critica'. Ora l'id NON è più
    # oracolo => nessuna critica, solo la nota info che chiede un seed_marker.
    httpserver.expect_request(
        "/invoices/invoice-2024", method="GET"
    ).respond_with_data(
        '{"error": "invoice-2024 not found"}',
        status=200,
        content_type="application/json",
    )
    _register_catch_all_404(httpserver)
    accts = [
        Account(
            label="cliente_a",
            username="a@example.com",
            password_env="A_PW",
            tenant_id="tenant-a",
            seeded_resources=[
                Resource(
                    kind="invoice",
                    id="invoice-2024",  # distintivo: ex-ripiego sicuro, ora ignorato
                    url_template=httpserver.url_for("/invoices/{id}"),
                    seed_marker=None,  # nessun marcatore esplicito
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
    contract = _contract([httpserver.url_for("/")], accts)
    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert not any(f.severity == "critica" for f in findings)
    assert any(
        f.severity == "info" and "seed_marker" in f.description for f in findings
    )


def test_vertical_admin_endpoint_reachable_is_flagged(httpserver, sa, sb):
    # L'endpoint risorsa esiste (per derivare l'origine) e un endpoint admin
    # Directus noto risponde 200 a un utente normale => escalation verticale.
    httpserver.expect_request("/orders/1", method="GET").respond_with_data(
        '{"id": 1, "marker": "SEED-A"}', content_type="application/json"
    )
    httpserver.expect_request("/server/info", method="GET").respond_with_json(
        {"project": {"project_name": "acme"}}
    )
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert any(
        f.source == "access-control" and "/server/info" in f.description
        for f in findings
    )
    # Nessun endpoint admin raggiungibile non deve mai essere "critica":
    # la critica è riservata al leak cross-tenant confermato.
    assert all(
        f.severity != "critica"
        for f in findings
        if "/server/info" in f.description
    )


def test_vertical_probe_uses_contract_admin_endpoints(httpserver, sa, sb):
    # Il contratto dichiara un endpoint admin specifico del progetto
    # (/api/segreto) che non è nella lista generica: il probe verticale deve
    # sondarlo (unione con ADMIN_ENDPOINTS) e, se risponde 2xx, segnalarlo.
    httpserver.expect_request("/orders/1", method="GET").respond_with_data(
        '{"id": 1, "marker": "SEED-A"}', content_type="application/json"
    )
    httpserver.expect_request("/api/segreto", method="GET").respond_with_json(
        {"secret": "esposto"}
    )
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)
    contract.admin_endpoints = ["/api/segreto"]

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert any(
        f.source == "access-control" and "/api/segreto" in f.description
        for f in findings
    )


# --- modalità write: gate di conferma distruttiva ------------------------


def test_write_mode_skips_when_not_confirmed(httpserver, sa, sb):
    # In write senza conferma, i tentativi di modifica sono saltati (non sollevano)
    # e la lettura cross-tenant resta negata (403) => nessun finding.
    def handler(request):
        if request.headers.get("Authorization") == f"Bearer {TOKEN_A}":
            return Response("{}", status=200, content_type="application/json")
        return Response("forbidden", status=403)

    httpserver.expect_request("/orders/1").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
        mode="write",
        confirm=lambda _desc: False,  # mai confermato
    )

    assert findings == []


def test_write_confirmed_leak_is_critica(httpserver, sa, sb):
    # PATCH di B su /orders/1 (di A) risponde 2xx E la re-GET come proprietario
    # mostra il marcatore della sonda: la scrittura ha mutato i dati della
    # vittima => finding 'critica' confermato. La lettura resta negata (403 su
    # GET di B) per isolare il percorso di scrittura.
    def handler(request):
        auth = request.headers.get("Authorization")
        if request.method == "PATCH" and auth == f"Bearer {TOKEN_B}":
            return Response("{}", status=200, content_type="application/json")
        if request.method == "GET" and auth == f"Bearer {TOKEN_A}":
            # Il proprietario rilegge e trova il marcatore della sonda scritto.
            return Response(
                '{"id": 1, "gauntlet_probe": "%s"}' % _WRITE_PROBE_MARKER,
                status=200,
                content_type="application/json",
            )
        return Response("forbidden", status=403)

    httpserver.expect_request("/orders/1").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
        mode="write",
        confirm=lambda _desc: True,
    )

    write = [f for f in findings if "scrittura" in f.title.lower()]
    assert len(write) == 1
    assert write[0].severity == "critica"
    assert write[0].confidence == 1.0


def test_write_2xx_without_confirmation_is_alta_not_critica(httpserver, sa, sb):
    # PATCH di B risponde 2xx ma la re-GET come proprietario NON mostra il
    # marcatore della sonda: la mutazione non è confermata => NON 'critica' ma
    # 'alta' NON CONFERMATA. Nessuna critica sul solo status code.
    def handler(request):
        auth = request.headers.get("Authorization")
        if request.method == "PATCH" and auth == f"Bearer {TOKEN_B}":
            return Response("{}", status=200, content_type="application/json")
        if request.method == "GET" and auth == f"Bearer {TOKEN_A}":
            # Proprietario rilegge: nessun marcatore => scrittura non confermata.
            return Response(
                '{"id": 1}', status=200, content_type="application/json"
            )
        return Response("forbidden", status=403)

    httpserver.expect_request("/orders/1").respond_with_handler(handler)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
        mode="write",
        confirm=lambda _desc: True,
    )

    write = [f for f in findings if "scrittura" in f.title.lower()]
    assert len(write) == 1
    assert write[0].severity == "alta"
    assert write[0].severity != "critica"
    assert "NON CONFERMATA" in write[0].title


# --- gate allowlist fail-closed ------------------------------------------


def test_offallowlist_url_template_is_refused_no_request_sent(httpserver, sa, sb):
    # url_template ASSOLUTO che punta al server finto, ma l'allowlist del
    # contratto contiene una origine DIVERSA: il gate fail-closed deve saltare
    # OGNI richiesta (orizzontale e verticale) => nessun finding e, soprattutto,
    # il server finto non riceve NESSUNA richiesta.
    def handler(request):
        # Se mai raggiunto, restituirebbe un leak confermato (bug nel gate).
        return Response(
            '{"id": 1, "marker": "SEED-A"}',
            status=200,
            content_type="application/json",
        )

    httpserver.expect_request(re.compile(r".*")).respond_with_handler(handler)
    accts = _accounts(httpserver.url_for("/orders/{id}"))
    # Allowlist volutamente NON contenente l'origine del server finto.
    contract = _contract(["http://example.invalid:9999"], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert findings == []
    # Prova che nessun traffico è partito verso l'host non in allowlist.
    assert len(httpserver.log) == 0


# --- host-side mapping per reachability == "docker" (Task 4b) -------------
#
# In docker mode gli URL del contratto possono usare host.docker.internal (serve
# a ZAP nel container), ma le richieste httpx host-side vanno rimappate su
# 127.0.0.1. Il gate allowlist resta sull'origine ORIGINALE: nessun bypass.


def _docker_contract(allowed_targets, accounts):
    import dataclasses

    return dataclasses.replace(
        _contract(allowed_targets, accounts), reachability="docker"
    )


def test_docker_leak_uses_mapped_host_for_request(httpserver, sa, sb):
    # Server su 127.0.0.1:PORT; risorse e allowlist su host.docker.internal:PORT.
    # In docker mode la GET di B deve raggiungere il server (mappata su loopback)
    # e il leak confermato dal marcatore.
    httpserver.expect_request("/orders/1", method="GET").respond_with_data(
        '{"id": 1, "owner": "tenant-a", "marker": "SEED-A"}',
        content_type="application/json",
    )
    _register_catch_all_404(httpserver)
    port = httpserver.port
    tmpl = f"http://host.docker.internal:{port}/orders/{{id}}"
    accts = _accounts(tmpl)
    contract = _docker_contract([f"http://host.docker.internal:{port}/"], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert any(
        f.severity == "critica" and "orders/1" in f.description for f in findings
    )


def test_docker_off_allowlist_host_is_still_refused(httpserver, sa, sb):
    # Invariante di sicurezza: una risorsa su host.docker.internal:PORT NON in
    # allowlist resta rifiutata anche in docker mode; nessuna richiesta parte.
    httpserver.expect_request("/orders/1", method="GET").respond_with_data(
        '{"id": 1, "owner": "tenant-a", "marker": "SEED-A"}',
        content_type="application/json",
    )
    _register_catch_all_404(httpserver)
    port = httpserver.port
    tmpl = f"http://host.docker.internal:{port}/orders/{{id}}"
    accts = _accounts(tmpl)
    # Allowlist che NON copre host.docker.internal:PORT.
    contract = _docker_contract(["http://localhost:1"], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert findings == []
    assert not httpserver.log


# --- E2: fuzzing IDOR su ID sequenziali ----------------------------------
#
# Oltre alla risorsa esatta seminata, si sondano gli ID vicini (id±N) con la
# sessione del PROPRIETARIO, per scoprire IDOR dove gli oggetti sono numerati.
# Nessun falso positivo: un finding 'critica' richiede 2xx E un oracolo di
# proprietà (owner_field) nel corpo il cui valore è di un ALTRO proprietario
# (diverso dallo username dell'account che sta sondando). Status da solo, o
# owner_field assente/uguale, non segnalano mai.


def _enum_accounts(url_template: str):
    """Account A (a@x) possiede /api/orders/10 con enumerate attivo su owner."""
    return [
        Account(
            label="cliente_a",
            username="a@x",
            password_env="A_PW",
            tenant_id="tenant-a",
            seeded_resources=[
                Resource(
                    kind="order",
                    id="10",
                    url_template=url_template,
                    seed_marker="SEED-A",
                    enumerate=True,
                    owner_field="owner",
                    enumerate_count=3,
                )
            ],
        ),
        Account(
            label="cliente_b",
            username="b@x",
            password_env="B_PW",
            tenant_id="tenant-b",
            seeded_resources=[],
        ),
    ]


def _owner_gated_seed(httpserver, path: str) -> None:
    """La risorsa esatta seminata risponde SEED-A solo al proprietario (TOKEN_A).

    Così il test orizzontale cross-tenant sulla risorsa esatta resta "negato" e
    non introduce una 'critica' spuria: l'unica 'critica' attesa è quella del
    fuzzing IDOR sui vicini.
    """

    def handler(request):
        if request.headers.get("Authorization") == f"Bearer {TOKEN_A}":
            return Response(
                '{"id": 10, "owner": "a@x", "marker": "SEED-A"}',
                status=200,
                content_type="application/json",
            )
        return Response("forbidden", status=403)

    httpserver.expect_request(path, method="GET").respond_with_handler(handler)


def test_sequential_idor_confirmed_is_critica(httpserver, sa, sb):
    # A possiede /api/orders/10; il vicino /api/orders/11 risponde 2xx con
    # owner "b@x" (di un ALTRO cliente) letto dalla sessione di A => IDOR
    # sequenziale confermato dall'oracolo di proprietà.
    _owner_gated_seed(httpserver, "/api/orders/10")
    httpserver.expect_request("/api/orders/11", method="GET").respond_with_json(
        {"id": 11, "owner": "b@x", "secret": "dati-di-b"}
    )
    _register_catch_all_404(httpserver)
    accts = _enum_accounts(httpserver.url_for("/api/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    seq = [
        f
        for f in findings
        if f.severity == "critica" and "orders/11" in f.description
    ]
    assert len(seq) == 1
    assert "b@x" in seq[0].evidence or "b@x" in seq[0].description


def test_sequential_idor_localized_in_english(httpserver, sa, sb):
    _owner_gated_seed(httpserver, "/api/orders/10")
    httpserver.expect_request("/api/orders/11", method="GET").respond_with_json(
        {"id": 11, "owner": "b@x"}
    )
    _register_catch_all_404(httpserver)
    accts = _enum_accounts(httpserver.url_for("/api/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
        lang="en",
    )

    seq = [
        f for f in findings if f.severity == "critica" and "orders/11" in f.description
    ]
    assert seq
    # Frase italiana assente...
    assert "ha letto" not in seq[0].description
    # ...e un token inglese stabile presente (non solo l'assenza dell'italiano).
    assert "probing IDs neighboring" in seq[0].description


def test_sequential_idor_same_owner_no_finding(httpserver, sa, sb):
    # Il vicino risponde 2xx ma con owner == l'account che sonda (a@x): è un
    # oggetto proprio, non un leak => nessun finding.
    _owner_gated_seed(httpserver, "/api/orders/10")
    httpserver.expect_request("/api/orders/11", method="GET").respond_with_json(
        {"id": 11, "owner": "a@x"}
    )
    httpserver.expect_request("/api/orders/12", method="GET").respond_with_json(
        {"id": 12, "owner": "a@x"}
    )
    httpserver.expect_request("/api/orders/13", method="GET").respond_with_json(
        {"id": 13, "owner": "a@x"}
    )
    for i in (7, 8, 9):
        httpserver.expect_request(
            "/api/orders/%d" % i, method="GET"
        ).respond_with_json({"id": i, "owner": "a@x"})
    _register_catch_all_404(httpserver)
    accts = _enum_accounts(httpserver.url_for("/api/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert not any(f.severity == "critica" for f in findings)


def test_sequential_idor_no_oracle_no_finding(httpserver, sa, sb):
    # I vicini rispondono 2xx ma senza owner_field (e uno non-JSON) => nessun
    # oracolo di proprietà => nessun finding, nessun crash.
    _owner_gated_seed(httpserver, "/api/orders/10")
    httpserver.expect_request("/api/orders/11", method="GET").respond_with_json(
        {"id": 11, "total": 42}
    )
    httpserver.expect_request("/api/orders/12", method="GET").respond_with_data(
        "<html>pagina non-json</html>", content_type="text/html"
    )
    for i in (7, 8, 9, 13):
        httpserver.expect_request(
            "/api/orders/%d" % i, method="GET"
        ).respond_with_json({"id": i, "total": 1})
    _register_catch_all_404(httpserver)
    accts = _enum_accounts(httpserver.url_for("/api/orders/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert not any(f.severity == "critica" for f in findings)


def test_sequential_idor_disabled_by_default(httpserver, sa, sb):
    # enumerate non dichiarato (default False): nessun vicino viene sondato.
    # Se un vicino venisse richiesto risponderebbe con un owner diverso (sarebbe
    # un falso 'critica'); non deve accadere.
    httpserver.expect_request("/orders/1", method="GET").respond_with_json(
        {"id": 1, "owner": "a@x", "marker": "SEED-A"}
    )

    def boom(request):
        return Response(
            '{"owner": "b@x"}', status=200, content_type="application/json"
        )

    httpserver.expect_request(
        re.compile(r"/orders/\d+"), method="GET"
    ).respond_with_handler(boom)
    _register_catch_all_404(httpserver)
    accts = _accounts(httpserver.url_for("/orders/{id}"))  # enumerate default False
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    # Solo la risorsa esatta /orders/1 è stata interrogata (dal test orizzontale);
    # nessun vicino sequenziale => nessun finding derivante da /orders/2, /orders/0...
    assert all("orders/2" not in f.description for f in findings)
    assert all("orders/0" not in f.description for f in findings)


def test_sequential_idor_non_numeric_id_no_probe(httpserver, sa, sb):
    # id non numerico (UUID-like) con enumerate=True: non si può enumerare =>
    # nessun probe dei vicini, nessun crash, nessun finding sequenziale.
    uid = "abc-123-def-456"
    httpserver.expect_request("/api/orders/%s" % uid, method="GET").respond_with_json(
        {"id": uid, "owner": "a@x"}
    )
    _register_catch_all_404(httpserver)
    accts = [
        Account(
            label="cliente_a",
            username="a@x",
            password_env="A_PW",
            tenant_id="tenant-a",
            seeded_resources=[
                Resource(
                    kind="order",
                    id=uid,
                    url_template=httpserver.url_for("/api/orders/{id}"),
                    seed_marker="SEED-A",
                    enumerate=True,
                    owner_field="owner",
                )
            ],
        ),
        Account(
            label="cliente_b",
            username="b@x",
            password_env="B_PW",
            seeded_resources=[],
        ),
    ]
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert not any(f.severity == "critica" for f in findings)


def test_sequential_idor_unicode_digit_id_no_crash(httpserver, sa, sb):
    # id con una "cifra" Unicode non decimale (apice '²'): str.isdigit() la
    # accetterebbe ma int() solleverebbe ValueError. Il guard usa isdecimal(),
    # quindi niente probe dei vicini, nessun crash, nessun finding sequenziale.
    uid = "²"  # SUPERSCRIPT TWO: isdigit() True, isdecimal() False
    assert uid.isdigit() and not uid.isdecimal()
    httpserver.expect_request("/api/orders/%s" % uid, method="GET").respond_with_json(
        {"id": uid, "owner": "a@x"}
    )
    _register_catch_all_404(httpserver)
    accts = [
        Account(
            label="cliente_a",
            username="a@x",
            password_env="A_PW",
            tenant_id="tenant-a",
            seeded_resources=[
                Resource(
                    kind="order",
                    id=uid,
                    url_template=httpserver.url_for("/api/orders/{id}"),
                    seed_marker="SEED-A",
                    enumerate=True,
                    owner_field="owner",
                )
            ],
        ),
        Account(
            label="cliente_b",
            username="b@x",
            password_env="B_PW",
            seeded_resources=[],
        ),
    ]
    contract = _contract([httpserver.url_for("/")], accts)

    # Non deve sollevare (nessun int('²')) e non deve produrre un finding
    # sequenziale sui vicini.
    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert not any(f.source == "access-control" and "IDOR" in f.title for f in findings)


def _userid_accounts(url_template: str, *, enumerate_count: int = 1):
    """Account A (email a@example.com) possiede /api/items/50 con enumerate su un
    ``owner_field`` numerico ``user_id`` — namespace DIVERSO dallo username.
    """
    return [
        Account(
            label="cliente_a",
            username="a@example.com",  # email: diverso dal user_id numerico
            password_env="A_PW",
            tenant_id="tenant-a",
            seeded_resources=[
                Resource(
                    kind="item",
                    id="50",
                    url_template=url_template,
                    seed_marker="SEED-A",
                    enumerate=True,
                    owner_field="user_id",
                    enumerate_count=enumerate_count,
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


def test_sequential_idor_compares_self_owner_not_username(httpserver, sa, sb):
    # GAP 2 (regressione): owner_field="user_id" numerico, username è un'email.
    # La PROPRIA risorsa /api/items/50 espone user_id "42" => self_owner="42".
    # Il vicino 51 ha user_id "42" (oggetto proprio adiacente) => NESSUN finding
    # (col vecchio confronto con lo username "a@example.com" sarebbe stato un
    # falso 'critica'). Il vicino 49 ha user_id "99" (altro proprietario) =>
    # CRITICA.
    def own(request):
        if request.headers.get("Authorization") == f"Bearer {TOKEN_A}":
            return Response(
                '{"id": 50, "user_id": "42", "marker": "SEED-A"}',
                status=200,
                content_type="application/json",
            )
        return Response("forbidden", status=403)

    httpserver.expect_request("/api/items/50", method="GET").respond_with_handler(own)
    httpserver.expect_request("/api/items/49", method="GET").respond_with_json(
        {"id": 49, "user_id": "99"}
    )
    httpserver.expect_request("/api/items/51", method="GET").respond_with_json(
        {"id": 51, "user_id": "42"}
    )
    _register_catch_all_404(httpserver)
    accts = _userid_accounts(httpserver.url_for("/api/items/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    crit = [f for f in findings if f.severity == "critica"]
    assert len(crit) == 1
    assert "items/49" in crit[0].description
    # L'oggetto proprio adiacente (stesso user_id "42") non è mai segnalato.
    assert all("items/51" not in f.description for f in findings)


def test_sequential_idor_self_owner_undeterminable_skips(httpserver, sa, sb):
    # GAP 2 (regressione): la risorsa PROPRIA non espone owner_field =>
    # self_owner non determinabile => test sequenziale SALTATO, nessun finding
    # sui vicini anche se un vicino rivelerebbe un altro proprietario.
    def own(request):
        if request.headers.get("Authorization") == f"Bearer {TOKEN_A}":
            return Response(
                '{"id": 50, "marker": "SEED-A"}',  # nessun user_id
                status=200,
                content_type="application/json",
            )
        return Response("forbidden", status=403)

    httpserver.expect_request("/api/items/50", method="GET").respond_with_handler(own)

    def leak(request):
        return Response(
            '{"user_id": "99"}', status=200, content_type="application/json"
        )

    httpserver.expect_request(
        re.compile(r"/api/items/\d+"), method="GET"
    ).respond_with_handler(leak)
    _register_catch_all_404(httpserver)
    accts = _userid_accounts(httpserver.url_for("/api/items/{id}"))
    contract = _contract([httpserver.url_for("/")], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert not any(f.severity == "critica" for f in findings)


def test_sequential_idor_offallowlist_neighbor_not_requested(httpserver, sa, sb):
    # url_template assoluto sul server finto, ma allowlist su un'origine diversa:
    # il gate fail-closed salta ogni richiesta, vicini compresi => nessun finding
    # e nessun traffico verso il server finto.
    def leaker(request):
        return Response(
            '{"owner": "b@x"}', status=200, content_type="application/json"
        )

    httpserver.expect_request(re.compile(r".*")).respond_with_handler(leaker)
    accts = _enum_accounts(httpserver.url_for("/api/orders/{id}"))
    contract = _contract(["http://example.invalid:9999"], accts)

    findings = run(
        sessions={"cliente_a": sa, "cliente_b": sb},
        accounts=accts,
        contract=contract,
    )

    assert findings == []
    assert len(httpserver.log) == 0
