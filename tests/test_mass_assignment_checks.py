"""Test del tester di mass assignment (``gauntlet.mass_assignment_checks``).

Il *mass assignment* è il bug per cui un client riesce a impostare, via un
update non filtrato, un campo che non dovrebbe poter toccare (p.es.
``role``/``isAdmin``). L'oracolo qui è **deterministico** e in due tempi:
scrittura del campo vietato + ri-lettura della risorsa. Il finding nasce
**solo** quando la re-GET riflette il valore iniettato **e** quel valore
rappresenta un cambiamento reale rispetto allo stato iniziale: mai sul solo
status della scrittura.

Il modulo è **distruttivo** (scrive) e aggressivo-only: ogni scrittura passa
prima per :func:`gauntlet.safety.confirm_destructive`; senza via libera
esplicito non parte alcuna richiesta.

Si usa ``pytest-httpserver`` con un piccolo stato in memoria: un handler che
"accetta" il campo lo riflette nella GET successiva; uno che lo "ignora"
risponde ``2xx`` ma lascia la GET invariata.
"""

import json
import socket

from werkzeug.wrappers import Response

from gauntlet import mass_assignment_checks
from gauntlet.contract import (
    Account,
    Contract,
    LoginConfig,
    MassAssignmentProbe,
)


def _contract(allowed_targets: list[str], probes: list[MassAssignmentProbe]) -> Contract:
    """Contratto minimo: porta l'allowlist del gate e le sonde da eseguire."""
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
        accounts=[Account(label="a", username="a@x", password_env="A_PW")],
        mass_assignment=probes,
    )


def _stateful_handler(state: dict, *, reflect: bool, writes: list | None = None):
    """Handler con stato in memoria.

    GET restituisce lo stato corrente come JSON. Una scrittura (qualunque metodo
    non-GET) risponde ``2xx``; se ``reflect`` è ``True`` fonde il corpo nello
    stato (lo "accetta"), altrimenti lo lascia invariato (lo "ignora"). Ogni
    corpo di scrittura è registrato in ``writes`` (per verificare il ripristino).
    """

    def handler(request):
        if request.method == "GET":
            return Response(json.dumps(state), status=200, content_type="application/json")
        body = json.loads(request.data or b"{}")
        if writes is not None:
            writes.append(body)
        if reflect:
            state.update(body)
        return Response(json.dumps(state), status=200, content_type="application/json")

    return handler


def _closed_port() -> int:
    """Una porta TCP su ``127.0.0.1`` chiusa (bind effimero, poi rilasciato)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _probe(url_template: str, **kw) -> MassAssignmentProbe:
    return MassAssignmentProbe(
        url_template=url_template,
        id=kw.pop("id", "1"),
        forbidden_field=kw.pop("forbidden_field", "role"),
        forbidden_value=kw.pop("forbidden_value", "admin"),
        **kw,
    )


# --- oracolo write + re-GET ---------------------------------------------------


def test_accepted_field_is_flagged(httpserver):
    # L'update ACCETTA il campo vietato: la re-GET lo riflette => finding.
    # ``method`` è in minuscolo di proposito: il modulo deve maiuscolarlo.
    state: dict = {}
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True)
    )
    probe = _probe(httpserver.url_for("/api/users/{id}"), method="patch")
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert len(findings) == 1
    assert findings[0].source == "mass-assignment"
    assert findings[0].severity == "alta"
    assert findings[0].confidence == 1.0
    # Il metodo è stato maiuscolato: il server ha ricevuto una PATCH.
    assert any(req.method == "PATCH" for req, _resp in httpserver.log)


def test_ignored_field_is_not_flagged(httpserver):
    # L'update risponde 2xx ma NON scrive il campo: la re-GET resta invariata
    # => nessun finding (non si segnala mai sul solo status).
    state: dict = {}
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=False)
    )
    probe = _probe(httpserver.url_for("/api/users/{id}"))
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert findings == []


def test_already_equal_value_is_not_flagged(httpserver):
    # Se la GET iniziale ha GIÀ forbidden_value, la scrittura non prova nulla
    # (nessun cambiamento reale) => nessun finding.
    state = {"role": "admin"}
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True)
    )
    probe = _probe(httpserver.url_for("/api/users/{id}"))
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert findings == []


def test_consent_denied_sends_no_write(httpserver):
    # Consenso negato: nessuna scrittura (e nessuna richiesta) deve partire.
    state: dict = {}
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True)
    )
    probe = _probe(httpserver.url_for("/api/users/{id}"))
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: False,  # nega
    )

    assert findings == []
    # Nessuna scrittura inviata; prova sul log del server.
    assert all(req.method != "PATCH" for req, _resp in httpserver.log)
    assert len(httpserver.log) == 0


def test_offallowlist_url_sends_no_request(httpserver):
    # url_template assoluto sul server finto, ma allowlist su un'altra origine:
    # il gate fail-closed salta ogni richiesta.
    state: dict = {}
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True)
    )
    probe = _probe(httpserver.url_for("/api/users/{id}"))
    contract = _contract(["http://example.invalid:9999"], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert findings == []
    assert len(httpserver.log) == 0


def test_restore_writes_back_original_value(httpserver):
    # Finding confermato con ``original`` presente: dopo la sonda il server deve
    # ricevere una seconda scrittura col valore originale (ripristino best-effort).
    state = {"role": "user"}
    writes: list = []
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True, writes=writes)
    )
    probe = _probe(httpserver.url_for("/api/users/{id}"))
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert len(findings) == 1
    assert findings[0].severity == "alta"
    # Due scritture: la sonda (role=admin) e il ripristino (role=user).
    assert len(writes) == 2
    assert writes[0] == {"role": "admin"}
    assert writes[1] == {"role": "user"}


def test_boolean_sentinel_is_sent_typed_and_flagged(httpserver):
    # Sentinel booleano end-to-end: il corpo JSON deve contenere un booleano
    # VERO (``true``), non la stringa ``"True"``. Se il server lo accetta e la
    # re-GET lo riflette => finding (alta, 1.0).
    state: dict = {}
    writes: list = []
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True, writes=writes)
    )
    probe = _probe(
        httpserver.url_for("/api/users/{id}"),
        forbidden_field="isAdmin",
        forbidden_value=True,
    )
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert len(findings) == 1
    assert findings[0].severity == "alta"
    assert findings[0].confidence == 1.0
    # Il server ha ricevuto un booleano JSON, non una stringa.
    assert writes[0]["isAdmin"] is True
    assert isinstance(writes[0]["isAdmin"], bool)
    # Il testo del finding mostra il valore in grafia JSON, non Python.
    assert "true" in findings[0].description
    assert "True" not in findings[0].description
    assert "true" in findings[0].evidence
    assert "True" not in findings[0].evidence
    # ...senza apici attorno al valore: il corpo d'esempio resta JSON valido.
    assert "'true'" not in findings[0].evidence
    assert '{"isAdmin": true}' in findings[0].evidence


def test_json_spelling_renders_valid_json_tokens():
    # La grafia JSON è coerente: booleano/null/numero nudi, stringa fra doppi apici.
    spell = mass_assignment_checks._json_spelling
    assert spell(True) == "true"
    assert spell(False) == "false"
    assert spell(None) == "null"
    assert spell(1) == "1"
    assert spell("admin") == '"admin"'


def test_none_sentinel_never_confirms(httpserver):
    # Guard: forbidden_value=None => la re-GET riflette ``null`` e il campo è
    # trattato come assente. Senza il guard l'oracolo confermerebbe a vuoto
    # (str(None) == str(None)); col guard non deve nascere alcun finding.
    state: dict = {}
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True)
    )
    probe = _probe(
        httpserver.url_for("/api/users/{id}"),
        forbidden_field="isAdmin",
        forbidden_value=None,
    )
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert findings == []


def test_false_sentinel_present_is_flagged(httpserver):
    # Falsy ma presente: forbidden_value=False riflesso come ``false`` su un
    # campo prima assente => cambiamento reale => finding. Il guard
    # ``current is not None`` non deve scartare un falsy effettivamente presente.
    state: dict = {}
    writes: list = []
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True, writes=writes)
    )
    probe = _probe(
        httpserver.url_for("/api/users/{id}"),
        forbidden_field="isAdmin",
        forbidden_value=False,
    )
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert len(findings) == 1
    assert findings[0].severity == "alta"
    # Inviato come booleano JSON ``false``, non come stringa.
    assert writes[0]["isAdmin"] is False
    assert isinstance(writes[0]["isAdmin"], bool)


def test_transport_error_is_skipped():
    # Porta chiusa: errore di trasporto => sonda saltata senza sollevare.
    port = _closed_port()
    url_template = f"http://127.0.0.1:{port}/api/users/{{id}}"
    probe = _probe(url_template)
    contract = _contract([f"http://127.0.0.1:{port}"], [probe])

    findings = mass_assignment_checks.run(
        f"http://127.0.0.1:{port}/",
        contract,
        "localhost",
        confirm=lambda _desc: True,
    )

    assert findings == []


def test_finding_localized_in_english(httpserver):
    state: dict = {}
    httpserver.expect_request("/api/users/1").respond_with_handler(
        _stateful_handler(state, reflect=True)
    )
    probe = _probe(httpserver.url_for("/api/users/{id}"))
    contract = _contract([httpserver.url_for("/")], [probe])

    findings = mass_assignment_checks.run(
        httpserver.url_for("/"),
        contract,
        "localhost",
        confirm=lambda _desc: True,
        lang="en",
    )

    assert len(findings) == 1
    assert "mass assignment" in findings[0].title.lower()
    # Il nome del campo vietato compare nella descrizione inglese.
    assert "role" in findings[0].description
