"""Test dell'ingresso CLI (``gauntlet.cli``): il cablaggio end-to-end.

Questo è il test di *orchestrazione*: tutti i sottosistemi (preflight, runner
ZAP, autenticazione, controllo-accessi, discovery) sono mockati, così da
verificare solo che :func:`gauntlet.cli.run` li cabli nell'ordine giusto secondo
il livello e che scriva davvero un ``report.md`` nel progetto. Nessun Docker,
nessuna rete.

Il confine di mock è deliberatamente ai nomi importati in ``gauntlet.cli``:
``preflight.run``, ``ZapRunner``, ``login``, ``build_zap_context``,
``access_control.run`` e ``discover``. Patchandoli lì si intercetta esattamente
ciò che la CLI invoca, senza toccare l'implementazione reale dei moduli.
"""

import socket
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

from gauntlet import cli
from gauntlet.discovery import Endpoint
from gauntlet.models import Finding
from gauntlet.preflight import PreflightResult
from gauntlet.safety import TargetNotAllowed

# Contratto minimo valido: due account di clienti diversi, un solo target.
_CONTRACT_YAML = """\
name: progetto-di-prova
allowed_targets:
  - http://localhost:8081
reachability: localhost

login:
  method: json
  login_url: http://localhost:8081/api/auth/login
  username_field: email
  password_field: password
  logged_in_indicator: '"token"'
  token_path: data.token

accounts:
  - label: cliente_a
    username: a@example.com
    password_env: GAUNTLET_TEST_A_PW
    tenant_id: tenant-a
    seeded_resources:
      - kind: invoice
        id: inv-a-0001
        url_template: /api/invoices/{id}
        seed_marker: SEED-A-0001
  - label: cliente_b
    username: b@example.com
    password_env: GAUNTLET_TEST_B_PW
    tenant_id: tenant-b
    seeded_resources:
      - kind: invoice
        id: inv-b-0001
        url_template: /api/invoices/{id}
        seed_marker: SEED-B-0001
"""


@pytest.fixture
def project(tmp_path):
    """Crea un progetto con il suo ``gauntlet.yaml`` e lo restituisce."""
    (tmp_path / "gauntlet.yaml").write_text(_CONTRACT_YAML, encoding="utf-8")
    return tmp_path


def _mock_zap_factory(alerts=None):
    """Factory che rimpiazza ``ZapRunner``: ritorna un context manager mock.

    Il mock registra spider/active_scan e fa restituire ad ``alerts`` la lista
    passata (vuota per default). Supporta il protocollo ``with`` nativamente
    perché è un :class:`MagicMock`.
    """
    runner = MagicMock(name="ZapRunner-instance")
    runner.__enter__.return_value = runner
    runner.__exit__.return_value = False
    runner.alerts.return_value = list(alerts or [])
    return MagicMock(name="ZapRunner", return_value=runner), runner


def _green_preflight(monkeypatch):
    monkeypatch.setattr(
        cli.preflight,
        "run",
        lambda contract, level, **kw: PreflightResult(True, [], None),
    )


def _authn_env(monkeypatch):
    monkeypatch.setenv("GAUNTLET_TEST_A_PW", "pw-a")
    monkeypatch.setenv("GAUNTLET_TEST_B_PW", "pw-b")


def _patch_authn(monkeypatch):
    """Mocka login/build_zap_context per i livelli autenticati."""

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        return MagicMock(name=f"Session-{label}")

    monkeypatch.setattr(cli, "login", fake_login)
    monkeypatch.setattr(cli, "build_zap_context", lambda zap, c, a, **kw: (1, 1))


def _capture_access_control(monkeypatch):
    """Patcha ``access_control.run`` e restituisce la lista delle chiamate."""
    ac_calls: list[dict] = []

    def fake_access_control(sessions, accounts, contract, **kw):
        ac_calls.append(
            {"sessions": sessions, "accounts": accounts, "contract": contract, "kw": kw}
        )
        return []

    monkeypatch.setattr(cli.access_control, "run", fake_access_control)
    return ac_calls


def _capture_cors(monkeypatch):
    """Patcha ``cors_checks.run`` e restituisce la lista delle chiamate."""
    cors_calls: list[dict] = []

    def fake_cors(targets, contract, reachability, **kw):
        cors_calls.append(
            {
                "targets": targets,
                "contract": contract,
                "reachability": reachability,
                "kw": kw,
            }
        )
        return []

    monkeypatch.setattr(cli.cors_checks, "run", fake_cors)
    return cors_calls


@pytest.fixture(autouse=True)
def _stub_cors(monkeypatch):
    """Rende ERMETICA la suite CLI rispetto al controllo CORS.

    ``cli.run`` invoca ``cors_checks.run`` a QUALSIASI livello e questo, non
    stubbato, emette una GET ``httpx`` reale verso le origini del contratto
    (``http://localhost:8081`` nella fixture ``project``). Sarebbe egress di rete
    da una suite unitaria, non deterministico se qualcosa è in ascolto su
    :8081. Questo stub autouse lo neutralizza di default (ritorna ``[]``), come
    gli altri collaboratori vengono mockati: nessun test CLI apre un socket
    reale. Il test di cablaggio CORS lo ri-patcha nel corpo con ``_capture_cors``
    (l'ultimo ``monkeypatch.setattr`` vince), così continua a verificare la
    chiamata.
    """
    monkeypatch.setattr(cli.cors_checks, "run", lambda *args, **kwargs: [])


@pytest.fixture(autouse=True)
def _stub_new_attacks(monkeypatch):
    """Rende ERMETICA la suite CLI rispetto ai due nuovi moduli d'attacco.

    ``cli.run`` invoca ``error_disclosure_checks.run`` ai livelli autenticati e
    ``ratelimit_checks.run`` in modalità aggressive: entrambi, non stubbati,
    emetterebbero richieste ``httpx`` reali verso le origini del contratto
    (``http://localhost:8081``) — egress di rete da una suite unitaria, non
    deterministico. Come per ``_stub_cors``, questo stub autouse li neutralizza
    di default (ritornano ``[]``); i test di cablaggio li ri-patchano nel corpo
    per catturare la chiamata (l'ultimo ``monkeypatch.setattr`` vince).
    """
    monkeypatch.setattr(cli.error_disclosure_checks, "run", lambda *a, **k: [])
    monkeypatch.setattr(cli.ratelimit_checks, "run", lambda *a, **k: [])
    monkeypatch.setattr(cli.mass_assignment_checks, "run", lambda *a, **k: [])


def test_run_level1_writes_report(project, monkeypatch):
    # Preflight verde e nessun finding: deve comunque scrivere il report.
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    path = cli.run(str(project), level=1)

    assert path.exists() and path.name == "report.md"
    # A livello 1 (cieco) si scansiona ma non ci si autentica. Di default (non
    # aggressive) gira solo lo spider (+ passiva): lo scan attivo NON parte.
    assert runner.spider.called
    assert not runner.active_scan.called
    assert runner.alerts.called


def test_cors_checks_run_at_level1(project, monkeypatch):
    # Il controllo CORS non dipende dall'autenticazione: deve girare anche a
    # livello 1 (cieco), contro l'allowlist del contratto, con la lingua passata.
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    cors_calls = _capture_cors(monkeypatch)

    cli.run(str(project), level=1, report_lang="en")

    assert len(cors_calls) == 1
    assert cors_calls[0]["targets"] == ["http://localhost:8081"]
    assert cors_calls[0]["contract"].allowed_targets == ["http://localhost:8081"]
    assert cors_calls[0]["reachability"] == "localhost"
    assert cors_calls[0]["kw"].get("lang") == "en"


def test_run_raises_when_preflight_fails(project, monkeypatch):
    monkeypatch.setattr(
        cli.preflight,
        "run",
        lambda contract, level, **kw: PreflightResult(
            False, ["Docker non disponibile"], "Crea gli account..."
        ),
    )
    # Se il preflight non passa, non si avvia nessuna scansione.
    boom = MagicMock(side_effect=AssertionError("ZapRunner non deve partire"))
    monkeypatch.setattr(cli, "ZapRunner", boom)

    with pytest.raises(cli.PreflightError) as exc:
        cli.run(str(project), level=1)
    # Il messaggio deve riportare problemi e guida account per l'utente.
    assert "Docker" in str(exc.value)
    assert "Crea gli account" in str(exc.value)
    assert not boom.called


def test_run_level2_authenticates_and_runs_access_control(project, monkeypatch):
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    logins: list[str] = []

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        # La CLI deve inoltrare l'allowlist del contratto al gate di login.
        assert allowed_targets == ["http://localhost:8081"]
        # e la reachability del contratto (serve al mapping host-side docker).
        assert reachability == "localhost"
        logins.append(label or username)
        return MagicMock(name=f"Session-{label}")

    monkeypatch.setattr(cli, "login", fake_login)
    monkeypatch.setattr(cli, "build_zap_context", lambda zap, c, a, **kw: (1, 1))

    ac_calls = _capture_access_control(monkeypatch)

    path = cli.run(str(project), level=2)

    assert path.exists()
    # Livello 2: si autenticano entrambi i clienti e gira il controllo-accessi.
    assert logins == ["cliente_a", "cliente_b"]
    assert len(ac_calls) == 1
    assert set(ac_calls[0]["sessions"].keys()) == {"cliente_a", "cliente_b"}
    # La CLI passa il contratto caricato al controllo-accessi (per il gate).
    assert ac_calls[0]["contract"].allowed_targets == ["http://localhost:8081"]


def test_cli_forwards_primary_auth_header_to_build_zap_context(project, monkeypatch):
    """La CLI inoltra l'header Authorization della sessione PRIMARIA a
    ``build_zap_context`` (I#2).

    Il Bearer è già ottenuto via ``authn.login`` per il tester di
    controllo-accessi: riusarlo in una regola Replacer di ZAP rende la
    scansione realmente autenticata su API a token, senza un secondo login
    lato ZAP.
    """
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        # Ogni account ottiene un header distinto; il primario è cliente_a.
        return cli.Session(
            cookies={}, headers={"Authorization": f"Bearer tok-{label}"}, label=label
        )

    monkeypatch.setattr(cli, "login", fake_login)

    captured: dict = {}

    def fake_build_zap_context(zap, contract, account, *, auth_header=None, session_cookie=None):
        captured["auth_header"] = auth_header
        captured["session_cookie"] = session_cookie
        captured["account_label"] = account.label
        return (1, 1)

    monkeypatch.setattr(cli, "build_zap_context", fake_build_zap_context)
    _capture_access_control(monkeypatch)

    cli.run(str(project), level=2)

    # Il contesto ZAP è costruito sull'account primario (cliente_a) e riceve il
    # suo header Authorization, non quello di un altro account.
    assert captured["account_label"] == "cliente_a"
    assert captured["auth_header"] == "Bearer tok-cliente_a"
    # Login json (non-session): nessun Cookie da iniettare, session_cookie resta None.
    assert captured["session_cookie"] is None


def test_level3_invokes_discovery_from_docs(project, monkeypatch):
    # Livello 3 (documentazione): discovery dalla sola documentazione.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)

    discover_mock = MagicMock(name="discover", return_value=[])
    monkeypatch.setattr(cli, "discover", discover_mock)

    cli.run(str(project), level=3)

    discover_mock.assert_called_once()
    kwargs = discover_mock.call_args.kwargs
    assert kwargs["use_docs"] is True
    assert kwargs["use_source"] is False


def test_level4_uses_docs_and_source(project, monkeypatch):
    # Livello 4 (sorgente): discovery da documentazione e sorgente.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)

    discover_mock = MagicMock(name="discover", return_value=[])
    monkeypatch.setattr(cli, "discover", discover_mock)

    cli.run(str(project), level=4)

    discover_mock.assert_called_once()
    kwargs = discover_mock.call_args.kwargs
    assert kwargs["use_docs"] is True
    assert kwargs["use_source"] is True


def test_aggressive_enables_destructive(project, monkeypatch):
    # Con aggressive=True l'hook confirm cablato ai moduli approva i passi
    # distruttivi (consenso a lotto upfront) e lo scan attivo è distruttivo.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    ac_calls = _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    cli.run(str(project), level=2, aggressive=True)

    # L'hook passato al runner ZAP approva.
    zap_confirm = zap_factory.call_args.kwargs["confirm"]
    assert zap_confirm("qualsiasi passo distruttivo") is True
    # L'hook passato al controllo-accessi approva.
    ac_confirm = ac_calls[0]["kw"]["confirm"]
    assert ac_confirm("scrittura cross-tenant") is True
    # Lo scan attivo è lanciato in modalità distruttiva.
    assert any(
        call.kwargs.get("destructive") is True
        for call in runner.active_scan.call_args_list
    )


def test_default_is_non_destructive(project, monkeypatch):
    # Di default (non aggressive) l'hook confirm nega i passi distruttivi e lo
    # scan attivo resta non distruttivo.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    ac_calls = _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    cli.run(str(project), level=2)

    zap_confirm = zap_factory.call_args.kwargs["confirm"]
    assert zap_confirm("qualsiasi passo distruttivo") is False
    ac_confirm = ac_calls[0]["kw"]["confirm"]
    assert ac_confirm("scrittura cross-tenant") is False
    # Nessuno scan attivo distruttivo.
    assert all(
        call.kwargs.get("destructive") is False
        for call in runner.active_scan.call_args_list
    )


def test_default_mode_does_not_run_active_scan(project, monkeypatch):
    # "Non distruttivo di default": senza aggressive NON parte lo scan attivo;
    # spider e raccolta alert (scansione passiva) girano comunque.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    cli.run(str(project), level=2)

    assert not runner.active_scan.called
    assert runner.spider.called
    assert runner.alerts.called


def test_aggressive_runs_active_scan(project, monkeypatch):
    # Con aggressive parte lo scan attivo (distruttivo), oltre a spider e alert.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    cli.run(str(project), level=2, aggressive=True)

    assert runner.active_scan.called
    assert runner.spider.called
    assert runner.alerts.called
    # In aggressive lo scan attivo è distruttivo.
    assert all(
        call.kwargs.get("destructive") is True
        for call in runner.active_scan.call_args_list
    )


def test_aggressive_still_allowlist_gated(project, monkeypatch):
    # Un endpoint scoperto fuori allowlist NON viene mai attaccato, nemmeno in
    # modalità aggressive: l'allowlist gaterà il seed prima di qualunque uso.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    ac_calls = _capture_access_control(monkeypatch)

    discover_mock = MagicMock(
        return_value=[
            Endpoint("GET", "/api/safe", "openapi"),
            Endpoint("GET", "http://evil.example/pwn", "openapi"),
        ]
    )
    monkeypatch.setattr(cli, "discover", discover_mock)

    cli.run(str(project), level=4, aggressive=True)

    # Tutti gli URL toccati da spider/active_scan.
    touched: list[str] = []
    for call in list(runner.spider.call_args_list) + list(
        runner.active_scan.call_args_list
    ):
        if call.args:
            touched.append(call.args[0])
    # Il seed consentito è stato usato; quello fuori allowlist mai.
    assert any("http://localhost:8081/api/safe" == url for url in touched)
    assert all("evil.example" not in url for url in touched)
    # Gli endpoint scoperti non vengono MAI inoltrati al controllo-accessi
    # (né dentro né fuori allowlist): non sono né admin né dotati di oracolo.
    assert "extra_endpoints" not in ac_calls[0]["kw"]


def test_discovered_endpoint_is_informational_not_access_control(project, monkeypatch):
    # Un endpoint legittimo scoperto (es. /api/profile) diventa SOLO un seed ZAP
    # e una voce informativa nel report: non è inoltrato al controllo-accessi e
    # non può quindi generare un finding verticale "admin raggiungibile" (alta).
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    ac_calls = _capture_access_control(monkeypatch)

    monkeypatch.setattr(
        cli,
        "discover",
        MagicMock(return_value=[Endpoint("GET", "/api/profile", "openapi")]),
    )

    # Lingua forzata: il test asserisce la stringa italiana della nota di
    # discovery, quindi non deve dipendere dal locale di sistema (la CI gira in
    # inglese e il report si auto-localizzerebbe altrimenti).
    path = cli.run(str(project), level=4, report_lang="it")

    # 1) L'endpoint scoperto è stato dato come seed a ZAP.
    touched = [
        call.args[0]
        for call in list(runner.spider.call_args_list)
        + list(runner.active_scan.call_args_list)
        if call.args
    ]
    assert "http://localhost:8081/api/profile" in touched

    # 2) Il controllo-accessi NON riceve l'endpoint scoperto in alcuna forma.
    assert "extra_endpoints" not in ac_calls[0]["kw"]

    # 3) Il report lo riporta come informazione, non come finding ad alta gravità.
    text = path.read_text(encoding="utf-8")
    assert "/api/profile" in text
    assert "Superficie aggiuntiva scoperta" in text
    assert "amministrativo raggiungibile" not in text


def test_main_invokes_run(project, monkeypatch, capsys):
    called = {}

    def fake_run(project_path, level, aggressive=False, zap_port=None, report_lang="auto"):
        called["project_path"] = project_path
        called["level"] = level
        called["aggressive"] = aggressive
        return Path(project_path) / "gauntlet-runs" / "x" / "report.md"

    monkeypatch.setattr(cli, "run", fake_run)
    rc = cli.main(["run", "--project", str(project), "--level", "3"])

    assert rc == 0
    assert called == {"project_path": str(project), "level": 3, "aggressive": False}


def test_main_passes_aggressive_flag(project, monkeypatch):
    called = {}

    def fake_run(project_path, level, aggressive=False, zap_port=None, report_lang="auto"):
        called["aggressive"] = aggressive
        return Path(project_path) / "report.md"

    monkeypatch.setattr(cli, "run", fake_run)
    rc = cli.main(["run", "--project", str(project), "--level", "4", "--aggressive"])

    assert rc == 0
    assert called["aggressive"] is True


def test_main_passes_report_lang_flag(project, monkeypatch):
    # --report-lang è inoltrato a run come report_lang.
    called = {}

    def fake_run(project_path, level, aggressive=False, zap_port=None, report_lang="auto"):
        called["report_lang"] = report_lang
        return Path(project_path) / "report.md"

    monkeypatch.setattr(cli, "run", fake_run)
    rc = cli.main(
        ["run", "--project", str(project), "--level", "2", "--report-lang", "en"]
    )

    assert rc == 0
    assert called["report_lang"] == "en"


def test_main_report_lang_defaults_to_auto(project, monkeypatch):
    called = {}

    def fake_run(project_path, level, aggressive=False, zap_port=None, report_lang="x"):
        called["report_lang"] = report_lang
        return Path(project_path) / "report.md"

    monkeypatch.setattr(cli, "run", fake_run)
    rc = cli.main(["run", "--project", str(project), "--level", "2"])

    assert rc == 0
    assert called["report_lang"] == "auto"


def test_main_success_line_localized_english(project, monkeypatch, capsys):
    # Con --report-lang en la riga di successo di main è in inglese (non italiano).
    def fake_run(project_path, level, aggressive=False, zap_port=None, report_lang="auto"):
        return Path(project_path) / "report.md"

    monkeypatch.setattr(cli, "run", fake_run)
    rc = cli.main(
        ["run", "--project", str(project), "--level", "2", "--report-lang", "en"]
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "Report written to:" in out
    assert "Report scritto in:" not in out


def test_main_error_line_localized_english(project, monkeypatch, capsys):
    # Con --report-lang en la riga di errore di main è in inglese (non italiano).
    def boom(project_path, level, aggressive=False, zap_port=None, report_lang="auto"):
        raise RuntimeError("qualcosa è andato storto")

    monkeypatch.setattr(cli, "run", boom)
    rc = cli.main(
        ["run", "--project", str(project), "--level", "2", "--report-lang", "en"]
    )

    assert rc == 1
    err = capsys.readouterr().err
    assert err.startswith("Error:")
    assert "Errore:" not in err


def test_pick_free_port_returns_bindable_port():
    # La porta restituita era libera: deve poter essere bindata subito dopo.
    port = cli.pick_free_port()
    assert isinstance(port, int)
    assert 0 < port < 65536
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Se la porta non fosse libera questo solleverebbe OSError.
        sock.bind(("", port))


def test_run_uses_free_port_when_not_specified(project, monkeypatch):
    # Senza porta esplicita la CLI ne sceglie una libera via pick_free_port e la
    # passa al runner ZAP (così non collide con altri container).
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    pick = MagicMock(name="pick_free_port", return_value=54321)
    monkeypatch.setattr(cli, "pick_free_port", pick)

    cli.run(str(project), level=1)

    pick.assert_called_once()
    assert zap_factory.call_args.kwargs["port"] == 54321


def test_run_respects_explicit_zap_port(project, monkeypatch):
    # Con una porta esplicita la CLI la usa così com'è e NON chiama pick_free_port.
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    pick = MagicMock(name="pick_free_port")
    monkeypatch.setattr(cli, "pick_free_port", pick)

    cli.run(str(project), level=1, zap_port=9999)

    assert not pick.called
    assert zap_factory.call_args.kwargs["port"] == 9999


def test_main_passes_zap_port_flag(project, monkeypatch):
    called = {}

    def fake_run(project_path, level, aggressive=False, zap_port=None, report_lang="auto"):
        called["zap_port"] = zap_port
        return Path(project_path) / "report.md"

    monkeypatch.setattr(cli, "run", fake_run)
    rc = cli.main(
        ["run", "--project", str(project), "--level", "4", "--zap-port", "9999"]
    )

    assert rc == 0
    assert called["zap_port"] == 9999


def test_authenticated_path_passes_zap_client_not_runner(project, monkeypatch):
    # Regressione Task 4f: la CLI DEVE passare a ``build_zap_context`` il client
    # zapv2 vivo (``zap.client``), NON l'istanza ``ZapRunner``. Prima del fix
    # veniva passato il runner e il run autenticato esplodeva con
    # ``'ZapRunner' object has no attribute 'context'``.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        return MagicMock(name=f"Session-{label}")

    monkeypatch.setattr(cli, "login", fake_login)

    captured: dict = {}

    def fake_build_zap_context(zap, contract, account, **kw):
        captured["zap"] = zap
        return (1, 1)

    monkeypatch.setattr(cli, "build_zap_context", fake_build_zap_context)
    _capture_access_control(monkeypatch)

    cli.run(str(project), level=2)

    # Deve essere il client (``runner.client``), mai il runner stesso.
    assert captured["zap"] is runner.client
    assert captured["zap"] is not runner


def test_ratelimit_runs_only_when_aggressive(project, monkeypatch):
    # Il controllo rate-limit è destructive-ish (possibile lockout): gira SOLO in
    # aggressive, mai di default. Lo verifichiamo catturando le invocazioni del
    # modulo in entrambe le modalità.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    calls: list[dict] = []

    def fake_ratelimit(login_cfg, username, **kw):
        calls.append({"login_cfg": login_cfg, "username": username, "kw": kw})
        return []

    monkeypatch.setattr(cli.ratelimit_checks, "run", fake_ratelimit)

    # Default (non aggressive): il modulo NON viene invocato.
    cli.run(str(project), level=2)
    assert calls == []

    # Aggressive: il modulo viene invocato una volta, sull'account primario.
    cli.run(str(project), level=2, aggressive=True)
    assert len(calls) == 1
    assert calls[0]["login_cfg"] is not None
    assert calls[0]["username"] == "a@example.com"
    assert calls[0]["kw"]["contract"].allowed_targets == ["http://localhost:8081"]
    assert calls[0]["kw"]["reachability"] == "localhost"


def test_error_disclosure_wired_with_malformed_probes(project, monkeypatch):
    # A livello autenticato (default) la CLI invoca error_disclosure_checks.run con
    # le sonde costruite dalle risorse seminate del primario, id malformato incluso.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    calls: list[dict] = []

    def fake_error_disclosure(probe_urls, session_headers, **kw):
        calls.append({"urls": probe_urls, "headers": session_headers, "kw": kw})
        return []

    monkeypatch.setattr(cli.error_disclosure_checks, "run", fake_error_disclosure)

    cli.run(str(project), level=2)

    assert len(calls) == 1
    urls = calls[0]["urls"]
    # Una risorsa seminata (inv-a-0001) => 3 sonde (una per id malformato).
    assert len(urls) == 3
    assert all("http://localhost:8081/api/invoices/" in u for u in urls)
    # L'id originale non compare: è stato sostituito con id malformati.
    assert all("inv-a-0001" not in u for u in urls)
    # La variante da 300 caratteri è presente.
    assert any(len(u) > 250 for u in urls)
    assert calls[0]["kw"]["contract"].allowed_targets == ["http://localhost:8081"]


def test_error_disclosure_skipped_at_blind_level1(project, monkeypatch):
    # Livello 1 (cieco, non autenticato): niente sessioni => error-disclosure non
    # viene invocato (richiede le risorse seminate del primario autenticato).
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    calls: list[int] = []
    monkeypatch.setattr(
        cli.error_disclosure_checks,
        "run",
        lambda *a, **k: calls.append(1) or [],
    )

    cli.run(str(project), level=1)

    assert calls == []


# --- cablaggio del controllo open-redirect (open_redirect_checks) ------------


def _capture_open_redirect(monkeypatch, findings=None):
    """Patcha ``open_redirect_checks.run`` e restituisce la lista delle chiamate.

    Il fake cattura argomenti posizionali e keyword e restituisce ``findings``
    (vuota per default), così i test di cablaggio possono asserire sia la
    presenza del finding nel report sia l'inoltro della sessione primaria.
    """
    calls: list[dict] = []

    def fake_open_redirect(base_url, contract, reachability, **kw):
        calls.append(
            {
                "base_url": base_url,
                "contract": contract,
                "reachability": reachability,
                "kw": kw,
            }
        )
        return list(findings or [])

    monkeypatch.setattr(cli.open_redirect_checks, "run", fake_open_redirect)
    return calls


def test_open_redirect_runs_at_level1_and_finding_in_report(project, monkeypatch):
    # Come CORS, il controllo open-redirect non dipende dall'autenticazione: gira
    # a QUALSIASI livello (anche il livello 1 cieco), contro l'allowlist e la
    # reachability del contratto, con la lingua passata. Il suo finding finisce
    # nel report.
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    sentinel = _finding("open-redirect", "Open redirect confermato")
    calls = _capture_open_redirect(monkeypatch, findings=[sentinel])
    captured = _capture_report(monkeypatch)

    cli.run(str(project), level=1, report_lang="en")

    assert len(calls) == 1
    assert calls[0]["base_url"] == "http://localhost:8081"
    assert calls[0]["contract"].allowed_targets == ["http://localhost:8081"]
    assert calls[0]["reachability"] == "localhost"
    assert calls[0]["kw"].get("lang") == "en"
    # A livello 1 (non autenticato) non c'è sessione: header/cookie sono None.
    assert calls[0]["kw"].get("session_headers") is None
    assert calls[0]["kw"].get("session_cookies") is None
    # Il finding del modulo è incluso nel report.
    assert sentinel in captured["findings"]


def test_open_redirect_noop_adds_nothing(project, monkeypatch):
    # Quando il modulo non restituisce nulla (nessun probe vulnerabile, o
    # redirect_probes vuoto) non viene aggiunto alcun finding open-redirect.
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _capture_open_redirect(monkeypatch, findings=[])
    captured = _capture_report(monkeypatch)

    cli.run(str(project), level=1)

    assert all(f.source != "open-redirect" for f in captured["findings"])


def test_open_redirect_forwards_primary_session_when_authenticated(project, monkeypatch):
    # Ai livelli autenticati la CLI inoltra header e cookie della sessione
    # PRIMARIA (cliente_a) al modulo, così le sonde vedono le pagine dietro login.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        return cli.Session(
            cookies={"sid": f"sid-{label}"},
            headers={"Authorization": f"Bearer tok-{label}"},
            label=label,
        )

    monkeypatch.setattr(cli, "login", fake_login)
    monkeypatch.setattr(cli, "build_zap_context", lambda zap, c, a, **kw: (1, 1))
    _capture_access_control(monkeypatch)
    calls = _capture_open_redirect(monkeypatch, findings=[])

    cli.run(str(project), level=2)

    assert len(calls) == 1
    # Header e cookie sono quelli dell'account primario (cliente_a), non di un altro.
    assert calls[0]["kw"]["session_headers"] == {"Authorization": "Bearer tok-cliente_a"}
    assert calls[0]["kw"]["session_cookies"] == {"sid": "sid-cliente_a"}


# --- cablaggio del controllo mass-assignment (mass_assignment_checks) --------

# Contratto con una sonda `mass_assignment`: l'unico caso in cui il modulo di
# assegnazione di massa (aggressive-only) deve partire. Due account per avere una
# sessione primaria (cliente_a) da inoltrare.
_MASS_ASSIGNMENT_CONTRACT_YAML = """\
name: progetto-mass-assignment
allowed_targets:
  - http://localhost:8081
reachability: localhost

login:
  method: json
  login_url: http://localhost:8081/api/auth/login
  username_field: email
  password_field: password
  logged_in_indicator: '"token"'
  token_path: data.token

accounts:
  - label: cliente_a
    username: a@example.com
    password_env: GAUNTLET_TEST_A_PW
    tenant_id: tenant-a
  - label: cliente_b
    username: b@example.com
    password_env: GAUNTLET_TEST_B_PW
    tenant_id: tenant-b

mass_assignment:
  - url_template: /api/users/{id}
    id: "1"
    forbidden_field: role
    forbidden_value: admin
"""


@pytest.fixture
def mass_assignment_project(tmp_path):
    (tmp_path / "gauntlet.yaml").write_text(
        _MASS_ASSIGNMENT_CONTRACT_YAML, encoding="utf-8"
    )
    return tmp_path


def _capture_mass_assignment(monkeypatch, findings=None):
    """Patcha ``mass_assignment_checks.run`` e restituisce la lista delle chiamate."""
    calls: list[dict] = []

    def fake_mass_assignment(base_url, contract, reachability, **kw):
        calls.append(
            {
                "base_url": base_url,
                "contract": contract,
                "reachability": reachability,
                "kw": kw,
            }
        )
        return list(findings or [])

    monkeypatch.setattr(cli.mass_assignment_checks, "run", fake_mass_assignment)
    return calls


def test_mass_assignment_runs_only_when_aggressive(mass_assignment_project, monkeypatch):
    # Il controllo mass-assignment è DISTRUTTIVO (scrive): gira SOLO in aggressive,
    # mai di default. Lo verifichiamo catturando le invocazioni del modulo in
    # entrambe le modalità e asserendo l'inoltro della sessione primaria + confirm.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        return cli.Session(
            cookies={"sid": f"sid-{label}"},
            headers={"Authorization": f"Bearer tok-{label}"},
            label=label,
        )

    monkeypatch.setattr(cli, "login", fake_login)
    monkeypatch.setattr(cli, "build_zap_context", lambda zap, c, a, **kw: (1, 1))
    _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    sentinel = _finding("mass-assignment", "Mass assignment confermato")
    calls = _capture_mass_assignment(monkeypatch, findings=[sentinel])
    captured = _capture_report(monkeypatch)

    # Default (non aggressive): il modulo NON viene invocato (nessuna scrittura).
    cli.run(str(mass_assignment_project), level=2, report_lang="it")
    assert calls == []
    assert all(f.source != "mass-assignment" for f in captured["findings"])

    # Aggressive: invocato una volta sull'account primario, con sessione e confirm.
    cli.run(str(mass_assignment_project), level=2, aggressive=True, report_lang="it")
    assert len(calls) == 1
    assert calls[0]["base_url"] == "http://localhost:8081"
    assert calls[0]["contract"].allowed_targets == ["http://localhost:8081"]
    assert calls[0]["reachability"] == "localhost"
    assert calls[0]["kw"].get("lang") == "it"
    # Header e cookie della sessione PRIMARIA (cliente_a), non di un altro account.
    assert calls[0]["kw"]["session_headers"] == {"Authorization": "Bearer tok-cliente_a"}
    assert calls[0]["kw"]["session_cookies"] == {"sid": "sid-cliente_a"}
    # confirm è inoltrato e, in aggressive, approva (consenso a lotto upfront).
    assert calls[0]["kw"]["confirm"]("scrittura mass-assignment") is True
    # Il finding del modulo è incluso nel report.
    assert sentinel in captured["findings"]


def test_mass_assignment_skipped_without_probes(project, monkeypatch):
    # Senza un blocco `mass_assignment` nel contratto, il modulo NON viene mai
    # invocato, nemmeno in aggressive: il gate `contract.mass_assignment` è falso.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)
    monkeypatch.setattr(cli, "discover", MagicMock(return_value=[]))

    calls = _capture_mass_assignment(monkeypatch, findings=[])

    cli.run(str(project), level=2, aggressive=True)

    assert calls == []


def test_console_entry_point_matches_pyproject():
    """Il console script `gauntlet` deve puntare a ``gauntlet.cli:main``.

    Protegge il punto d'ingresso dell'installazione globale (pipx/pip): se
    qualcuno rinomina ``main`` o cambia la stringa in ``pyproject.toml``, il
    comando ``gauntlet`` smetterebbe di funzionare pur restando verde il resto
    della suite. Verifichiamo sia la stringa dichiarata sia che l'oggetto
    referenziato sia davvero ``cli.main`` e sia invocabile.
    """
    import tomllib

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    entry = data["project"]["scripts"]["gauntlet"]
    assert entry == "gauntlet.cli:main"

    module_name, _, attr = entry.partition(":")
    import importlib

    module = importlib.import_module(module_name)
    target = getattr(module, attr)
    assert target is cli.main
    assert callable(target)


# --- cablaggio dei controlli di debolezza JWT (jwt_checks) --------------------

# Contratto a login di tipo "token": il bearer è un JWT reale, quindi i controlli
# JWT si attivano. Un solo account con una risorsa seminata (la sonda).
_TOKEN_CONTRACT_YAML = """\
name: progetto-token
allowed_targets:
  - http://localhost:8081
reachability: localhost

login:
  method: token
  login_url: http://localhost:8081/api/auth/login
  username_field: email
  password_field: password
  logged_in_indicator: '"token"'
  token_path: token

accounts:
  - label: cliente_a
    username: a@example.com
    password_env: GAUNTLET_TEST_A_PW
    tenant_id: tenant-a
    seeded_resources:
      - kind: invoice
        id: inv-a-0001
        url_template: /api/invoices/{id}
        seed_marker: SEED-A-0001
"""


@pytest.fixture
def token_project(tmp_path):
    (tmp_path / "gauntlet.yaml").write_text(_TOKEN_CONTRACT_YAML, encoding="utf-8")
    return tmp_path


def test_cli_wires_jwt_checks_for_token_login(token_project, monkeypatch):
    # Login a token: la CLI deve invocare jwt_checks.run sull'account primario,
    # passando il bearer senza "Bearer ", la sonda risolta e il seed_marker.
    monkeypatch.setenv("GAUNTLET_TEST_A_PW", "pw-a")
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        return cli.Session(
            cookies={}, headers={"Authorization": "Bearer jwt-reale-123"}, label=label
        )

    monkeypatch.setattr(cli, "login", fake_login)
    monkeypatch.setattr(cli, "build_zap_context", lambda zap, c, a, **kw: (1, 1))
    _capture_access_control(monkeypatch)

    calls: list[dict] = []

    def fake_jwt_run(token, probe_url, marker, session_headers, **kw):
        calls.append(
            {
                "token": token,
                "probe_url": probe_url,
                "marker": marker,
                "session_headers": session_headers,
                "kw": kw,
            }
        )
        return []

    monkeypatch.setattr(cli.jwt_checks, "run", fake_jwt_run)

    cli.run(str(token_project), level=2)

    assert len(calls) == 1
    assert calls[0]["token"] == "jwt-reale-123"
    assert calls[0]["probe_url"] == "http://localhost:8081/api/invoices/inv-a-0001"
    assert calls[0]["marker"] == "SEED-A-0001"
    assert calls[0]["session_headers"]["Authorization"] == "Bearer jwt-reale-123"
    assert calls[0]["kw"]["reachability"] == "localhost"
    assert calls[0]["kw"]["contract"].allowed_targets == ["http://localhost:8081"]


def test_cli_skips_jwt_checks_for_json_login(project, monkeypatch):
    # Il contratto di default usa login "json": i controlli JWT NON si attivano.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)
    _capture_access_control(monkeypatch)

    called = {"n": 0}

    def fake_jwt_run(*a, **kw):
        called["n"] += 1
        return []

    monkeypatch.setattr(cli.jwt_checks, "run", fake_jwt_run)

    cli.run(str(project), level=2)

    assert called["n"] == 0


# --- cablaggio del login a sessione-cookie (method=session) -------------------

# Contratto a login di tipo "session": il successo è provato dal cookie di
# sessione (``success_cookie``), non da un token nel corpo. Gli account non hanno
# una password dedicata (``password_env`` assente): tipico del login a sessione.
_SESSION_CONTRACT_YAML = """\
name: progetto-session
allowed_targets:
  - http://localhost:8081
reachability: localhost

login:
  method: session
  login_url: http://localhost:8081/api/auth/login
  username_field: email
  success_cookie: session_id

accounts:
  - label: cliente_a
    username: a@example.com
    tenant_id: tenant-a
  - label: cliente_b
    username: b@example.com
    tenant_id: tenant-b
"""


@pytest.fixture
def session_project(tmp_path):
    (tmp_path / "gauntlet.yaml").write_text(_SESSION_CONTRACT_YAML, encoding="utf-8")
    return tmp_path


def _finding(source, title):
    """Costruisce un Finding sentinella minimo per i test di cablaggio."""
    return Finding(
        source=source,
        severity="info",
        title=title,
        description="",
        evidence="",
        fix="",
        impact_if_ignored="",
        confidence=1.0,
        url=None,
    )


def _capture_report(monkeypatch):
    """Patcha ``write_report`` per catturare ``findings`` e ``meta``.

    Non scrive su disco: cattura gli argomenti e restituisce un path fittizio, così
    i test possono asserire il contenuto di ``meta`` senza leggere il Markdown.
    """
    captured: dict = {}

    def fake_write_report(findings, project_path, meta, *, lang="it"):
        captured["findings"] = findings
        captured["meta"] = meta
        captured["lang"] = lang
        return Path(project_path) / "report.md"

    monkeypatch.setattr(cli, "write_report", fake_write_report)
    return captured


# --- resilienza: contenimento dei crash operativi di ZAP ---------------------


def test_zap_crash_is_contained_run_continues(project, monkeypatch, capsys):
    # Il daemon ZAP "muore" durante lo scan attivo (pressione di memoria): requests
    # solleva ConnectionError (sottoclasse di RequestException). Il crash deve essere
    # CONTENUTO: run NON rilancia, i controlli httpx dopo il blocco ZAP girano
    # comunque e il report viene scritto segnalando la copertura parziale.
    _authn_env(monkeypatch)
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    runner.active_scan.side_effect = requests.exceptions.ConnectionError(
        "Unable to connect to proxy"
    )
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    _patch_authn(monkeypatch)

    # I controlli DOPO il blocco ZAP devono comunque produrre finding.
    ac_finding = _finding("access-control", "controllo-accessi orizzontale")
    monkeypatch.setattr(cli.access_control, "run", lambda *a, **k: [ac_finding])
    cors_finding = _finding("cors", "CORS permissivo")
    monkeypatch.setattr(cli.cors_checks, "run", lambda *a, **k: [cors_finding])

    captured = _capture_report(monkeypatch)

    path = cli.run(str(project), level=2, aggressive=True)

    # 1) run NON rilancia: ritorna il path del report.
    assert path == Path(str(project)) / "report.md"
    # 2) i controlli post-ZAP hanno girato: i loro finding sono nel report.
    assert ac_finding in captured["findings"]
    assert cors_finding in captured["findings"]
    # 3) il motivo è registrato in meta e nomina il tipo dell'eccezione.
    assert captured["meta"]["zap_interrotto"]
    assert "ConnectionError" in captured["meta"]["zap_interrotto"]
    # 4) un avviso è stampato su stderr (senza traceback che esploda il run).
    err = capsys.readouterr().err
    assert "ZAP" in err


def test_zap_target_not_allowed_stays_fatal(project, monkeypatch):
    # TargetNotAllowed NON è una RequestException: l'allowlist resta FATALE.
    # Un crash contenuto non deve mai inghiottire una violazione di perimetro.
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    runner.spider.side_effect = TargetNotAllowed("fuori allowlist")
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    with pytest.raises(TargetNotAllowed):
        cli.run(str(project), level=1)


def test_happy_path_has_no_zap_interrotto_in_meta(project, monkeypatch):
    # Caso felice invariato: senza crash ZAP, meta NON contiene zap_interrotto
    # (retrocompatibilità byte-identica dell'intestazione del report).
    _green_preflight(monkeypatch)
    zap_factory, _ = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    captured = _capture_report(monkeypatch)

    cli.run(str(project), level=1)

    assert "zap_interrotto" not in captured["meta"]


def test_zap_interrotto_reason_is_only_type_and_message(project, monkeypatch):
    # Niente leak: il motivo salvato è esattamente "tipo: messaggio", nient'altro
    # (nessun traceback). Gli errori ZAP non trasportano segreti.
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    runner.spider.side_effect = requests.exceptions.ConnectionError(
        "proxy down durante lo scan"
    )
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)
    captured = _capture_report(monkeypatch)

    cli.run(str(project), level=1)

    assert (
        captured["meta"]["zap_interrotto"]
        == "ConnectionError: proxy down durante lo scan"
    )


def test_cli_builds_session_cookie_for_session_login(session_project, monkeypatch):
    # Login a sessione: la CLI costruisce la stringa Cookie dell'account PRIMARIO
    # dai suoi ``Session.cookies`` e la passa a ``build_zap_context`` come
    # ``session_cookie``. Il contesto a sessione non crea un utente ZAP, quindi
    # ``build_zap_context`` ritorna ``user_id=None``: lo spider deve essere
    # invocato con ``user_id=None`` senza errori.
    _green_preflight(monkeypatch)
    zap_factory, runner = _mock_zap_factory(alerts=[])
    monkeypatch.setattr(cli, "ZapRunner", zap_factory)

    def fake_login(
        login_cfg, username, password, *, allowed_targets, label=None,
        reachability="localhost",
    ):
        # Ogni account cattura i propri cookie; il primario è cliente_a.
        return cli.Session(
            cookies={"session_id": f"sid-{label}", "csrf": f"csrf-{label}"},
            headers={},
            label=label,
        )

    monkeypatch.setattr(cli, "login", fake_login)

    captured: dict = {}

    def fake_build_zap_context(zap, contract, account, *, auth_header=None, session_cookie=None):
        captured["auth_header"] = auth_header
        captured["session_cookie"] = session_cookie
        captured["account_label"] = account.label
        # Il contesto a sessione non crea un utente ZAP: user_id è None.
        return (7, None)

    monkeypatch.setattr(cli, "build_zap_context", fake_build_zap_context)
    _capture_access_control(monkeypatch)

    cli.run(str(session_project), level=2)

    # Il contesto è costruito sull'account primario (cliente_a).
    assert captured["account_label"] == "cliente_a"
    # Il session_cookie è non vuoto e costruito dai cookie del login primario.
    assert captured["session_cookie"] == "session_id=sid-cliente_a; csrf=csrf-cliente_a"
    # Per il login a sessione non c'è header Authorization da inoltrare.
    assert captured["auth_header"] is None
    # Lo spider è stato invocato con il context_id e user_id=None (senza errori).
    assert runner.spider.called
    assert any(
        call.args == ("http://localhost:8081", 7, None)
        for call in runner.spider.call_args_list
    )
