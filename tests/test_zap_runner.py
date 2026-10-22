"""Test del runner ZAP (``gauntlet.zap_runner``).

Il cuore testato in TDD è :func:`normalize_alert` — funzione *pura*, senza
Docker né un'istanza ZAP viva: mappa il rischio ZAP sulla scala di gravità
italiana e trasporta i campi dell'alert in un :class:`Finding`.

Per :class:`ZapRunner` i test coprono, con mock, solo ciò che il brief richiede
più il gate di sicurezza nominato: che ``active_scan`` chiami
``assert_target_allowed`` *prima di tutto* e, per uno scan distruttivo, esiga la
conferma. Nessun avvio di Docker/ZAP reale: l'integrazione end-to-end è rinviata
allo smoke test manuale del Task 9.
"""

from unittest.mock import MagicMock

import pytest

from gauntlet.contract import load_contract
from gauntlet.models import Finding
from gauntlet.safety import DestructiveNotConfirmed, TargetNotAllowed
from gauntlet.zap_runner import ZapRunner, normalize_alert

FIXTURES = "tests/fixtures"


# --- normalize_alert: il cuore unit-testato ------------------------------


def test_normalize_alert_maps_risk_and_fields():
    raw = {
        "name": "SQL Injection",
        "risk": "High",
        "description": "...",
        "solution": "Use parametrized queries",
        "url": "http://localhost:8081/x",
        "evidence": "' OR 1=1",
    }
    f = normalize_alert(raw)
    assert f.source == "zap"
    assert f.severity == "alta"
    assert f.fix.startswith("Use parametrized")
    assert f.evidence == "' OR 1=1"


@pytest.mark.parametrize(
    "risk,expected",
    [
        ("Informational", "info"),
        ("Low", "bassa"),
        ("Medium", "media"),
        ("High", "alta"),
        # mappatura case-insensitive
        ("informational", "info"),
        ("HIGH", "alta"),
    ],
)
def test_risk_mapping(risk, expected):
    assert normalize_alert({"name": "x", "risk": risk}).severity == expected


def test_normalize_alert_never_emits_critica():
    # 'critica' è riservata al controllo-accessi confermato (Task 5): ZAP non la
    # produce mai, nemmeno per rischi sconosciuti o assenti.
    for risk in ["Informational", "Low", "Medium", "High", "boh", ""]:
        assert normalize_alert({"name": "x", "risk": risk}).severity != "critica"


def test_normalize_alert_unknown_risk_defaults_to_info():
    assert normalize_alert({"name": "x", "risk": "Qualcosa"}).severity == "info"


def test_normalize_alert_is_finding_with_zap_source():
    f = normalize_alert({"name": "Header mancante", "risk": "Low"})
    assert isinstance(f, Finding)
    assert f.source == "zap"
    assert f.title == "Header mancante"
    assert f.url is None  # url assente => None
    assert isinstance(f.confidence, float)
    assert f.impact_if_ignored  # non vuoto: utile per il report


def test_normalize_alert_maps_confidence_string_to_float():
    f = normalize_alert({"name": "x", "risk": "Low", "confidence": "High"})
    assert 0.0 <= f.confidence <= 1.0
    assert f.confidence > 0.5


# --- ZapRunner: gate di sicurezza (con mock) -----------------------------


@pytest.fixture
def contract():
    # allowed_targets: http://localhost:8081, http://host.docker.internal:8081
    return load_contract(f"{FIXTURES}/gauntlet.valid.yaml")


def test_active_scan_rejects_target_not_in_allowlist(contract):
    runner = ZapRunner(api_key="k", contract=contract)
    runner._zap = MagicMock()
    with pytest.raises(TargetNotAllowed):
        runner.active_scan("https://prod.cliente.it/")
    runner._zap.ascan.scan.assert_not_called()


def test_active_scan_allowlist_checked_before_confirmation(contract):
    # Target fuori allowlist + distruttivo: deve fallire con TargetNotAllowed
    # senza nemmeno interrogare l'hook di conferma.
    confirm = MagicMock(return_value=True)
    runner = ZapRunner(api_key="k", contract=contract, confirm=confirm)
    runner._zap = MagicMock()
    with pytest.raises(TargetNotAllowed):
        runner.active_scan("https://prod/", destructive=True)
    confirm.assert_not_called()


def test_active_scan_destructive_without_confirmation_raises(contract):
    runner = ZapRunner(api_key="k", contract=contract, confirm=lambda d: False)
    runner._zap = MagicMock()
    with pytest.raises(DestructiveNotConfirmed):
        runner.active_scan("http://localhost:8081/", destructive=True)
    runner._zap.ascan.scan.assert_not_called()


def test_active_scan_destructive_without_hook_raises(contract):
    # Nessun hook di conferma => in assenza di via libera esplicito, si rifiuta.
    runner = ZapRunner(api_key="k", contract=contract)  # confirm=None
    runner._zap = MagicMock()
    with pytest.raises(DestructiveNotConfirmed):
        runner.active_scan("http://localhost:8081/", destructive=True)


def test_active_scan_confirm_hook_exception_propagates(contract):
    # Da nota Task 2: se l'hook solleva, l'eccezione propaga (non viene inghiottita).
    def boom(_desc):
        raise RuntimeError("l'utente ha interrotto")

    runner = ZapRunner(api_key="k", contract=contract, confirm=boom)
    runner._zap = MagicMock()
    with pytest.raises(RuntimeError):
        runner.active_scan("http://localhost:8081/", destructive=True)


def test_active_scan_confirmed_destructive_runs(contract):
    confirm = MagicMock(return_value=True)
    runner = ZapRunner(api_key="k", contract=contract, confirm=confirm)
    runner._poll_interval = 0
    zap = MagicMock()
    zap.ascan.scan.return_value = "0"
    zap.ascan.status.return_value = "100"
    runner._zap = zap
    runner.active_scan("http://localhost:8081/api", destructive=True)
    confirm.assert_called_once()
    zap.ascan.scan.assert_called_once()


def test_non_destructive_active_scan_runs_without_confirmation(contract):
    # Lo scan attivo non distruttivo gira liberamente dopo il check allowlist.
    confirm = MagicMock(return_value=False)
    runner = ZapRunner(api_key="k", contract=contract, confirm=confirm)
    runner._poll_interval = 0
    zap = MagicMock()
    zap.ascan.scan.return_value = "0"
    zap.ascan.status.return_value = "100"
    runner._zap = zap
    runner.active_scan("http://localhost:8081/api")  # destructive=False
    confirm.assert_not_called()
    zap.ascan.scan.assert_called_once()


def test_active_scan_without_contract_fails_closed():
    # Senza contratto non si può verificare l'allowlist => fail-closed.
    runner = ZapRunner(api_key="k")  # nessun contratto
    runner._zap = MagicMock()
    with pytest.raises(TargetNotAllowed):
        runner.active_scan("http://localhost:8081/")


def test_spider_rejects_target_not_in_allowlist(contract):
    runner = ZapRunner(api_key="k", contract=contract)
    runner._zap = MagicMock()
    with pytest.raises(TargetNotAllowed):
        runner.spider("https://prod/")


def test_spider_runs_for_allowed_target(contract):
    runner = ZapRunner(api_key="k", contract=contract)
    runner._poll_interval = 0
    zap = MagicMock()
    zap.spider.scan.return_value = "0"
    zap.spider.status.return_value = "100"
    runner._zap = zap
    runner.spider("http://localhost:8081/")
    zap.spider.scan.assert_called_once()


# --- alerts(): conversione in Finding ------------------------------------


def test_alerts_normalizes_each(contract):
    runner = ZapRunner(api_key="k", contract=contract)
    zap = MagicMock()
    zap.core.alerts.return_value = [
        {
            "name": "A",
            "risk": "High",
            "solution": "fix a",
            "url": "http://localhost:8081/a",
            "evidence": "e",
        },
        {"name": "B", "risk": "Low"},
    ]
    runner._zap = zap
    out = runner.alerts("http://localhost:8081")
    assert len(out) == 2
    assert all(isinstance(f, Finding) for f in out)
    assert out[0].severity == "alta"
    assert out[1].severity == "bassa"
    zap.core.alerts.assert_called_once_with(baseurl="http://localhost:8081")


# --- start()/stop(): sola costruzione del comando Docker -----------------


def test_docker_command_has_host_gateway_and_image():
    runner = ZapRunner(api_key="secret", port=8099)
    cmd = runner._build_docker_command()
    assert cmd[0] == "docker"
    assert "run" in cmd
    assert "--add-host=host.docker.internal:host-gateway" in cmd
    assert "zaproxy/zap-stable" in cmd
    assert "zap.sh" in cmd
    assert "-daemon" in cmd
    assert any("api.key=secret" in part for part in cmd)
    assert any("8099" in part for part in cmd)


def test_zap_daemon_command_disables_autoupdate():
    # Task 4d: all'avvio il daemon NON deve auto-aggiornarsi / installare add-on,
    # altrimenti si riavvia e lascia cadere la connessione del client a metà scan.
    runner = ZapRunner(api_key="secret", port=8099)
    cmd = runner._build_docker_command()
    # -silent: disabilita update-check automatico e invio statistiche
    assert "-silent" in cmd
    # flag di config "belt-and-suspenders": nessun download/installazione all'avvio
    joined = " ".join(cmd)
    for flag in (
        "autoupdate.checkOnStart=false",
        "autoupdate.downloadNewRelease=false",
        "autoupdate.installAddonUpdates=false",
        "autoupdate.installScannerRules=false",
        "start.checkForUpdates=false",
    ):
        assert flag in joined, f"flag mancante: {flag}"
    # i flag esistenti api.*/host/port restano intatti
    assert "--add-host=host.docker.internal:host-gateway" in cmd
    assert any("api.key=secret" in part for part in cmd)
    assert any("8099" in part for part in cmd)


# --- _await_ready(): attesa robusta che l'API risponda -------------------


def test_await_ready_returns_when_version_call_succeeds():
    # Ritorna (senza sollevare) appena una chiamata a core.version va a buon fine.
    runner = ZapRunner(api_key="k")
    runner._poll_interval = 0
    zap = MagicMock()
    zap.core.version = "2.14.0"
    runner._zap = zap
    runner._await_ready()  # non deve sollevare


def test_await_ready_polls_until_version_responds():
    # Finché core.version solleva, continua a riprovare; appena risponde, ritorna.
    runner = ZapRunner(api_key="k")
    runner._poll_interval = 0

    class _Core:
        def __init__(self):
            self.calls = 0

        @property
        def version(self):
            self.calls += 1
            if self.calls < 3:
                raise ConnectionError("proxy non ancora pronto")
            return "2.14.0"

    zap = MagicMock()
    zap.core = _Core()
    runner._zap = zap
    runner._await_ready()
    assert zap.core.calls >= 3


def test_await_ready_times_out_when_api_never_responds():
    runner = ZapRunner(api_key="k")
    runner._poll_interval = 0
    runner._ready_timeout = 0.05

    class _Core:
        @property
        def version(self):
            raise ConnectionError("daemon giù")

    zap = MagicMock()
    zap.core = _Core()
    runner._zap = zap
    with pytest.raises(RuntimeError):
        runner._await_ready()


# --- .client: accessore pubblico del client zapv2 vivo -------------------


def test_zaprunner_client_property_returns_live_client(monkeypatch):
    # Task 4f: ``.client`` espone il client zapv2 vivo (quello che la CLI passa a
    # ``build_zap_context``). Prima di start() e dopo stop() deve sollevare
    # ``RuntimeError``, esattamente come ``_require_client``.
    runner = ZapRunner(api_key="k", port=8099)

    # Prima di start(): nessun client -> RuntimeError.
    with pytest.raises(RuntimeError):
        runner.client

    # Mock di start(): niente Docker/ZAP reali. ``subprocess.run`` finto +
    # ``_await_ready`` neutralizzato; il costruttore ZAPv2 restituisce un sentinella.
    sentinel = MagicMock(name="zapv2-client")
    monkeypatch.setattr(
        "gauntlet.zap_runner.subprocess.run",
        lambda *a, **k: MagicMock(stdout="container-id\n"),
    )
    monkeypatch.setattr(ZapRunner, "_await_ready", lambda self: None)
    import zapv2

    monkeypatch.setattr(zapv2, "ZAPv2", lambda **kw: sentinel)

    runner.start()
    # Dopo start(): ``.client`` è il client vivo (identico a ``_require_client``).
    assert runner.client is sentinel
    assert runner.client is runner._require_client()

    # Dopo stop(): il client torna assente -> RuntimeError.
    monkeypatch.setattr(
        "gauntlet.zap_runner.subprocess.run",
        lambda *a, **k: MagicMock(stdout=""),
    )
    runner.stop()
    with pytest.raises(RuntimeError):
        runner.client
