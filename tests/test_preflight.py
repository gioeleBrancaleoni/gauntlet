"""Test del preflight (``gauntlet.preflight``).

Il preflight è una funzione **pura**: le verifiche che toccherebbero Docker, la
rete o l'applicazione sotto test sono iniettate come callable, così i test le
possono pilotare senza alcun effetto collaterale. Qui verifichiamo le due
proprietà centrali del brief:

1. ambiente non pronto (Docker assente) ⇒ ``ok=False`` con un problema che
   nomina Docker;
2. livello autenticato + account di prova assenti ⇒ viene prodotta una guida
   (``account_guidance``) che spiega quali account servono e con quali permessi.
"""

import socket

import pytest

from gauntlet.contract import load_contract
from gauntlet.preflight import PreflightResult, _default_reachability_check, run

FIXTURES = "tests/fixtures"


@pytest.fixture
def contract():
    # allowed_targets: http://localhost:8081, http://host.docker.internal:8081
    # due account di clienti diversi (cliente_a / cliente_b).
    return load_contract(f"{FIXTURES}/gauntlet.valid.yaml")


def test_preflight_reports_missing_docker(contract):
    r = run(
        contract,
        level=1,
        docker_check=lambda: False,
        reachability_check=lambda target, reachability: True,
    )
    assert r.ok is False and any("Docker" in p for p in r.problems)


def test_preflight_emits_account_guidance_when_accounts_absent(contract):
    r = run(
        contract,
        level=2,
        docker_check=lambda: True,
        account_probe=lambda a: False,
        reachability_check=lambda target, reachability: True,
    )
    assert r.account_guidance is not None and "permessi" in r.account_guidance.lower()


# --- Proprietà aggiuntive --------------------------------------------------


def test_preflight_ok_when_everything_ready_unauthenticated(contract):
    # Livello cieco (1): nessun account richiesto; ambiente pronto ⇒ ok.
    r = run(
        contract,
        level=1,
        docker_check=lambda: True,
        reachability_check=lambda target, reachability: True,
    )
    assert r.ok is True
    assert r.problems == []
    assert r.account_guidance is None


def test_preflight_ok_when_authenticated_accounts_present(contract):
    # Livello autenticato (2) con account presenti: nessuna guida, ok.
    r = run(
        contract,
        level=2,
        docker_check=lambda: True,
        account_probe=lambda a: True,
        reachability_check=lambda target, reachability: True,
    )
    assert r.ok is True
    assert r.account_guidance is None


def test_preflight_unreachable_target_is_a_problem(contract):
    r = run(
        contract,
        level=1,
        docker_check=lambda: True,
        reachability_check=lambda target, reachability: False,
    )
    assert r.ok is False
    # Ogni target non raggiungibile deve comparire nei problemi.
    assert any("localhost:8081" in p for p in r.problems)


def test_preflight_guidance_lists_accounts_and_known_data(contract):
    # La guida deve nominare i due account e i dati noti seminati, e citare
    # i percorsi docs/src del contratto quando disponibili.
    r = run(
        contract,
        level=2,
        docker_check=lambda: True,
        account_probe=lambda a: False,
        reachability_check=lambda target, reachability: True,
    )
    g = r.account_guidance
    assert g is not None
    assert "cliente_a" in g and "cliente_b" in g
    assert "inv-a-001" in g  # dato noto seminato
    assert "./docs" in g and "./src" in g  # percorsi del contratto


def test_preflight_no_account_probe_on_unauthenticated_level(contract):
    # A livello 1 l'account_probe non deve nemmeno essere chiamato.
    calls = []

    def probe(account):
        calls.append(account)
        return False

    r = run(
        contract,
        level=1,
        docker_check=lambda: True,
        account_probe=probe,
        reachability_check=lambda target, reachability: True,
    )
    assert calls == []
    assert r.account_guidance is None


# --- reachability host-side mapping in docker mode (Task 4b) ---------------


def test_reachability_check_docker_maps_host_internal_to_loopback():
    # In docker mode, un target su host.docker.internal:PORT deve risultare
    # raggiungibile se è in ascolto 127.0.0.1:PORT (il nome non risolve
    # sull'host, ma la sonda lo rimappa sul loopback).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        target = f"http://host.docker.internal:{port}/"
        assert _default_reachability_check(target, "docker") is True


def test_reachability_check_non_docker_does_not_remap(monkeypatch):
    # Fuori da docker NON c'è rimappatura: la connessione va a host.docker.internal
    # così com'è. Intercettiamo socket.create_connection per catturare l'host.
    captured = {}

    import gauntlet.preflight as pf

    def fake_create_connection(address, timeout=None):
        captured["host"] = address[0]
        raise OSError("blocked in test")

    monkeypatch.setattr(pf.socket, "create_connection", fake_create_connection)
    assert _default_reachability_check("http://host.docker.internal:3000/", "localhost") is False
    assert captured["host"] == "host.docker.internal"


def test_reachability_check_docker_remaps_before_connect(monkeypatch):
    captured = {}

    import gauntlet.preflight as pf

    def fake_create_connection(address, timeout=None):
        captured["host"] = address[0]
        raise OSError("blocked in test")

    monkeypatch.setattr(pf.socket, "create_connection", fake_create_connection)
    assert _default_reachability_check("http://host.docker.internal:3000/", "docker") is False
    assert captured["host"] == "127.0.0.1"


def test_preflight_result_is_the_exported_dataclass(contract):
    r = run(
        contract,
        level=1,
        docker_check=lambda: True,
        reachability_check=lambda target, reachability: True,
    )
    assert isinstance(r, PreflightResult)
