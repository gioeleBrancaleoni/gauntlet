"""Tests for the safety gate (``gauntlet.safety``).

Il gate è l'unica barriera che impedisce alla skill di attaccare un host non
autorizzato / di produzione: la proprietà centrale sotto test è il
*fail-closed* (qualunque origine non esplicitamente consentita deve far
sollevare :class:`TargetNotAllowed`).
"""

import pytest

from gauntlet.contract import load_contract
from gauntlet.safety import (
    DestructiveNotConfirmed,
    TargetNotAllowed,
    assert_target_allowed,
    confirm_destructive,
    host_side_url,
)

FIXTURES = "tests/fixtures"


@pytest.fixture
def contract():
    # allowed_targets: http://localhost:8081, http://host.docker.internal:8081
    return load_contract(f"{FIXTURES}/gauntlet.valid.yaml")


def test_allowed_target_passes(contract):
    assert assert_target_allowed(contract, "http://localhost:8081/api") is None


def test_target_not_in_allowlist_raises(contract):
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed(contract, "https://app.example.com")


def test_destructive_step_requires_confirmation():
    assert confirm_destructive("active scan che scrive", confirm=lambda d: False) is False
    assert confirm_destructive("active scan che scrive", confirm=lambda d: True) is True


# --- Proprietà fail-closed: casi aggiuntivi di confine ---------------------


def test_exact_origin_without_path_passes(contract):
    assert assert_target_allowed(contract, "http://localhost:8081") is None


def test_default_port_is_normalized(contract):
    # http://localhost (porta 80 implicita) NON è http://localhost:8081.
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed(contract, "http://localhost/api")


def test_scheme_mismatch_is_refused(contract):
    # https contro un'origine allow-listata in http: origine diversa, rifiutata.
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed(contract, "https://localhost:8081/api")


def test_different_port_is_refused(contract):
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed(contract, "http://localhost:9000/api")


def test_host_as_substring_is_refused(contract):
    # Un host che contiene "localhost" come sottostringa non deve passare.
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed(contract, "http://localhost:8081.evil.com/api")


def test_host_is_case_insensitive(contract):
    assert assert_target_allowed(contract, "http://LOCALHOST:8081/api") is None


def test_second_allowed_origin_passes(contract):
    assert (
        assert_target_allowed(contract, "http://host.docker.internal:8081/x")
        is None
    )


def test_malformed_target_is_refused(contract):
    # Nessuno schema/host estraibile => fail-closed.
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed(contract, "not-a-url")


def test_confirm_destructive_without_hook_returns_false():
    assert confirm_destructive("qualunque cosa", confirm=None) is False


def test_destructive_not_confirmed_is_exported():
    # L'eccezione fa parte dell'interfaccia pubblica per i chiamanti (Task 3/8).
    assert issubclass(DestructiveNotConfirmed, Exception)


# --- mapping host-side per reachability == "docker" (Task 4b) --------------
#
# In modalità ``docker`` ZAP gira in container e usa ``host.docker.internal``,
# ma lo stesso nome NON risolve sul processo host: ogni connessione host-side
# (sonda TCP del preflight, httpx di login e controllo-accessi) va rimappata su
# 127.0.0.1 per la sola connessione, senza toccare l'URL del contratto/ZAP.


def test_host_side_url_maps_docker_internal_in_docker_mode():
    assert (
        host_side_url("http://host.docker.internal:3000/api/x", "docker")
        == "http://127.0.0.1:3000/api/x"
    )


def test_host_side_url_preserves_scheme_port_path_and_query():
    assert (
        host_side_url(
            "https://host.docker.internal:8443/a/b?q=1#f", "docker"
        )
        == "https://127.0.0.1:8443/a/b?q=1#f"
    )


def test_host_side_url_is_case_insensitive_on_host():
    assert (
        host_side_url("http://HOST.DOCKER.INTERNAL:3000/", "docker")
        == "http://127.0.0.1:3000/"
    )


def test_host_side_url_leaves_localhost_alone_in_docker_mode():
    # Solo host.docker.internal viene rimappato: localhost resta localhost.
    assert (
        host_side_url("http://localhost:8081/api", "docker")
        == "http://localhost:8081/api"
    )


def test_host_side_url_leaves_other_hosts_alone_in_docker_mode():
    assert (
        host_side_url("http://example.com:3000/", "docker")
        == "http://example.com:3000/"
    )


def test_host_side_url_noop_in_non_docker_modes():
    # Fuori da docker il mapping non si applica mai, nemmeno a host.docker.internal.
    for mode in ("localhost", "vpn", ""):
        assert (
            host_side_url("http://host.docker.internal:3000/api", mode)
            == "http://host.docker.internal:3000/api"
        )
