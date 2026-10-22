"""Tests for the project-contract loader (``gauntlet.contract``)."""

import pytest

from gauntlet.contract import ContractError, load_contract, resolve_password

FIXTURES = "tests/fixtures"


def test_load_valid_contract_parses_accounts_and_resolves_env(monkeypatch):
    monkeypatch.setenv("DEMO_A_PW", "secretA")
    c = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    assert c.allowed_targets == [
        "http://localhost:8081",
        "http://host.docker.internal:8081",
    ]
    assert c.accounts[0].label == "cliente_a"
    assert resolve_password(c.accounts[0]) == "secretA"


def test_missing_required_field_raises_contract_error():
    with pytest.raises(ContractError):
        load_contract(f"{FIXTURES}/gauntlet.invalid.yaml")


def test_contract_parses_admin_endpoints(monkeypatch):
    monkeypatch.setenv("DEMO_A_PW", "secretA")
    # Il campo è additivo e opzionale: assente => default lista vuota.
    base = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    assert base.admin_endpoints == []
    # Quando presente nel YAML, viene letto come lista di stringhe.
    c = load_contract(f"{FIXTURES}/gauntlet.admin_endpoints.yaml")
    assert c.admin_endpoints == ["/api/segreto", "/admin"]


# Blocco minimo YAML per un contratto con login `session`: nessun
# password_field/logged_in_indicator, un solo account senza password_env.
_SESSION_YAML = """\
name: demo-session
allowed_targets:
  - http://localhost:8081
reachability: localhost

login:
  method: session
  login_url: http://localhost:8081/login
  username_field: email
  success_cookie: sid

accounts:
  - label: cliente_a
    username: a@example.com
"""


def _write(tmp_path, text):
    """Scrive un contratto YAML temporaneo e ne restituisce il percorso."""
    p = tmp_path / "gauntlet.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_contract_without_redirect_probes_defaults_empty(monkeypatch):
    # Retro-compat: campo assente => lista vuota.
    monkeypatch.setenv("DEMO_A_PW", "secretA")
    c = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    assert c.redirect_probes == []


def test_contract_parses_redirect_probes(tmp_path):
    yaml_text = _SESSION_YAML + (
        "\nredirect_probes:\n"
        "  - /login?next={payload}\n"
        "  - /go?u={payload}\n"
    )
    c = load_contract(_write(tmp_path, yaml_text))
    assert c.redirect_probes == ["/login?next={payload}", "/go?u={payload}"]
    assert all(isinstance(p, str) for p in c.redirect_probes)


def test_session_method_loads_without_password_fields(tmp_path):
    c = load_contract(_write(tmp_path, _SESSION_YAML))
    assert c.login.method == "session"
    assert c.login.success_cookie == "sid"
    # password_field e logged_in_indicator sono facoltativi con `session`:
    # vengono normalizzati a stringa vuota.
    assert c.login.password_field == ""
    assert c.login.logged_in_indicator == ""
    # L'account può non avere password_env (login basato su sessione).
    assert c.accounts[0].password_env is None


def test_session_method_without_success_cookie_raises(tmp_path):
    yaml_text = _SESSION_YAML.replace("  success_cookie: sid\n", "")
    with pytest.raises(ContractError) as exc:
        load_contract(_write(tmp_path, yaml_text))
    assert "success_cookie" in str(exc.value)


def test_resolve_password_returns_empty_when_env_is_none():
    from gauntlet.contract import Account

    account = Account(label="cliente_a", username="a@example.com", password_env=None)
    assert resolve_password(account) == ""


def test_resolve_password_raises_when_env_name_set_but_unset(monkeypatch):
    from gauntlet.contract import Account

    monkeypatch.delenv("NOME_NON_IMPOSTATO", raising=False)
    account = Account(
        label="cliente_a", username="a@example.com", password_env="NOME_NON_IMPOSTATO"
    )
    with pytest.raises(ContractError):
        resolve_password(account)


def test_invalid_method_rejected_and_lists_session(tmp_path):
    yaml_text = _SESSION_YAML.replace("  method: session\n", "  method: pippo\n")
    with pytest.raises(ContractError) as exc:
        load_contract(_write(tmp_path, yaml_text))
    assert "session" in str(exc.value)


def test_contract_without_mass_assignment_defaults_empty(monkeypatch):
    # Retro-compat: campo assente => lista vuota.
    monkeypatch.setenv("DEMO_A_PW", "secretA")
    c = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    assert c.mass_assignment == []


def test_contract_parses_mass_assignment(tmp_path):
    from gauntlet.contract import MassAssignmentProbe

    yaml_text = _SESSION_YAML + (
        "\nmass_assignment:\n"
        "  - url_template: /api/users/{id}\n"
        "    id: 1\n"
        "    forbidden_field: role\n"
        "    forbidden_value: admin\n"
    )
    c = load_contract(_write(tmp_path, yaml_text))
    assert len(c.mass_assignment) == 1
    probe = c.mass_assignment[0]
    assert isinstance(probe, MassAssignmentProbe)
    assert probe.url_template == "/api/users/{id}"
    # id resta coercito a stringa; forbidden_value conserva il tipo YAML/JSON:
    # una stringa resta stringa (retro-compat).
    assert probe.id == "1"
    assert probe.forbidden_field == "role"
    assert probe.forbidden_value == "admin"
    assert isinstance(probe.forbidden_value, str)
    # Default: method == "PATCH", read_template == None.
    assert probe.method == "PATCH"
    assert probe.read_template is None


def test_mass_assignment_overrides_method_and_read_template(tmp_path):
    yaml_text = _SESSION_YAML + (
        "\nmass_assignment:\n"
        "  - url_template: /api/users/{id}\n"
        "    id: 1\n"
        "    forbidden_field: isAdmin\n"
        "    forbidden_value: true\n"
        "    method: PUT\n"
        "    read_template: /api/users/{id}/profile\n"
    )
    c = load_contract(_write(tmp_path, yaml_text))
    probe = c.mass_assignment[0]
    assert probe.method == "PUT"
    assert probe.read_template == "/api/users/{id}/profile"
    # forbidden_value conserva il tipo: un booleano YAML resta un bool Python
    # (``True``), non la stringa ``"True"``, così il corpo JSON è tipizzato.
    assert probe.forbidden_value is True


def test_mass_assignment_forbidden_value_preserves_int(tmp_path):
    # Un intero YAML resta un int Python (non "1"): il corpo JSON è tipizzato.
    yaml_text = _SESSION_YAML + (
        "\nmass_assignment:\n"
        "  - url_template: /api/users/{id}\n"
        "    id: 1\n"
        "    forbidden_field: level\n"
        "    forbidden_value: 1\n"
    )
    c = load_contract(_write(tmp_path, yaml_text))
    probe = c.mass_assignment[0]
    assert probe.forbidden_value == 1
    assert isinstance(probe.forbidden_value, int)
    assert not isinstance(probe.forbidden_value, bool)


def test_mass_assignment_missing_required_field_raises(tmp_path):
    # forbidden_field assente => ContractError che nomina il campo.
    yaml_text = _SESSION_YAML + (
        "\nmass_assignment:\n"
        "  - url_template: /api/users/{id}\n"
        "    id: 1\n"
        "    forbidden_value: admin\n"
    )
    with pytest.raises(ContractError) as exc:
        load_contract(_write(tmp_path, yaml_text))
    assert "forbidden_field" in str(exc.value)


def test_existing_json_contract_still_parses_identically(monkeypatch):
    # Retro-compat: la fixture `json` esistente continua a caricarsi invariata.
    monkeypatch.setenv("DEMO_A_PW", "secretA")
    c = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    assert c.login.method == "json"
    assert c.login.password_field == "password"
    assert c.login.logged_in_indicator == '"token"'
    assert c.login.success_cookie is None
    assert c.accounts[0].password_env == "DEMO_A_PW"
