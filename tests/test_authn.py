"""Test dell'autenticazione (``gauntlet.authn``).

Il focus di review è la **rilevazione del login fallito**: un server che
risponde ``200 OK`` ma *senza* l'indicatore di login non deve mai produrre una
sessione valida, altrimenti una scansione "senza autenticazione" passerebbe per
"tutto a posto". I test usano ``pytest-httpserver`` come server di login finto;
``build_zap_context`` è verificato con un client ZAP mock (l'integrazione reale
è rinviata allo smoke test del Task 9).
"""

from unittest.mock import MagicMock

import pytest
from werkzeug.wrappers import Response

from gauntlet.authn import LoginFailed, Session, build_zap_context, login
from gauntlet.contract import LoginConfig, load_contract
from gauntlet.safety import TargetNotAllowed

FIXTURES = "tests/fixtures"


# --- helper per costruire configurazioni di login ------------------------


def json_login_config(url: str) -> LoginConfig:
    """Config di login JSON: il token sta al top-level ``token``."""
    return LoginConfig(
        method="json",
        login_url=url,
        username_field="email",
        password_field="password",
        logged_in_indicator='"token"',
        token_path="token",
        extra={},
    )


def token_login_config(url: str) -> LoginConfig:
    """Config di login a token con ``token_path`` annidato (dot-path)."""
    return LoginConfig(
        method="token",
        login_url=url,
        username_field="email",
        password_field="password",
        logged_in_indicator='"access"',
        token_path="data.access",
        extra={},
    )


def form_login_config(url: str, indicator: str = "Benvenuto") -> LoginConfig:
    """Config di login a form: cattura i cookie, verifica l'indicatore nel corpo."""
    return LoginConfig(
        method="form",
        login_url=url,
        username_field="user",
        password_field="pass",
        logged_in_indicator=indicator,
        token_path=None,
        extra={},
    )


def session_login_config(
    url: str,
    *,
    success_cookie: str = "sid",
    password_field: str = "password",
    logged_in_indicator: str = "",
    extra: dict | None = None,
) -> LoginConfig:
    """Config di login a sessione-cookie: successo = ``2xx`` + ``success_cookie``.

    ``password_field``/``logged_in_indicator`` possono essere vuoti (corpo
    minimale e nessun controllo di indicatore opzionale).
    """
    return LoginConfig(
        method="session",
        login_url=url,
        username_field="email",
        password_field=password_field,
        logged_in_indicator=logged_in_indicator,
        token_path=None,
        success_cookie=success_cookie,
        extra=extra or {},
    )


# --- i due test del brief ------------------------------------------------


def test_json_login_returns_session_with_token(httpserver):
    # il server finto risponde 200 con {"token": "abc"} all'endpoint di login
    httpserver.expect_request("/auth", method="POST").respond_with_json({"token": "abc"})
    s = login(
        json_login_config(httpserver.url_for("/auth")),
        "a@x.it",
        "pw",
        allowed_targets=[httpserver.url_for("/")],
    )
    assert s.headers["Authorization"] == "Bearer abc"


def test_login_failure_detected_via_indicator(httpserver):
    # Fallimento silenzioso: 200 OK ma senza token né l'indicatore di login.
    httpserver.expect_request("/auth-bad", method="POST").respond_with_json(
        {"error": "invalid credentials"}
    )
    with pytest.raises(LoginFailed):
        login(
            json_login_config(httpserver.url_for("/auth-bad")),
            "a@x.it",
            "wrong",
            allowed_targets=[httpserver.url_for("/")],
        )


# --- varianti di metodo --------------------------------------------------


def test_token_login_extracts_nested_token(httpserver):
    # token_path annidato: data.access
    httpserver.expect_request("/token", method="POST").respond_with_json(
        {"data": {"access": "xyz"}}
    )
    s = login(
        token_login_config(httpserver.url_for("/token")),
        "a@x.it",
        "pw",
        allowed_targets=[httpserver.url_for("/")],
    )
    assert s.headers["Authorization"] == "Bearer xyz"


def test_form_login_captures_cookies_and_verifies_indicator(httpserver):
    httpserver.expect_request("/login", method="POST").respond_with_data(
        "<html><body>Benvenuto, utente</body></html>",
        headers={"Set-Cookie": "session=xyz; Path=/"},
    )
    s = login(
        form_login_config(httpserver.url_for("/login")),
        "u",
        "p",
        allowed_targets=[httpserver.url_for("/")],
    )
    assert isinstance(s, Session)
    assert s.cookies.get("session") == "xyz"
    assert "Authorization" not in s.headers  # il form usa i cookie, non il bearer


def test_form_login_missing_indicator_raises(httpserver):
    # Il form restituisce la pagina di login (credenziali errate): nessun indicatore.
    httpserver.expect_request("/login-bad", method="POST").respond_with_data(
        "<html><body>Credenziali non valide</body></html>"
    )
    with pytest.raises(LoginFailed):
        login(
            form_login_config(httpserver.url_for("/login-bad")),
            "u",
            "wrong",
            allowed_targets=[httpserver.url_for("/")],
        )


def test_json_login_indicator_present_but_token_path_missing_raises(httpserver):
    # L'indicatore '"token"' c'è nel corpo ma il valore al token_path non risolve
    # a un token utilizzabile (null): login non verificabile => LoginFailed.
    httpserver.expect_request("/auth-notoken", method="POST").respond_with_json(
        {"token": None, "note": "risposta con la chiave token ma valore nullo"}
    )
    cfg = json_login_config(httpserver.url_for("/auth-notoken"))
    with pytest.raises(LoginFailed):
        login(cfg, "a@x.it", "pw", allowed_targets=[httpserver.url_for("/")])


def test_login_carries_label_onto_session(httpserver):
    httpserver.expect_request("/auth", method="POST").respond_with_json({"token": "abc"})
    s = login(
        json_login_config(httpserver.url_for("/auth")),
        "a@x.it",
        "pw",
        allowed_targets=[httpserver.url_for("/")],
        label="cliente_a",
    )
    assert s.label == "cliente_a"


def test_login_default_label_is_username(httpserver):
    httpserver.expect_request("/auth", method="POST").respond_with_json({"token": "abc"})
    s = login(
        json_login_config(httpserver.url_for("/auth")),
        "a@x.it",
        "pw",
        allowed_targets=[httpserver.url_for("/")],
    )
    assert s.label == "a@x.it"


# --- gate allowlist fail-closed sull'URL di login ------------------------


def test_login_off_allowlist_url_is_refused_no_credentials_sent(httpserver):
    # login_url la cui origine NON è in allowed_targets: il gate fail-closed
    # deve sollevare TargetNotAllowed PRIMA di inviare le credenziali, così la
    # POST non raggiunge mai l'host non autorizzato.
    httpserver.expect_request("/auth", method="POST").respond_with_json({"token": "abc"})
    cfg = json_login_config(httpserver.url_for("/auth"))

    with pytest.raises(TargetNotAllowed):
        login(cfg, "a@x.it", "pw", allowed_targets=["http://example.invalid:9999"])

    # Nessuna richiesta deve essere arrivata al server finto.
    assert len(httpserver.log) == 0


# --- login a sessione-cookie (method="session") --------------------------


def test_session_login_captures_cookie_on_2xx(httpserver):
    # 204 con Set-Cookie del cookie atteso => Session con quel cookie e headers vuoti.
    httpserver.expect_request("/session", method="POST").respond_with_data(
        "", status=204, headers={"Set-Cookie": "sid=abc123; Path=/"}
    )
    s = login(
        session_login_config(httpserver.url_for("/session"), success_cookie="sid"),
        "a@x.it",
        "pw",
        allowed_targets=[httpserver.url_for("/")],
    )
    assert isinstance(s, Session)
    assert s.cookies.get("sid") == "abc123"
    assert s.headers == {}


def test_session_login_minimal_body_no_password(httpserver):
    # password_field="" e account senza password: il corpo JSON contiene SOLO
    # username_field. Un handler che rifiuta chiavi extra risponde comunque 2xx.
    def handler(request):
        data = request.get_json(force=True, silent=True) or {}
        if "password" in data:
            return Response("chiave password inattesa", status=400)
        return Response("", status=204, headers={"Set-Cookie": "sid=xyz; Path=/"})

    httpserver.expect_request("/session", method="POST").respond_with_handler(handler)
    s = login(
        session_login_config(
            httpserver.url_for("/session"), success_cookie="sid", password_field=""
        ),
        "a@x.it",
        "",  # account senza password dedicata
        allowed_targets=[httpserver.url_for("/")],
    )
    assert s.cookies.get("sid") == "xyz"
    # Il corpo ricevuto contiene solo username_field, nessuna chiave password.
    received = httpserver.log[0][0].get_json(force=True, silent=True) or {}
    assert received == {"email": "a@x.it"}
    assert "password" not in received


def test_session_login_2xx_without_expected_cookie_raises(httpserver):
    # 2xx ma senza il success_cookie atteso => LoginFailed (login non verificabile).
    httpserver.expect_request("/session", method="POST").respond_with_data(
        "", status=200, headers={"Set-Cookie": "other=1; Path=/"}
    )
    with pytest.raises(LoginFailed):
        login(
            session_login_config(httpserver.url_for("/session"), success_cookie="sid"),
            "a@x.it",
            "pw",
            allowed_targets=[httpserver.url_for("/")],
        )


def test_session_login_non_2xx_raises(httpserver):
    # Risposta 4xx/5xx => LoginFailed, anche se arrivasse un Set-Cookie.
    httpserver.expect_request("/session", method="POST").respond_with_data(
        "non autorizzato", status=401, headers={"Set-Cookie": "sid=nope; Path=/"}
    )
    with pytest.raises(LoginFailed):
        login(
            session_login_config(httpserver.url_for("/session"), success_cookie="sid"),
            "a@x.it",
            "wrong",
            allowed_targets=[httpserver.url_for("/")],
        )


def test_session_login_optional_indicator_absent_raises(httpserver):
    # logged_in_indicator non vuoto ma assente dal corpo => LoginFailed, anche con
    # cookie presente (controllo extra opzionale rispettato).
    httpserver.expect_request("/session", method="POST").respond_with_data(
        "<html><body>Credenziali non valide</body></html>",
        status=200,
        headers={"Set-Cookie": "sid=abc; Path=/"},
    )
    cfg = session_login_config(
        httpserver.url_for("/session"),
        success_cookie="sid",
        logged_in_indicator="Benvenuto",
    )
    with pytest.raises(LoginFailed):
        login(cfg, "a@x.it", "pw", allowed_targets=[httpserver.url_for("/")])


def test_session_login_optional_indicator_present_succeeds(httpserver):
    # logged_in_indicator presente nel corpo E cookie atteso => Session valida.
    httpserver.expect_request("/session", method="POST").respond_with_data(
        "<html><body>Benvenuto, utente</body></html>",
        status=200,
        headers={"Set-Cookie": "sid=ok; Path=/"},
    )
    cfg = session_login_config(
        httpserver.url_for("/session"),
        success_cookie="sid",
        logged_in_indicator="Benvenuto",
    )
    s = login(cfg, "a@x.it", "pw", allowed_targets=[httpserver.url_for("/")])
    assert s.cookies.get("sid") == "ok"


def test_session_login_body_format_form_sends_form_encoded(httpserver):
    # extra.body_format == "form" => il corpo è form-encoded (non JSON).
    httpserver.expect_request("/session", method="POST").respond_with_data(
        "", status=204, headers={"Set-Cookie": "sid=f; Path=/"}
    )
    s = login(
        session_login_config(
            httpserver.url_for("/session"),
            success_cookie="sid",
            password_field="password",
            extra={"body_format": "form"},
        ),
        "a@x.it",
        "pw",
        allowed_targets=[httpserver.url_for("/")],
    )
    assert s.cookies.get("sid") == "f"
    req = httpserver.log[0][0]
    assert req.content_type.startswith("application/x-www-form-urlencoded")
    assert req.form.get("email") == "a@x.it"
    assert req.form.get("password") == "pw"


def test_session_login_off_allowlist_url_is_refused_no_request_sent(httpserver):
    # Gate allowlist fail-closed: login_url fuori da allowed_targets =>
    # TargetNotAllowed PRIMA di qualunque invio; il server non riceve nulla.
    httpserver.expect_request("/session", method="POST").respond_with_data(
        "", status=204, headers={"Set-Cookie": "sid=abc; Path=/"}
    )
    cfg = session_login_config(httpserver.url_for("/session"), success_cookie="sid")
    with pytest.raises(TargetNotAllowed):
        login(cfg, "a@x.it", "pw", allowed_targets=["http://example.com:9999"])
    assert len(httpserver.log) == 0


# --- build_zap_context: configurazione del client ZAP (mock) -------------


def test_build_zap_context_configures_client(monkeypatch):
    monkeypatch.setenv("DEMO_A_PW", "secret")
    contract = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    account = contract.accounts[0]

    zap = MagicMock()
    zap.context.new_context.return_value = "7"
    zap.users.new_user.return_value = "3"

    context_id, user_id = build_zap_context(zap, contract, account)

    assert (context_id, user_id) == (7, 3)
    # include per ogni target consentito; exclude per ogni esclusione
    assert zap.context.include_in_context.call_count == len(contract.allowed_targets)
    assert zap.context.exclude_from_context.call_count == len(contract.exclusions)
    # metodo di autenticazione + indicatore di login configurati sul contesto
    zap.authentication.set_authentication_method.assert_called_once()
    assert zap.authentication.set_authentication_method.call_args.args[0] == 7
    zap.authentication.set_logged_in_indicator.assert_called_once()
    # utente forzato attivo
    zap.forcedUser.set_forced_user.assert_called_once_with(7, 3)
    zap.forcedUser.set_forced_user_mode_enabled.assert_called_once_with(True)


def test_build_zap_context_token_uses_script_auth(monkeypatch):
    """Per ``method="token"`` ZAP usa lo script-based auth, non il form-based.

    Verifica che ``script.load`` sia chiamato (installazione dello script di
    token-auth) e che ``set_authentication_method`` usi
    ``scriptBasedAuthentication`` (non ``formBasedAuthentication``), così la
    scansione autenticata funziona anche sulle API a token (JWT crAPI).
    """
    import dataclasses

    monkeypatch.setenv("DEMO_A_PW", "secret")
    base = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    contract = dataclasses.replace(
        base, login=token_login_config("http://localhost:8081/api/auth/login")
    )
    account = contract.accounts[0]

    zap = MagicMock()
    zap.context.new_context.return_value = "7"
    zap.users.new_user.return_value = "3"

    build_zap_context(zap, contract, account)

    # lo script di token-auth è stato caricato in ZAP
    zap.script.load.assert_called_once()
    load_kwargs = zap.script.load.call_args.kwargs
    load_args = zap.script.load.call_args.args
    all_load = list(load_args) + list(load_kwargs.values())
    assert any("token_auth.js" in str(a) for a in all_load)
    assert any("authentication" == str(a) for a in all_load)

    # metodo di autenticazione script-based, NON form-based
    zap.authentication.set_authentication_method.assert_called_once()
    method_name = zap.authentication.set_authentication_method.call_args.args[1]
    assert method_name == "scriptBasedAuthentication"
    assert method_name != "formBasedAuthentication"
    # i parametri referenziano lo script per nome
    params = zap.authentication.set_authentication_method.call_args.args[2]
    assert "scriptName" in params


def test_build_zap_context_token_adds_replacer_rule(monkeypatch):
    """Per ``method="token"`` con ``auth_header`` il contesto usa una regola
    Replacer per iniettare l'header ``Authorization`` (I#2).

    Lo script-based authenticator da solo non basta: la gestione sessione di
    default di ZAP è cookie-based, quindi ``Authorization: Bearer <token>`` non
    verrebbe propagato su spider/active-scan e la scansione "autenticata"
    girerebbe in realtà NON autenticata. La ``headerBasedSessionManagement`` è
    stata validata LIVE come inefficace (header non iniettato). Il meccanismo
    affidabile, validato LIVE, è l'add-on Replacer: una regola ``REQ_HEADER``
    inietta ``Authorization: Bearer <token>`` su ogni richiesta in-context,
    riusando il Bearer già ottenuto via ``authn.login``.
    """
    import dataclasses

    monkeypatch.setenv("DEMO_A_PW", "secret")
    base = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    contract = dataclasses.replace(
        base, login=token_login_config("http://localhost:8081/api/auth/login")
    )
    account = contract.accounts[0]

    zap = MagicMock()
    zap.context.new_context.return_value = "7"
    zap.users.new_user.return_value = "3"

    build_zap_context(zap, contract, account, auth_header="Bearer abc123")

    zap.replacer.add_rule.assert_called_once()
    kwargs = zap.replacer.add_rule.call_args.kwargs
    assert kwargs["matchtype"] == "REQ_HEADER"
    assert kwargs["matchstring"] == "Authorization"
    assert kwargs["replacement"] == "Bearer abc123"
    assert kwargs["enabled"] is True
    # Match letterale (non regex) sul nome header, e nessun filtro di scope:
    # initiators/url vuoti => la regola vale per TUTTI gli initiator e tutti gli
    # URL in-context (contratto "tutto il traffico autenticato").
    assert kwargs["matchregex"] is False
    assert kwargs["initiators"] == ""
    assert kwargs["url"] == ""


def test_build_zap_context_form_does_not_add_replacer_rule(monkeypatch):
    """Per ``form`` la gestione sessione resta al default di ZAP: nessun Replacer.

    Il form authenticator ricava i cookie di sessione tramite il login replay di
    ZAP: la gestione sessione cookie-based di default è corretta e NON va
    integrata con una regola Replacer sull'header ``Authorization``.
    """
    import dataclasses

    monkeypatch.setenv("DEMO_A_PW", "secret")
    base = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    contract = dataclasses.replace(
        base, login=form_login_config("http://localhost:8081/login")
    )
    account = contract.accounts[0]

    zap = MagicMock()
    zap.context.new_context.return_value = "7"
    zap.users.new_user.return_value = "3"

    build_zap_context(zap, contract, account, auth_header="Bearer abc123")

    zap.replacer.add_rule.assert_not_called()


def test_build_zap_context_json_does_not_add_replacer_rule(monkeypatch):
    """Per ``json`` la gestione sessione resta al default di ZAP: nessun Replacer.

    Il json authenticator ricava i cookie di sessione tramite il login replay di
    ZAP: la gestione sessione cookie-based di default è corretta e NON va
    integrata con una regola Replacer sull'header ``Authorization``.
    """
    monkeypatch.setenv("DEMO_A_PW", "secret")
    contract = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")  # login: json
    account = contract.accounts[0]

    zap = MagicMock()
    zap.context.new_context.return_value = "7"
    zap.users.new_user.return_value = "3"

    build_zap_context(zap, contract, account, auth_header="Bearer abc123")

    zap.replacer.add_rule.assert_not_called()


def _session_contract(url: str = "http://localhost:8081/login"):
    """Contratto base del fixture con login a sessione-cookie."""
    import dataclasses

    base = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    return dataclasses.replace(base, login=session_login_config(url))


def test_build_zap_context_session_injects_cookie_and_no_user(monkeypatch):
    """Per ``method="session"`` il contesto inietta il ``Cookie`` via Replacer.

    La sessione è già stata catturata da ``authn.login`` (cookie), quindi ZAP non
    deve rifare il login: nessun metodo di autenticazione, nessun utente/forced
    user. L'header ``Cookie`` catturato viene propagato su spider/active-scan con
    una regola Replacer ``REQ_HEADER``. Il ritorno è ``(context_id, None)``.
    """
    monkeypatch.setenv("DEMO_A_PW", "secret")
    contract = _session_contract()
    account = contract.accounts[0]

    zap = MagicMock()
    zap.context.new_context.return_value = "7"

    context_id, user_id = build_zap_context(
        zap, contract, account, session_cookie="sid=abc"
    )

    assert (context_id, user_id) == (7, None)
    # contesto creato con include/exclude come per gli altri metodi
    assert zap.context.include_in_context.call_count == len(contract.allowed_targets)
    assert zap.context.exclude_from_context.call_count == len(contract.exclusions)
    # regola Replacer sul Cookie catturato
    zap.replacer.add_rule.assert_called_once()
    kwargs = zap.replacer.add_rule.call_args.kwargs
    assert kwargs["matchtype"] == "REQ_HEADER"
    assert kwargs["matchstring"] == "Cookie"
    assert kwargs["replacement"] == "sid=abc"
    assert kwargs["enabled"] is True
    assert kwargs["matchregex"] is False
    assert kwargs["initiators"] == ""
    assert kwargs["url"] == ""
    # nessun metodo di autenticazione, nessun utente, nessun forced user
    zap.authentication.set_authentication_method.assert_not_called()
    zap.users.new_user.assert_not_called()
    zap.forcedUser.set_forced_user.assert_not_called()
    zap.forcedUser.set_forced_user_mode_enabled.assert_not_called()


def test_build_zap_context_session_replacer_failure_does_not_crash(
    monkeypatch, capsys
):
    """Se ``replacer.add_rule`` solleva, il run non crolla e il cookie non trapela.

    Degradazione controllata come per l'iniezione dell'header ``Authorization``:
    l'errore è isolato su ``stderr`` con solo tipo+messaggio dell'eccezione, mai
    il valore del cookie. Il contesto resta creato e il ritorno è coerente.
    """
    monkeypatch.setenv("DEMO_A_PW", "secret")
    contract = _session_contract()
    account = contract.accounts[0]

    zap = MagicMock()
    zap.context.new_context.return_value = "7"
    zap.replacer.add_rule.side_effect = RuntimeError("replacer non disponibile")

    secret_cookie = "sid=supersegretovalore"
    context_id, user_id = build_zap_context(
        zap, contract, account, session_cookie=secret_cookie
    )

    assert (context_id, user_id) == (7, None)
    captured = capsys.readouterr()
    # il valore del cookie non deve MAI comparire nell'output
    assert secret_cookie not in captured.out
    assert secret_cookie not in captured.err
    assert "supersegretovalore" not in captured.out
    assert "supersegretovalore" not in captured.err


def test_build_zap_context_replacer_failure_emits_warning_without_leak(
    monkeypatch, capsys
):
    """Se ``replacer.add_rule`` solleva, su stderr compare l'avviso con il tipo
    dell'eccezione (percorsi cookie/session e token) e mai il valore iniettato."""
    import dataclasses

    monkeypatch.setenv("DEMO_A_PW", "secret")

    def _run(contract, **kwargs):
        zap = MagicMock()
        zap.context.new_context.return_value = "7"
        zap.users.new_user.return_value = "3"
        zap.replacer.add_rule.side_effect = RuntimeError("replacer non disponibile")
        build_zap_context(zap, contract, contract.accounts[0], **kwargs)
        return capsys.readouterr()

    session = _session_contract()
    captured = _run(session, session_cookie="sid=supersegretovalore")
    assert "Attenzione" in captured.err
    assert "Cookie" in captured.err
    assert "RuntimeError" in captured.err
    assert "supersegretovalore" not in captured.out + captured.err

    base = load_contract(f"{FIXTURES}/gauntlet.valid.yaml")
    token = dataclasses.replace(
        base, login=token_login_config("http://localhost:8081/api/auth/login")
    )
    captured = _run(token, auth_header="Bearer supersegretotoken")
    assert "Attenzione" in captured.err
    assert "Authorization" in captured.err
    assert "RuntimeError" in captured.err
    assert "supersegretotoken" not in captured.out + captured.err


# --- host-side mapping per reachability == "docker" (Task 4b) -------------
#
# In docker mode l'URL di login può usare host.docker.internal (serve a ZAP nel
# container), ma il POST host-side deve essere rimappato su 127.0.0.1. Il gate
# allowlist resta però sull'origine ORIGINALE del contratto: nessun bypass.


def test_login_docker_maps_host_internal_for_the_request(httpserver):
    # Il server finto ascolta su 127.0.0.1:PORT; l'URL di login usa
    # host.docker.internal:PORT. In docker mode il POST deve arrivare al server.
    httpserver.expect_request("/auth", method="POST").respond_with_json({"token": "abc"})
    port = httpserver.port
    login_url = f"http://host.docker.internal:{port}/auth"
    allowed = [f"http://host.docker.internal:{port}/"]

    s = login(
        json_login_config(login_url),
        "a@x.it",
        "pw",
        allowed_targets=allowed,
        reachability="docker",
    )
    assert s.headers["Authorization"] == "Bearer abc"


def test_login_docker_off_allowlist_host_still_refused(httpserver):
    # Invariante di sicurezza: anche in docker mode, se host.docker.internal:PORT
    # NON è in allowlist, il login deve essere rifiutato PRIMA di qualunque invio.
    # Il mapping su 127.0.0.1 non deve mai creare un bypass dell'allowlist.
    httpserver.expect_request("/auth", method="POST").respond_with_json({"token": "abc"})
    port = httpserver.port
    login_url = f"http://host.docker.internal:{port}/auth"
    # Allowlist che NON copre host.docker.internal:PORT.
    allowed = ["http://localhost:1"]

    with pytest.raises(TargetNotAllowed):
        login(
            json_login_config(login_url),
            "a@x.it",
            "pw",
            allowed_targets=allowed,
            reachability="docker",
        )
    # Nessuna richiesta deve essere arrivata al server finto.
    assert not httpserver.log
