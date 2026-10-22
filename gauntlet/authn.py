"""Autenticazione: login applicativo e configurazione del contesto ZAP.

Questo modulo porta la scansione *dietro* l'autenticazione. Due responsabilità:

* :func:`login` — automatizza il login applicativo con ``httpx`` (``form`` /
  ``json`` / ``token`` / ``session``) e restituisce una :class:`Session` che il
  tester di controllo-accessi (Task 5) riusa per parlare con l'app come utente
  loggato.
* :func:`build_zap_context` — configura il client ``zapv2`` perché anche ZAP
  scansioni da utente autenticato (contesto con include/exclude, metodo di
  autenticazione, indicatore di login e *forced user*).

Punto critico di sicurezza — **verifica dell'indicatore di login.** Un'app può
rispondere ``200 OK`` anche a credenziali errate (ri-mostra la pagina di login,
restituisce ``{"error": ...}`` senza token, ...). Se accettassimo quella
risposta come sessione valida, l'intera scansione girerebbe *non autenticata* e
il report direbbe "tutto a posto" per le aree protette: un falso negativo
pericoloso. Per questo :func:`login` esige la presenza del
``logged_in_indicator`` (e, per ``json``/``token``, l'effettiva estraibilità del
token) e solleva :class:`LoginFailed` quando manca: il login fallito non degrada
mai silenziosamente in una sessione anonima.

Nota di progettazione sulla firma. Il piano fissa
``login(login, username, password) -> Session`` e indica che la ``Session``
trasporta un ``label``. La firma documentata non ha però un parametro da cui
ricavare quel ``label``. È stato aggiunto il solo parametro **keyword-only
opzionale** ``label`` (default: lo ``username``), così la forma posizionale
documentata resta invariata e l'orchestratore (Task 5) può passare
``account.label`` esplicitamente. Divergenza segnalata per adjudication.
"""

from __future__ import annotations

import json as _json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

from gauntlet.contract import Account, Contract, LoginConfig, resolve_password
from gauntlet.safety import assert_origin_allowed, host_side_url


class LoginFailed(Exception):
    """Sollevata quando il login non è verificabile come riuscito.

    Copre: indicatore di login assente nella risposta, token non estraibile dal
    ``token_path`` e risposte di errore HTTP. È volutamente un fallimento *forte*
    (fail-closed): meglio interrompere il run che scansionare non autenticati
    credendosi autenticati.
    """


@dataclass
class Session:
    """Sessione autenticata da passare al tester di controllo-accessi (Task 5).

    Attributi:
        cookies: cookie di sessione catturati (login a ``form`` o ``session``).
        headers: header da inoltrare, es. ``{"Authorization": "Bearer ..."}``
            per ``json``/``token``.
        label: etichetta dell'account a cui appartiene la sessione.
    """

    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    label: str = ""


def _extract(data: Any, dotted_path: str) -> Any:
    """Estrae un valore annidato seguendo un dot-path (es. ``data.token``).

    Restituisce ``None`` se un segmento manca o se si attraversa un non-dict,
    così il chiamante tratta il token mancante come login fallito.
    """
    current = data
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def _indicator_present(indicator: str, response: httpx.Response) -> bool:
    """Verifica la presenza dell'indicatore di login nella risposta.

    L'indicatore è una stringa letterale cercata nel corpo testuale della
    risposta (es. ``'"token"'`` nel JSON, oppure un messaggio di benvenuto in
    una pagina HTML). Una risposta HTTP di errore (>= 400) non è mai accettata.
    """
    if response.status_code >= 400:
        return False
    return indicator in response.text


def _login_session(
    client: httpx.Client,
    request_url: str,
    login: LoginConfig,
    username: str,
    password: str,
    session_label: str,
) -> Session:
    """Login a sessione-cookie: ``2xx`` + ``success_cookie`` presente nei cookie.

    A differenza di ``form``/``json``/``token``, qui la prova di autenticazione è
    il *cookie di sessione* atteso (``login.success_cookie``), non un token o un
    indicatore nel corpo. Vengono inviati **solo** i campi configurati: il campo
    utente sempre, la password solo se ``password_field`` è valorizzato **e** la
    password non è vuota (corpo minimale per gli account senza password dedicata).
    Un eventuale corpo di base è preso da ``login.extra["body"]``; il formato è
    JSON salvo ``login.extra["body_format"] == "form"``.

    Fail-closed: una risposta ``>= 400``, l'eventuale ``logged_in_indicator`` non
    vuoto ma assente, o il ``success_cookie`` mancante tra i cookie catturati
    sollevano :class:`LoginFailed`. Il messaggio nomina URL e condizione mancante
    (nome del cookie/stato), **mai** il valore del cookie.
    """
    body: dict[str, Any] = dict(login.extra.get("body", {}))
    body[login.username_field] = username
    if login.password_field and password:
        body[login.password_field] = password

    if login.extra.get("body_format") == "form":
        response = client.post(request_url, data=body)
    else:
        response = client.post(request_url, json=body)

    if response.status_code >= 400:
        raise LoginFailed(
            f"Login a sessione su {login.login_url}: risposta di errore "
            f"(status {response.status_code}). Credenziali errate o endpoint "
            "modificato? Interrompo per non scansionare non autenticato."
        )

    if login.logged_in_indicator and not _indicator_present(
        login.logged_in_indicator, response
    ):
        raise LoginFailed(
            f"Login a sessione su {login.login_url}: indicatore "
            f"{login.logged_in_indicator!r} assente nella risposta "
            f"(status {response.status_code}). Login non verificabile."
        )

    cookies = {name: value for name, value in client.cookies.items()}
    if login.success_cookie not in cookies:
        raise LoginFailed(
            f"Login a sessione su {login.login_url}: cookie di sessione atteso "
            f"{login.success_cookie!r} assente tra i cookie ricevuti "
            f"(status {response.status_code}). Login non verificabile."
        )
    return Session(cookies=cookies, headers={}, label=session_label)


def login(
    login: LoginConfig,
    username: str,
    password: str,
    *,
    allowed_targets: list[str],
    label: str | None = None,
    reachability: str = "localhost",
) -> Session:
    """Esegue il login applicativo e restituisce una :class:`Session` verificata.

    * ``form``: invia le credenziali come dati di form, segue gli eventuali
      redirect e cattura i cookie di sessione.
    * ``json`` / ``token``: invia le credenziali come JSON, estrae il token dal
      ``token_path`` (dot-path nel JSON di risposta) e lo mette in
      ``Authorization: Bearer <token>``.
    * ``session``: invia solo i campi configurati (password solo se prevista e
      non vuota) e considera riuscito il login quando la risposta è ``2xx`` e il
      cookie ``login.success_cookie`` è presente; cattura tutti i cookie nella
      :class:`Session` (``headers`` vuoti). Vedi :func:`_login_session`.

    Per ``form``/``json``/``token`` verifica il ``logged_in_indicator`` nella
    risposta; per ``json``/``token`` richiede anche che il token sia
    effettivamente estraibile. Per ``session`` il ``logged_in_indicator`` è un
    controllo opzionale (applicato solo se non vuoto). Se la verifica non passa
    solleva :class:`LoginFailed`.

    **Gate allowlist (fail-closed).** Prima di inviare le credenziali, l'URL di
    login (``login.login_url``, che può essere assoluto e con un'origine
    diversa da quella dei target) è verificato contro ``allowed_targets`` con
    :func:`gauntlet.safety.assert_origin_allowed`. Se l'origine non è in
    allowlist viene sollevata :class:`gauntlet.safety.TargetNotAllowed` e
    **nessuna richiesta parte**: le credenziali non raggiungono mai un host non
    autorizzato.

    :param allowed_targets: allowlist delle origini consentite (di norma
        ``contract.allowed_targets``); l'URL di login deve rientrarvi.
    :param label: etichetta da applicare alla sessione (default: ``username``).
    :param reachability: modalità di raggiungibilità del contratto (``localhost``,
        ``docker``, ``vpn``). In ``docker`` un ``login_url`` su
        ``host.docker.internal`` è rimappato su ``127.0.0.1`` per la **sola**
        richiesta host-side (vedi :func:`gauntlet.safety.host_side_url`); il gate
        allowlist resta valutato sull'URL *originale*, così la rimappatura non
        può mai creare un bypass dell'allowlist.
    """
    # Gate allowlist fail-closed sull'URL ORIGINALE del contratto: un'origine non
    # consentita viene rifiutata PRIMA di qualunque invio e prima di qualsiasi
    # rimappatura host-side (nessun bypass possibile via host.docker.internal).
    assert_origin_allowed(allowed_targets, login.login_url)

    session_label = label if label is not None else username
    # Solo dopo il gate: URL effettivo della connessione host-side (rimappato su
    # 127.0.0.1 in docker mode; invariato altrimenti).
    request_url = host_side_url(login.login_url, reachability)

    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        if login.method == "session":
            return _login_session(
                client, request_url, login, username, password, session_label
            )

        # Calcolate solo sui percorsi che le usano (form/json/token): il ramo
        # ``session`` ritorna sopra senza mai inviare username/password.
        credentials = {login.username_field: username, login.password_field: password}
        if login.method == "form":
            response = client.post(request_url, data=credentials)
        else:  # json | token
            response = client.post(request_url, json=credentials)

        if not _indicator_present(login.logged_in_indicator, response):
            raise LoginFailed(
                f"Login non riuscito su {login.login_url}: indicatore "
                f"{login.logged_in_indicator!r} assente nella risposta "
                f"(status {response.status_code}). Credenziali errate o form "
                "modificato? Interrompo per non scansionare non autenticato."
            )

        if login.method == "form":
            cookies = {name: value for name, value in client.cookies.items()}
            if not cookies:
                raise LoginFailed(
                    f"Login a form su {login.login_url}: indicatore presente ma "
                    "nessun cookie di sessione ricevuto."
                )
            return Session(cookies=cookies, headers={}, label=session_label)

        # json | token: estrazione del token dal corpo JSON.
        try:
            payload = response.json()
        except ValueError as exc:
            raise LoginFailed(
                f"Login su {login.login_url}: risposta non JSON, impossibile "
                "estrarre il token."
            ) from exc

        token_path = login.token_path
        token = _extract(payload, token_path) if token_path else None
        if not token:
            raise LoginFailed(
                f"Login su {login.login_url}: token non trovato al percorso "
                f"{token_path!r} nella risposta. Login non verificabile."
            )

        headers = {"Authorization": f"Bearer {token}"}
        cookies = {name: value for name, value in client.cookies.items()}
        return Session(cookies=cookies, headers=headers, label=session_label)


# --- configurazione del contesto ZAP -------------------------------------

#: Mappa il metodo di login di Gauntlet sul nome del metodo di autenticazione ZAP.
_ZAP_AUTH_METHOD = {
    "form": "formBasedAuthentication",
    "json": "jsonBasedAuthentication",
    # ZAP non ha un metodo nativo "token": si usa uno script di autenticazione
    # (``scriptBasedAuthentication``) che esegue il login token/JSON e inietta
    # ``Authorization: Bearer <token>``. Vedi :func:`_configure_token_script_auth`.
    "token": "scriptBasedAuthentication",
}

#: Nome logico con cui lo script di token-auth viene registrato in ZAP.
_TOKEN_SCRIPT_NAME = "gauntlet-token-auth"

#: Percorso dello script di autenticazione a token (engine ZAP).
_TOKEN_SCRIPT_PATH = Path(__file__).resolve().parent / "zap_scripts" / "token_auth.js"

#: Engine di script ZAP di default per lo script di token-auth. Sovrascrivibile
#: tramite ``login.extra["script_engine"]`` (le versioni recenti di ZAP usano
#: ``"ECMAScript : Graal.js"``; quelle storiche ``"Oracle Nashorn"``).
_DEFAULT_SCRIPT_ENGINE = "Oracle Nashorn"


def _include_regex(target: str) -> str:
    """Regex di inclusione nel contesto per un target consentito (prefisso)."""
    return re.escape(target.rstrip("/")) + ".*"


def _exclude_regex(exclusion: str) -> str:
    """Regex di esclusione dal contesto per un path/URL escluso."""
    return ".*" + re.escape(exclusion) + ".*"


def _auth_method_config(login: LoginConfig) -> str:
    """Costruisce i parametri (URL-encoded) del metodo di autenticazione ZAP.

    I segnaposto ``{%username%}`` / ``{%password%}`` sono quelli attesi da ZAP e
    vengono sostituiti a runtime con le credenziali dell'utente del contesto.
    """
    if login.method == "json":
        request_data = _json.dumps(
            {login.username_field: "{%username%}", login.password_field: "{%password%}"}
        )
    else:  # form | token (ripiegato su form-based)
        request_data = (
            f"{login.username_field}={{%username%}}"
            f"&{login.password_field}={{%password%}}"
        )
    return urlencode({"loginUrl": login.login_url, "loginRequestData": request_data})


def _token_script_params(login: LoginConfig) -> str:
    """Parametri (URL-encoded) del metodo ``scriptBasedAuthentication``.

    Le chiavi devono combaciare con i nomi dichiarati dallo script
    ``token_auth.js`` (``getRequiredParamsNames`` / ``getOptionalParamsNames``):
    ``loginUrl``, ``usernameField``, ``passwordField``, ``tokenPath``. Lo
    ``scriptName`` indica a ZAP quale script di autenticazione eseguire.

    Nota di sicurezza: qui passiamo **solo** la configurazione (URL, nomi dei
    campi, dot-path del token), mai le credenziali né il token — quelli
    arrivano allo script via il meccanismo di credenziali di ZAP (``username``
    / ``password`` dell'utente del contesto).
    """
    return urlencode(
        {
            "scriptName": _TOKEN_SCRIPT_NAME,
            "loginUrl": login.login_url,
            "usernameField": login.username_field,
            "passwordField": login.password_field,
            "tokenPath": login.token_path or "token",
        }
    )


def _configure_token_script_auth(zap: Any, context_id: int, login: LoginConfig) -> None:
    """Installa lo script di token-auth e lo imposta come metodo del contesto.

    Carica ``token_auth.js`` in ZAP come script di tipo ``authentication`` e
    configura il contesto con ``scriptBasedAuthentication``. Lo script esegue il
    login token/JSON e inietta ``Authorization: Bearer <token>`` sulle richieste
    autenticate. Nessun segreto viene scritto da questo codice: lo script riceve
    le credenziali dal meccanismo di ZAP, non in forma hardcoded.
    """
    script_engine = login.extra.get("script_engine", _DEFAULT_SCRIPT_ENGINE)
    zap.script.load(
        scriptname=_TOKEN_SCRIPT_NAME,
        scripttype="authentication",
        scriptengine=script_engine,
        filename=str(_TOKEN_SCRIPT_PATH),
        scriptdescription="Gauntlet token/JSON bearer authentication",
    )
    zap.authentication.set_authentication_method(
        context_id,
        _ZAP_AUTH_METHOD["token"],
        _token_script_params(login),
    )


def _configure_header_injection(
    zap: Any, *, matchstring: str, replacement: str, description: str, warning: str
) -> None:
    """Inietta un header di richiesta via add-on Replacer (regola ``REQ_HEADER``).

    Helper unico per ``Authorization`` (token, fix I#2) e ``Cookie`` (session).
    Lo script-based authenticator / la sessione catturata da :func:`login` da soli
    non bastano: la gestione sessione di default di ZAP è cookie-based e
    ``headerBasedSessionManagement`` è stata validata LIVE come inefficace (header
    non iniettato sulle richieste in-context dello spider). Il meccanismo
    affidabile, validato LIVE, è l'add-on **Replacer**: una regola ``REQ_HEADER``
    inietta l'header su *ogni* richiesta (spider + active-scan), riusando il
    valore già ottenuto via :func:`login` (nessun secondo login lato ZAP).

    ``initiators`` e ``url`` vuoti applicano la regola a tutti gli initiator e a
    tutti gli URL; l'allowlist resta il gate di ciò che viene effettivamente
    scansionato. Un daemon che non supporta il metodo non deve far crollare
    l'intero run: l'errore è isolato e segnalato su ``stderr`` (``warning`` ne
    descrive la conseguenza), ma la configurazione già impostata resta valida.
    Non viene mai stampato ``replacement`` (token/cookie) né i parametri: solo
    tipo e messaggio dell'eccezione.
    """
    try:
        zap.replacer.add_rule(
            description=description,
            enabled=True,
            matchtype="REQ_HEADER",
            matchregex=False,
            matchstring=matchstring,
            replacement=replacement,
            initiators="",
            url="",
        )
    except Exception as exc:  # noqa: BLE001 - degradazione controllata, non crash
        print(
            "Attenzione: impossibile aggiungere la regola Replacer per l'header "
            f"{matchstring} su ZAP ({type(exc).__name__}: {exc}). {warning} "
            "Verificare che l'add-on Replacer sia disponibile.",
            file=sys.stderr,
        )


def build_zap_context(
    zap: Any,
    contract: Contract,
    account: Account,
    *,
    auth_header: str | None = None,
    session_cookie: str | None = None,
) -> tuple[int, int | None]:
    """Configura un contesto ZAP e restituisce ``(context_id, user_id)``.

    Sul client ``zapv2`` passato:

    1. crea un contesto e vi *include* ogni target consentito ed *esclude* ogni
       esclusione del contratto (sempre, per tutti i metodi);
    2. per ``method="session"`` la sessione è già catturata da :func:`login`
       (cookie): non si imposta **alcun** metodo di autenticazione e non si crea
       utente/forced-user; se ``session_cookie`` è fornito si aggiunge una regola
       Replacer ``REQ_HEADER`` che inietta l'header ``Cookie`` su
       spider/active-scan; il ritorno è ``(context_id, None)``;
    3. per gli altri metodi imposta il metodo di autenticazione (derivato da
       ``contract.login``) e l'indicatore di login; per ``method="token"`` carica
       lo script ``token_auth.js`` e usa ``scriptBasedAuthentication`` (login
       token/JSON con iniezione di ``Authorization: Bearer <token>``); se
       ``auth_header`` è fornito, aggiunge inoltre una regola Replacer
       ``REQ_HEADER`` così il Bearer viaggia su spider/active-scan (fix I#2);
    4. per gli altri metodi crea l'utente dall'``account`` (credenziali dalla
       variabile d'ambiente via :func:`resolve_password`), lo abilita e lo
       imposta come *forced user* attivando la modalità forced-user, e
       restituisce ``(context_id, user_id)``.

    :param auth_header: valore completo dell'header ``Authorization`` già
        ottenuto via :func:`login` (es. ``"Bearer <token>"``). Usato **solo**
        per ``method="token"`` per aggiungere la regola Replacer ``REQ_HEADER``.
        Per ``form``/``json`` è ignorato: la gestione sessione resta al default
        cookie-based di ZAP (corretta per quei metodi).
    :param session_cookie: valore completo dell'header ``Cookie`` già catturato
        via :func:`login`. Usato **solo** per ``method="session"`` per aggiungere
        la regola Replacer ``REQ_HEADER``; ignorato dagli altri metodi.

    L'integrazione reale con un daemon ZAP è verificata nello smoke test del
    Task 9; qui la logica di configurazione è unit-testata con un client mock.
    """
    login_cfg = contract.login
    context_name = f"gauntlet-{contract.name}-{account.label}"

    context_id = int(zap.context.new_context(context_name))

    for target in contract.allowed_targets:
        zap.context.include_in_context(context_name, _include_regex(target))
    for exclusion in contract.exclusions:
        zap.context.exclude_from_context(context_name, _exclude_regex(exclusion))

    if login_cfg.method == "session":
        # Sessione già catturata da login(): nessun metodo di autenticazione e
        # nessun utente/forced-user. Si propaga solo l'header Cookie catturato.
        if session_cookie:
            _configure_header_injection(
                zap,
                matchstring="Cookie",
                replacement=session_cookie,
                description="gauntlet-session-cookie",
                warning="La scansione a sessione potrebbe girare NON autenticata.",
            )
        return context_id, None

    if login_cfg.method == "token":
        _configure_token_script_auth(zap, context_id, login_cfg)
        if auth_header:
            _configure_header_injection(
                zap,
                matchstring="Authorization",
                replacement=auth_header,
                description="gauntlet-bearer",
                warning="La scansione a token potrebbe girare NON autenticata.",
            )
    else:
        zap.authentication.set_authentication_method(
            context_id,
            _ZAP_AUTH_METHOD[login_cfg.method],
            _auth_method_config(login_cfg),
        )
    zap.authentication.set_logged_in_indicator(
        context_id, re.escape(login_cfg.logged_in_indicator)
    )

    user_id = int(zap.users.new_user(context_id, account.label))
    creds = urlencode(
        {"username": account.username, "password": resolve_password(account)}
    )
    zap.users.set_authentication_credentials(context_id, user_id, creds)
    zap.users.set_user_enabled(context_id, user_id, True)

    zap.forcedUser.set_forced_user(context_id, user_id)
    zap.forcedUser.set_forced_user_mode_enabled(True)

    return context_id, user_id
