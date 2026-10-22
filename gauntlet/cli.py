"""Ingresso CLI di Gauntlet: cabla tutti i sottosistemi in un unico run.

Questo modulo è l'orchestratore. :func:`run` prende un progetto e un *livello di
conoscenza dell'attaccante* (1–4, vedi :mod:`gauntlet.levels`) e, nell'ordine:

1. carica il contratto da ``<project>/gauntlet.yaml``
   (:func:`gauntlet.contract.load_contract`);
2. esegue il **preflight** (:func:`gauntlet.preflight.run`): se l'ambiente non è
   pronto o mancano gli account di prova, interrompe sollevando
   :class:`PreflightError` con problemi e guida da mostrare all'utente — non si
   invia mai traffico quando il preflight non passa;
3. traduce il livello in un piano di azioni (:func:`gauntlet.levels.actions_for`);
4. avvia il daemon ZAP (:class:`gauntlet.zap_runner.ZapRunner`) **passando il
   contratto e l'hook ``confirm``**: così il gate allowlist e la conferma per i
   passi distruttivi restano attivi dentro il runner;
5. ai livelli autenticati fa il login applicativo di ogni account
   (:func:`gauntlet.authn.login`) e configura il contesto ZAP autenticato
   (:func:`gauntlet.authn.build_zap_context`);
6. esegue spider / scansione passiva / scan attivo / controllo-accessi secondo
   il piano e la modalità, raccoglie i :class:`~gauntlet.models.Finding`;
7. scrive il report nel progetto (:func:`gauntlet.report.write_report`) e ne
   restituisce il percorso.

L'esecuzione è **automatica**, senza prompt passo per passo. Il flag
``aggressive`` è l'unico consenso (a lotto, upfront) e separa due modalità:

* **default (non distruttivo):** gira lo **spider** ZAP e ci si affida alla
  **scansione passiva** (gli alert nascono dal traffico dello spider) più i
  controlli di controllo-accessi in sola lettura. Lo scan attivo **non** parte:
  nessun payload intrusivo viene inviato.
* **``aggressive=True`` (distruttivo):** oltre a quanto sopra parte anche lo
  **scan attivo** di ZAP (payload intrusivi: SQLi, command injection, ecc.) e
  le scritture cross-tenant del controllo-accessi; l'hook ``confirm`` le approva.

In nessun caso cambia il perimetro: il traffico parte solo per i target in
``allowed_targets``, garantiti dall'allowlist fail-closed, che gatea anche ogni
endpoint scoperto prima di usarlo come seed.
"""

from __future__ import annotations

import argparse
import secrets
import socket
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests  # dipendenza transitiva di zaproxy: le sue eccezioni di rete

from gauntlet import (
    access_control,
    cors_checks,
    error_disclosure_checks,
    jwt_checks,
    mass_assignment_checks,
    open_redirect_checks,
    preflight,
    ratelimit_checks,
)
from gauntlet.authn import Session, build_zap_context, login
from gauntlet.contract import Contract, load_contract, resolve_password
from gauntlet.discovery import Endpoint, discover
from gauntlet.i18n import resolve_language, t
from gauntlet.levels import actions_for
from gauntlet.models import Finding
from gauntlet.report import write_report
from gauntlet.safety import TargetNotAllowed, assert_target_allowed
from gauntlet.zap_runner import ZapRunner

#: Nome del file di contratto cercato nella cartella del progetto.
CONTRACT_FILENAME = "gauntlet.yaml"


def pick_free_port() -> int:
    """Restituisce una porta TCP libera scelta dal sistema operativo.

    Binda un socket su ``("", 0)``: il kernel assegna una porta effimera libera,
    che viene letta e restituita dopo aver chiuso il socket. Serve a evitare la
    collisione del daemon ZAP con altri container già in ascolto su una porta
    fissa (es. 8080). C'è una piccola finestra TOCTOU tra la chiusura del socket
    e il successivo ``docker run`` sulla porta: accettabile per l'uso locale.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        return sock.getsockname()[1]


class PreflightError(Exception):
    """Sollevata quando il preflight non passa: il run viene interrotto.

    Il messaggio raccoglie i problemi riscontrati e, se presente, la guida alla
    creazione degli account di prova (``account_guidance``), così chi lancia la
    skill sa esattamente cosa sistemare prima di riprovare.
    """


def _format_preflight_failure(result: preflight.PreflightResult, lang: str = "it") -> str:
    """Compone un messaggio leggibile dai problemi e dalla guida del preflight.

    L'intestazione è localizzata (``lang``); i problemi e la guida restano come li
    fornisce il preflight (contenuto dinamico, non tradotto qui).
    """
    righe = [t(lang, "cli_preflight_failed")]
    for problema in result.problems:
        righe.append(f"  - {problema}")
    if result.account_guidance:
        righe.append("")
        righe.append(result.account_guidance)
    return "\n".join(righe)


def _base_url(contract: Contract) -> str:
    """Origine di riferimento del run: il primo target consentito.

    Serve al tester di controllo-accessi per risolvere gli ``url_template``
    scritti come path relativi e per sondare gli endpoint admin sullo stesso
    host dell'applicazione.
    """
    return contract.allowed_targets[0]


def _seed_url(base_url: str, path: str) -> str:
    """Costruisce l'URL di un endpoint scoperto a partire dall'origine base.

    Un ``path`` relativo (es. ``/api/users``) viene appeso all'origine base del
    contratto; un ``path`` già assoluto (con schema, es. ``http://host/x``) è
    usato così com'è. In entrambi i casi l'URL risultante **deve poi** passare il
    gate allowlist prima di qualunque uso: un path assoluto che punta fuori host
    verrà quindi scartato da :func:`gauntlet.safety.assert_target_allowed`.
    """
    if urlsplit(path).scheme:
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")


#: Id deliberatamente malformati sostituiti nei template delle risorse seminate
#: per sondare la divulgazione di errori/stack trace: un apice (rompe le query),
#: un byte nullo url-encoded e una stringa molto lunga (overflow di buffer/campo).
_MALFORMED_IDS: tuple[str, ...] = ("'", "%00gauntlet", "g" * 300)


def _error_probe_urls(base_url: str, resources: list) -> list[str]:
    """URL di sonda per la divulgazione di errori, da risorse seminate.

    Per ogni risorsa con ``{id}`` nel template, sostituisce l'id con ciascun id
    malformato di :data:`_MALFORMED_IDS` e risolve l'URL sull'origine base. Le
    risorse senza ``{id}`` sono saltate (non c'è id da malformare). Gli URL
    restano poi soggetti al gate allowlist dentro ``error_disclosure_checks.run``.
    """
    urls: list[str] = []
    for resource in resources:
        template = resource.url_template
        if "{id}" not in template:
            continue
        for bad_id in _MALFORMED_IDS:
            urls.append(_seed_url(base_url, template.format(id=bad_id)))
    return urls


def _gated_seeds(
    contract: Contract, base_url: str, endpoints: list[Endpoint]
) -> tuple[list[str], list[Endpoint]]:
    """Filtra gli endpoint scoperti tenendo solo quelli in allowlist.

    Per ogni endpoint costruisce l'URL (:func:`_seed_url`) e lo sottopone al gate
    allowlist **fail-closed**: le origini non consentite vengono semplicemente
    saltate, senza che parta alcun traffico. Restituisce la coppia
    ``(url consentiti, endpoint consentiti)``, preservando l'ordine.
    """
    seed_urls: list[str] = []
    allowed: list[Endpoint] = []
    for endpoint in endpoints:
        url = _seed_url(base_url, endpoint.path)
        try:
            assert_target_allowed(contract, url)
        except TargetNotAllowed:
            # Fail-closed: un seed fuori allowlist non viene mai usato.
            continue
        seed_urls.append(url)
        allowed.append(endpoint)
    return seed_urls, allowed


def _discovery_finding(endpoints: list[Endpoint], lang: str = "it") -> Finding:
    """Finding **informativo** sulla superficie scoperta da doc/sorgente.

    Gli endpoint scoperti (e consentiti dall'allowlist) sono stati aggiunti come
    seed alla scansione ZAP. Questo finding li elenca per trasparenza: è sempre
    ``severity="info"``, perché un endpoint meramente scoperto — privo di
    proprietario e di marcatore — non è di per sé una vulnerabilità e non deve
    mai diventare un finding di controllo-accessi (nessuna ``alta``/``critica``).
    """
    righe = "\n".join(f"- {ep.method} {ep.path} ({ep.source})" for ep in endpoints)
    return Finding(
        source="zap",
        severity="info",
        title=t(lang, "cli_discovery_title"),
        description=t(lang, "cli_discovery_desc", count=len(endpoints)),
        evidence=t(lang, "cli_discovery_evidence", righe=righe),
        fix=t(lang, "cli_discovery_fix"),
        impact_if_ignored=t(lang, "cli_discovery_impact"),
        confidence=1.0,
        url=None,
    )


def run(
    project_path: str,
    level: int,
    aggressive: bool = False,
    zap_port: int | None = None,
    report_lang: str | None = None,
) -> Path:
    """Esegue un run completo di Gauntlet sul progetto e scrive il report.

    L'esecuzione è **automatica**: non c'è alcuna richiesta interattiva passo per
    passo. Il flag ``aggressive`` è l'unico consenso (a lotto, upfront) e si
    traduce in un hook di conferma costante inoltrato ai moduli:

    * ``aggressive=False`` (default, **non distruttivo**): gira lo spider ZAP e
      ci si affida alla scansione passiva (gli alert nascono dal traffico dello
      spider) più i controlli di controllo-accessi in sola lettura. Lo scan
      attivo **non** viene lanciato: nessun payload intrusivo parte;
    * ``aggressive=True`` (**distruttivo**): oltre a quanto sopra parte anche lo
      scan attivo di ZAP (payload intrusivi) e le scritture cross-tenant;
      l'hook approva i passi distruttivi. **Invariante:** questo non allarga in
      alcun modo il perimetro dei bersagli — l'allowlist fail-closed continua a
      gatear ogni singola richiesta.

    Ai livelli con ``uses_docs``/``uses_source`` (3 e 4) viene invocata la
    :func:`gauntlet.discovery.discover`; gli endpoint scoperti, costruiti
    sull'origine base del contratto e **gateati uno per uno dall'allowlist**,
    sono aggiunti come seed URL alla scansione ZAP e riportati come voce
    **informativa**. Non sono inoltrati al tester di controllo-accessi: privi di
    proprietario e di marcatore non sono endpoint admin (test verticale) né
    hanno un oracolo di proprietà (test orizzontale), quindi la discovery non
    può e non deve mai fabbricare un finding di controllo-accessi.

    Args:
        project_path: cartella del progetto che contiene ``gauntlet.yaml``.
        level: livello di conoscenza dell'attaccante (1–4).
        aggressive: se abilitare i passi distruttivi (consenso a lotto upfront).
        zap_port: porta su cui esporre il daemon ZAP. Se ``None`` (default) ne
            viene scelta una libera con :func:`pick_free_port`, così da non
            collidere con altri container già in ascolto (es. sulla 8080).
        report_lang: lingua del report. ``None``/``"auto"`` rileva quella di
            sistema (ripiego inglese se non supportata); ``"it"``/``"en"`` la
            forzano. Risolta una sola volta con
            :func:`gauntlet.i18n.resolve_language` e propagata ai finding nostri
            e al report.

    Returns:
        Il :class:`pathlib.Path` del ``report.md`` scritto nel progetto.

    Raises:
        gauntlet.contract.ContractError: contratto assente o malformato.
        PreflightError: ambiente non pronto o account di prova mancanti.
        ValueError: livello fuori dall'intervallo 1–4.
    """
    project = Path(project_path)
    # Lingua del report risolta una sola volta e propagata ovunque si producano
    # stringhe nostre (finding del controllo-accessi, voce di discovery, report).
    lang = resolve_language(report_lang)
    contract = load_contract(str(project / CONTRACT_FILENAME))

    # Il livello guida tutto il resto; validato qui (solleva ValueError se fuori 1–4).
    plan = actions_for(level)

    # Gate d'ingresso: niente traffico se l'ambiente non è pronto.
    pf = preflight.run(contract, level)
    if not pf.ok:
        raise PreflightError(_format_preflight_failure(pf, lang))

    base_url = _base_url(contract)
    findings: list[Finding] = []
    sessions: dict[str, Session] = {}

    # Consenso a lotto: l'hook di conferma è una costante derivata dal flag.
    confirm = (lambda _description: True) if aggressive else (lambda _description: False)

    # Discovery degli endpoint ai livelli che la prevedono (3: docs; 4: + source).
    # Ogni endpoint è poi gateato dall'allowlist prima di diventare un seed.
    discovered: list[Endpoint] = []
    if plan.uses_docs or plan.uses_source:
        discovered = discover(
            contract.docs_path,
            contract.src_path,
            use_docs=plan.uses_docs,
            use_source=plan.uses_source,
        )
    # Gli endpoint scoperti diventano SOLO seed per ZAP (già gateati). Non sono
    # inoltrati al controllo-accessi: senza proprietario né marcatore non possono
    # alimentare in modo sano né il test verticale (non sono admin) né quello
    # orizzontale (nessun oracolo). La loro unica traccia non-ZAP è informativa.
    seed_urls, allowed_endpoints = _gated_seeds(contract, base_url, discovered)

    api_key = secrets.token_hex(16)
    # Porta del daemon ZAP: quella richiesta dal chiamante, altrimenti una libera
    # scelta a runtime per evitare collisioni con altri container.
    chosen_port = zap_port if zap_port is not None else pick_free_port()
    # Motivo dell'eventuale interruzione operativa di ZAP (daemon caduto a metà
    # scan). Resta None nel caso felice; se valorizzato finisce in meta e segnala
    # al report che la copertura ZAP è parziale.
    zap_interrotto: str | None = None
    with ZapRunner(
        api_key, port=chosen_port, contract=contract, confirm=confirm
    ) as zap:
        # Contesto autenticato: ai livelli >= 2 si autenticano tutti gli account
        # (servono entrambi al controllo-accessi cross-tenant) e si costruisce il
        # contesto ZAP del primo, con cui spider/scan girano "da utente loggato".
        context_id: int | None = None
        user_id: int | None = None
        if plan.authenticated:
            for account in contract.accounts:
                password = resolve_password(account)
                sessions[account.label] = login(
                    contract.login,
                    account.username,
                    password,
                    allowed_targets=contract.allowed_targets,
                    label=account.label,
                    reachability=contract.reachability,
                )
            primary = contract.accounts[0]
            # Header Authorization già ottenuto via login() per l'account
            # primario: lo riusiamo in una regola Replacer di ZAP così il Bearer
            # viaggia su spider/active-scan (fix I#2). È None per i login form
            # (cookie-based) e build_zap_context lo usa solo per i login a token.
            auth_header = sessions[primary.label].headers.get("Authorization")
            # Login a sessione (cookie-based): costruiamo la stringa Cookie
            # dell'account primario dai suoi cookie catturati da login() e la
            # passiamo a build_zap_context, che la inietta via regola Replacer
            # così i cookie viaggiano su spider/active-scan. Per gli altri metodi
            # resta None (la gestione sessione è a token o al default di ZAP).
            session_cookie: str | None = None
            if contract.login.method == "session":
                session_cookie = "; ".join(
                    f"{k}={v}" for k, v in sessions[primary.label].cookies.items()
                )
            # build_zap_context lavora sul client zapv2 grezzo (zap.context,
            # zap.authentication, ...), non sui metodi di ZapRunner: va passato
            # il client vivo, non l'istanza del runner (Task 4f). Per il metodo
            # "session" ritorna user_id=None (nessun utente/forced-user ZAP);
            # spider/active_scan accettano già None.
            context_id, user_id = build_zap_context(
                zap.client,
                contract,
                primary,
                auth_header=auth_header,
                session_cookie=session_cookie,
            )

        # Solo le operazioni ZAP (traffico verso il daemon in Docker) sono avvolte
        # qui: se il daemon muore a metà scan — tipicamente sotto pressione di
        # memoria durante lo scan attivo — ``zapv2`` propaga una
        # ``requests.exceptions.RequestException`` (ProxyError/ConnectionError/
        # RemoteDisconnected). La conteniamo per NON perdere i controlli httpx a
        # valle (controllo-accessi, CORS, JWT, ecc.) e scrivere comunque un report
        # parziale. Restano FATALI: la violazione di allowlist (TargetNotAllowed) e
        # la mancata conferma distruttiva (DestructiveNotConfirmed), che non sono
        # RequestException e devono fermare il run. login/build_zap_context sono
        # fuori da questo try: i loro fallimenti (incl. login fail-closed) restano fatali.
        try:
            # Spider su ogni origine consentita e su ogni seed scoperto (già gateato
            # dall'allowlist): genera traffico non distruttivo che alimenta la
            # scansione passiva. Lo scan attivo (payload intrusivi: SQLi, command
            # injection, ecc.) è DISTRUTTIVO e parte SOLO in modalità aggressive;
            # di default ci si affida a spider + scansione passiva, così un run
            # standard resta non distruttivo ma produce comunque alert passivi.
            for target in list(contract.allowed_targets) + seed_urls:
                if plan.run_spider:
                    zap.spider(target, context_id, user_id)
                if plan.run_active and aggressive:
                    zap.active_scan(
                        target, context_id, user_id, destructive=True
                    )

            # Raccolta degli alert ZAP, una lettura per origine consentita (i seed
            # sono sotto-path delle origini in allowlist, già coperti da questa lettura).
            for target in contract.allowed_targets:
                findings.extend(zap.alerts(target))
        except requests.exceptions.RequestException as exc:
            # Solo tipo + messaggio: nessun traceback, nessun segreto (gli errori
            # di rete di ZAP non trasportano credenziali).
            zap_interrotto = f"{type(exc).__name__}: {exc}"
            print(
                f"Avviso: il daemon ZAP si è interrotto durante la scansione "
                f"({zap_interrotto}). Il run prosegue con copertura ZAP parziale.",
                file=sys.stderr,
            )

    # Controllo-accessi cross-tenant: fuori dal contesto ZAP, usa sessioni httpx.
    # In aggressive il tester gira in modalità write (scritture dietro confirm).
    if plan.run_access_control:
        findings.extend(
            access_control.run(
                sessions,
                contract.accounts,
                contract,
                mode="write" if aggressive else "read-only",
                confirm=confirm,
                base_url=base_url,
                lang=lang,
            )
        )

    # Configurazione CORS: controllo deterministico e non distruttivo (solo GET)
    # sulle origini consentite più quella di login. Non dipende
    # dall'autenticazione, quindi gira a QUALSIASI livello (anche il livello 1
    # cieco). Ogni richiesta resta sotto il gate allowlist fail-closed di
    # cors_checks.run.
    findings.extend(
        cors_checks.run(
            contract.allowed_targets,
            contract,
            contract.reachability,
            lang=lang,
        )
    )

    # Open redirect: controllo deterministico con oracolo canary sull'header
    # Location. Come il CORS non dipende dall'autenticazione, quindi gira a
    # QUALSIASI livello (anche il livello 1 cieco); sonda però solo se il
    # contratto dichiara `redirect_probes` (lista vuota => il modulo non invia
    # alcuna richiesta). Ai livelli autenticati inoltra header e cookie della
    # sessione primaria — come i blocchi JWT/error-disclosure con
    # `sessions.get(primary.label)` — così le sonde vedono anche le pagine dietro
    # login; altrimenti None per entrambi. Ogni URL resta sotto il gate allowlist
    # fail-closed di open_redirect_checks.run.
    redirect_headers: dict[str, str] | None = None
    redirect_cookies: dict[str, str] | None = None
    if plan.authenticated and sessions:
        primary = contract.accounts[0]
        primary_session = sessions.get(primary.label)
        if primary_session is not None:
            redirect_headers = primary_session.headers or None
            redirect_cookies = primary_session.cookies or None
    findings.extend(
        open_redirect_checks.run(
            base_url,
            contract,
            contract.reachability,
            session_headers=redirect_headers,
            session_cookies=redirect_cookies,
            lang=lang,
        )
    )

    # Debolezze JWT: ai livelli autenticati, solo per login a token (il bearer
    # è un JWT reale), si testano alg=none e secret HMAC debole sull'account
    # primario, usando una sua risorsa seminata come sonda. Non distruttivo (solo
    # GET) e sempre dietro il gate allowlist di jwt_checks.run. Se il primario non
    # ha risorse seminate o non ha una sessione, si salta senza rumore.
    if plan.authenticated and contract.login.method == "token" and sessions:
        primary = contract.accounts[0]
        primary_session = sessions.get(primary.label)
        if primary_session is not None and primary.seeded_resources:
            bearer = primary_session.headers.get("Authorization", "") or ""
            token = bearer[len("Bearer ") :] if bearer.startswith("Bearer ") else bearer
            resource = primary.seeded_resources[0]
            raw_url = (
                resource.url_template.format(id=resource.id)
                if "{id}" in resource.url_template
                else resource.url_template
            )
            probe_url = _seed_url(base_url, raw_url)
            findings.extend(
                jwt_checks.run(
                    token=token,
                    probe_url=probe_url,
                    marker=resource.seed_marker,
                    session_headers=primary_session.headers,
                    contract=contract,
                    reachability=contract.reachability,
                    lang=lang,
                )
            )

    # Divulgazione di errori/stack trace: ai livelli autenticati, read-only e di
    # default. Il chiamante costruisce le sonde dalle risorse seminate del
    # primario sostituendo l'id con id deliberatamente malformati; le GET sono
    # fatte come proprietario e ogni URL resta sotto il gate allowlist di
    # error_disclosure_checks.run. Rilevamento basato su pattern (confidenza 0.7).
    if plan.authenticated and sessions:
        primary = contract.accounts[0]
        primary_session = sessions.get(primary.label)
        if primary_session is not None and primary.seeded_resources:
            probe_urls = _error_probe_urls(base_url, primary.seeded_resources)
            if probe_urls:
                findings.extend(
                    error_disclosure_checks.run(
                        probe_urls,
                        primary_session.headers,
                        contract=contract,
                        reachability=contract.reachability,
                        lang=lang,
                    )
                )

    # Assenza di rate limiting sul login: AGGRESSIVE-ONLY. Invia pochi tentativi
    # di login FALLITI (password sonda errata, mai autenticazione reale): ripetuti
    # fallimenti possono innescare lockout, quindi è destructive-ish e gira SOLO
    # in aggressive (consenso a lotto upfront), mai di default. Allowlist-gated su
    # login_url dentro ratelimit_checks.run. Osservazione su N tentativi
    # (confidenza 0.6): se compare un 429/throttling non segnala nulla.
    if aggressive and contract.accounts:
        findings.extend(
            ratelimit_checks.run(
                contract.login,
                contract.accounts[0].username,
                contract=contract,
                reachability=contract.reachability,
                lang=lang,
            )
        )

    # Assegnazione di massa (mass assignment): AGGRESSIVE-ONLY e autenticato.
    # Scrive un campo PROTETTO dichiarato dal contratto e rilegge la risorsa
    # (oracolo deterministico write + re-GET): è DISTRUTTIVO, quindi gira SOLO in
    # aggressive (consenso a lotto upfront) e SOLO se il contratto dichiara
    # `mass_assignment` (altrimenti il modulo non parte). Inoltra header e cookie
    # della sessione primaria come i blocchi JWT/error-disclosure
    # (`sessions.get(primary.label)`), così le scritture viaggiano da proprietario.
    # `confirm` (True in aggressive) gatea ogni scrittura dentro
    # mass_assignment_checks.run; ogni URL resta sotto il gate allowlist fail-closed.
    if aggressive and plan.authenticated and sessions and contract.mass_assignment:
        primary = contract.accounts[0]
        primary_session = sessions.get(primary.label)
        ma_headers: dict[str, str] | None = None
        ma_cookies: dict[str, str] | None = None
        if primary_session is not None:
            ma_headers = primary_session.headers or None
            ma_cookies = primary_session.cookies or None
        findings.extend(
            mass_assignment_checks.run(
                base_url,
                contract,
                contract.reachability,
                session_headers=ma_headers,
                session_cookies=ma_cookies,
                confirm=confirm,
                lang=lang,
            )
        )

    # Traccia informativa della superficie aggiuntiva scoperta e data in pasto a
    # ZAP: niente gravità oltre 'info', la discovery non fabbrica mai un finding
    # di controllo-accessi.
    if allowed_endpoints:
        findings.append(_discovery_finding(allowed_endpoints, lang))

    meta = {
        "livello": level,
        "target": ", ".join(contract.allowed_targets),
        "data": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "aggressive": aggressive,
        "endpoint_scoperti": [f"{ep.method} {ep.path} ({ep.source})" for ep in discovered],
        # Incluso SOLO se ZAP si è interrotto: nel caso felice la chiave non compare
        # (intestazione del report byte-identica allo storico).
        **({"zap_interrotto": zap_interrotto} if zap_interrotto else {}),
    }
    return write_report(findings, str(project), meta, lang=lang)


def main(argv: list[str] | None = None) -> int:
    """Punto d'ingresso da riga di comando.

    Uso: ``python -m gauntlet run --project <path> --level <N> [--aggressive]``.

    Returns:
        Codice di uscita: ``0`` in caso di successo, ``1`` su errore gestito
        (contratto non valido o preflight fallito), con il dettaglio su stderr.
    """
    parser = argparse.ArgumentParser(
        prog="gauntlet",
        description="Security-testing (DAST) guidato da contratto per app web.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Esegue un run completo su un progetto.")
    run_p.add_argument(
        "--project",
        required=True,
        help="Cartella del progetto che contiene gauntlet.yaml.",
    )
    run_p.add_argument(
        "--level",
        required=True,
        type=int,
        choices=(1, 2, 3, 4),
        help="Livello di conoscenza dell'attaccante: 1 cieco … 4 sorgente.",
    )
    run_p.add_argument(
        "--zap-port",
        type=int,
        default=None,
        help=(
            "Porta per il daemon ZAP. Se omessa ne viene scelta una libera, "
            "evitando collisioni con altri container (es. sulla 8080)."
        ),
    )
    run_p.add_argument(
        "--report-lang",
        choices=("auto", "it", "en"),
        default="auto",
        help=(
            "Lingua del report: 'auto' (default) rileva quella di sistema e "
            "ripiega sull'inglese se non supportata; 'it'/'en' la forzano."
        ),
    )
    run_p.add_argument(
        "--aggressive",
        action="store_true",
        help=(
            "Abilita i passi distruttivi (scan attivo distruttivo, scritture "
            "cross-tenant): consenso a lotto upfront. Senza questo flag girano "
            "solo gli attacchi non distruttivi. Non allarga mai l'allowlist."
        ),
    )

    args = parser.parse_args(argv)

    if args.command == "run":
        # Lingua risolta come nel run, per localizzare anche l'output di main
        # (riga di successo / errore). Default "it" byte-identico allo storico.
        lang = resolve_language(args.report_lang)
        try:
            path = run(
                args.project,
                args.level,
                aggressive=args.aggressive,
                zap_port=args.zap_port,
                report_lang=args.report_lang,
            )
        except Exception as exc:  # errori gestiti: messaggio pulito, non traceback.
            print(t(lang, "cli_error", exc=exc), file=sys.stderr)
            return 1
        print(t(lang, "cli_report_written", path=path))
        return 0

    # argparse garantisce un comando valido; difesa in profondità.
    parser.error("comando non riconosciuto")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
