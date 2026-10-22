"""Controllo deterministico della configurazione CORS.

Il *Cross-Origin Resource Sharing* mal configurato permette a un sito di terze
parti di leggere, via browser, le risposte di un'API — nei casi peggiori anche
quelle autenticate con i cookie della vittima. Questo modulo lo rileva **senza
indovinare**: invia a ogni origine una GET con un header ``Origin`` chiaramente
**estraneo** (:data:`PROBE_ORIGIN`) e giudica solo in base agli header CORS
restituiti.

Oracolo (deterministico, basato sugli header di risposta):

* ``Access-Control-Allow-Origin`` riflette l'origine della sonda **e**
  ``Access-Control-Allow-Credentials: true`` => **critica** (bypass cross-origin
  con credenziali: qualsiasi sito può leggere le risposte autenticate).
* ACAO riflette l'origine della sonda, senza credenziali => **alta**.
* ACAO == ``*`` (wildcard) => **media** (permissivo; i browser ignorano le
  credenziali quando l'origine è ``*``).
* Altrimenti => nessun finding.

Un server CORS **corretto** non riflette mai un'origine estranea (al più ne
riflette una *configurata* come fidata, che non è la nostra sonda): perciò non
produce alcun finding. Nessun falso positivo sul solo fatto di rispondere.

**Sicurezza.** Prima di ogni richiesta si passa dal gate allowlist fail-closed
(:func:`gauntlet.safety.assert_target_allowed`): un'origine fuori allowlist non
genera traffico. La connessione host-side effettiva usa la rimappatura docker
(:func:`gauntlet.safety.host_side_url`) *dopo* il gate, come il resto della
skill. Il modulo è **non distruttivo**: solo richieste GET.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import httpx

from gauntlet.contract import Contract
from gauntlet.i18n import t
from gauntlet.models import Finding
from gauntlet.safety import TargetNotAllowed, assert_target_allowed, host_side_url

#: Origine della sonda: volutamente estranea e non registrabile (dominio di
#: esempio riservato da RFC 2606). Un server corretto non la rifletterà mai; se
#: la riflette, la riflessione è indiscriminata (bug), non una scelta di
#: allowlist. È l'oracolo del controllo.
PROBE_ORIGIN = "https://gauntlet-cors-probe.example"

#: Header CORS ispezionati.
_ACAO = "Access-Control-Allow-Origin"
_ACAC = "Access-Control-Allow-Credentials"

#: Timeout per ogni sonda (secondi).
_TIMEOUT = 15.0


def _origin_of(url: str) -> str | None:
    """Origine ``scheme://host[:porta]`` di ``url``, o ``None`` se non estraibile.

    Normalizza a schema minuscolo e scarta path/query/fragment: la sonda CORS
    colpisce la radice dell'origine. ``None`` quando schema o host mancano.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return urlunsplit((parts.scheme.lower(), parts.netloc, "", "", ""))


def _probe_origins(targets: list[str], contract: Contract) -> list[str]:
    """Origini da sondare: quelle dei ``targets`` più quella di ``login_url``.

    Deduplicate preservando l'ordine di prima comparsa. Le origini non
    estraibili sono scartate; il gate allowlist è applicato dopo, per ogni
    richiesta (:func:`run`).
    """
    ordered: list[str] = []
    seen: set[str] = set()
    candidates = list(targets)
    login_origin = _origin_of(contract.login.login_url)
    if login_origin is not None:
        candidates.append(login_origin)
    for candidate in candidates:
        origin = _origin_of(candidate)
        if origin is None or origin in seen:
            continue
        seen.add(origin)
        ordered.append(origin)
    return ordered


def _request(url: str, reachability: str) -> httpx.Response | None:
    """GET con header ``Origin`` estraneo, o ``None`` su errore di trasporto.

    I redirect non sono seguiti (un ``302`` non deve mascherare gli header CORS
    dell'endpoint). ``url`` è quello già gateato dal chiamante; la rimappatura
    host-side (docker) avviene solo qui, per la connessione effettiva, senza
    poter creare bypass dell'allowlist.
    """
    try:
        return httpx.request(
            "GET",
            host_side_url(url, reachability),
            headers={"Origin": PROBE_ORIGIN},
            follow_redirects=False,
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError:
        return None


def _finding(key_prefix: str, severity: str, url: str, acao: str, acac: str, lang: str) -> Finding:
    """Costruisce un :class:`Finding` CORS dalla famiglia di chiavi ``key_prefix``."""
    return Finding(
        source="cors",
        severity=severity,
        title=t(lang, f"{key_prefix}_title"),
        description=t(lang, f"{key_prefix}_desc", url=url, probe=PROBE_ORIGIN),
        evidence=t(
            lang,
            f"{key_prefix}_evidence",
            url=url,
            probe=PROBE_ORIGIN,
            acao=acao,
            acac=acac,
        ),
        fix=t(lang, f"{key_prefix}_fix"),
        impact_if_ignored=t(lang, f"{key_prefix}_impact"),
        confidence=1.0,
        url=url,
    )


def _classify(url: str, response: httpx.Response, lang: str) -> Finding | None:
    """Giudica gli header CORS della risposta, o ``None`` se nulla è esposto.

    L'ordine è significativo: il wildcard è valutato **prima** della riflessione
    con credenziali, perché con ACAO ``*`` i browser ignorano comunque le
    credenziali (resta solo ``media``). La riflessione esatta della sonda con
    credenziali è il caso peggiore (``critica``).
    """
    acao = response.headers.get(_ACAO)
    if acao is None:
        return None
    acac = response.headers.get(_ACAC, "")
    credentials = acac.strip().lower() == "true"

    if acao == "*":
        return _finding("cors_wildcard", "media", url, acao, acac, lang)
    if acao == PROBE_ORIGIN:
        if credentials:
            return _finding("cors_credentialed", "critica", url, acao, acac, lang)
        return _finding("cors_reflect", "alta", url, acao, acac, lang)
    # ACAO presente ma diverso dalla sonda e non wildcard: è un'origine
    # *configurata* (un server corretto riflette solo le origini fidate) =>
    # nessun finding. La sonda estranea non è stata riflessa.
    return None


def run(
    targets: list[str],
    contract: Contract,
    reachability: str,
    lang: str = "it",
) -> list[Finding]:
    """Esegue il controllo CORS su ``targets`` e restituisce i :class:`Finding`.

    :param targets: origini da sondare (tipicamente ``contract.allowed_targets``);
        vi si aggiunge l'origine di ``contract.login.login_url``. Deduplicato.
    :param contract: contratto del progetto; il suo ``allowed_targets`` alimenta
        il gate allowlist fail-closed valutato **prima** di ogni richiesta: una
        origine non consentita non genera alcun traffico.
    :param reachability: modalità di raggiungibilità (``localhost``/``docker``/…),
        propagata alla rimappatura host-side per la sola connessione effettiva.
    :param lang: lingua dei :class:`Finding` prodotti (``"it"`` default o ``"en"``).

    :returns: lista di finding (vuota se nessuna origine è mal configurata: un
        server CORS corretto non riflette l'origine estranea della sonda). Un
        errore di trasporto su una singola origine la salta senza sollevare.
    """
    findings: list[Finding] = []
    for origin in _probe_origins(targets, contract):
        # Gate allowlist fail-closed sull'origine ORIGINALE, prima di qualunque
        # richiesta: fuori allowlist => nessun traffico.
        try:
            assert_target_allowed(contract, origin)
        except TargetNotAllowed:
            continue
        response = _request(origin, reachability)
        if response is None:
            continue
        finding = _classify(origin, response, lang)
        if finding is not None:
            findings.append(finding)
    return findings
