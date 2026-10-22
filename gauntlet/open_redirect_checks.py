"""Controllo deterministico degli *open redirect*.

Un endpoint che costruisce la propria risposta di redirect a partire da un
parametro controllato dall'utente (tipicamente ``?next=``, ``?url=``,
``?returnTo=``) senza validarne la destinazione permette a un attaccante di
spedire la vittima su un sito arbitrario: base per phishing credibile, furto di
token OAuth/SSO e aggiramento di filtri. Questo modulo lo rileva **senza
indovinare**: inietta in ogni template di probe una destinazione canary
chiaramente **estranea** (:data:`PROBE_DESTINATION`) e giudica solo in base
all'header ``Location`` effettivamente restituito.

Oracolo (deterministico, basato sulla risposta):

* lo stato è un redirect (``300 <= status < 400``) **e**
* è presente un header ``Location`` **e**
* l'host (``netloc``) di quel ``Location`` coincide con l'host del canary.

Solo allora si produce un finding **alta** con confidenza ``1.0``. Il confronto
su ``netloc`` cattura ``https://canary/…``, ``http://canary/…`` e il
protocol-relative ``//canary/…`` (``urlsplit`` ne ricava ``netloc == "canary"``).
Un ``Location`` **relativo** (``netloc`` vuoto: l'app resta sul proprio host) o
verso un'origine **diversa** non produce alcun finding: nessun falso positivo
sul solo codice di stato.

**Sicurezza.** Prima di ogni richiesta si passa dal gate allowlist fail-closed
(:func:`gauntlet.safety.assert_target_allowed`): un URL fuori allowlist non
genera traffico. La connessione host-side effettiva usa la rimappatura docker
(:func:`gauntlet.safety.host_side_url`) *dopo* il gate, come il resto della
skill. Il modulo è **non distruttivo**: solo richieste GET e i redirect **non**
vengono seguiti (``follow_redirects=False``), così la risposta di redirect
originale resta ispezionabile.
"""

from __future__ import annotations

from urllib.parse import quote, urljoin, urlsplit

import httpx

from gauntlet.contract import Contract
from gauntlet.i18n import t
from gauntlet.models import Finding
from gauntlet.safety import TargetNotAllowed, assert_target_allowed, host_side_url

#: Destinazione canary iniettata nei probe: un URL off-origin su dominio di
#: esempio riservato da RFC 2606, non registrabile. Un endpoint che redirige
#: davvero qui sta seguendo un input non validato: è l'oracolo del controllo.
PROBE_DESTINATION = "https://gauntlet-redirect-probe.example/landing"

#: Host (``netloc``) del canary, confrontato con quello del ``Location``.
_PROBE_HOST = urlsplit(PROBE_DESTINATION).netloc.lower()

#: Segnaposto sostituito nei template di :attr:`Contract.redirect_probes`.
_PLACEHOLDER = "{payload}"

#: Timeout per ogni sonda (secondi).
_TIMEOUT = 15.0


def _probe_url(base_url: str, template: str) -> str:
    """URL assoluto del probe: sostituisce ``{payload}`` e risolve su ``base_url``.

    Il canary è iniettato **URL-encoded** (è un valore di parametro), poi il
    template — tipicamente relativo (``/login?next={payload}``) — è risolto in
    assoluto rispetto a ``base_url`` con :func:`urllib.parse.urljoin`. Un
    template già assoluto resta invariato.
    """
    injected = template.replace(_PLACEHOLDER, quote(PROBE_DESTINATION, safe=""))
    return urljoin(base_url, injected)


def _request(
    url: str,
    reachability: str,
    session_headers: dict[str, str] | None,
    session_cookies: dict[str, str] | None,
) -> httpx.Response | None:
    """GET autenticata sul probe, o ``None`` su errore di trasporto.

    I redirect **non** sono seguiti: la risposta di redirect originale deve
    restare ispezionabile (un ``follow_redirects`` ne maschererebbe il
    ``Location``). ``url`` è quello già gateato dal chiamante; la rimappatura
    host-side (docker) avviene solo qui, per la connessione effettiva, senza
    poter creare bypass dell'allowlist.
    """
    try:
        return httpx.request(
            "GET",
            host_side_url(url, reachability),
            headers=session_headers or {},
            cookies=session_cookies or None,
            follow_redirects=False,
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError:
        return None


def _is_open_redirect(response: httpx.Response) -> str | None:
    """Restituisce il ``Location`` verso il canary, o ``None`` se l'oracolo non scatta.

    Finding solo se: stato ``3xx``, header ``Location`` presente e il suo host
    (``netloc``) coincide con quello del canary — coprendo ``https://``,
    ``http://`` e il protocol-relative ``//canary/…``. Un ``Location`` relativo
    (``netloc`` vuoto) o verso un'altra origine => ``None``.
    """
    if not (300 <= response.status_code < 400):
        return None
    location = response.headers.get("Location")
    if location is None:
        return None
    if urlsplit(location).netloc.lower() != _PROBE_HOST:
        return None
    return location


def _finding(url: str, location: str, lang: str) -> Finding:
    """Costruisce il :class:`Finding` open redirect confermato."""
    return Finding(
        source="open-redirect",
        severity="alta",
        title=t(lang, "open_redirect_title"),
        description=t(lang, "open_redirect_desc", url=url, probe=PROBE_DESTINATION, location=location),
        evidence=t(lang, "open_redirect_evidence", url=url, probe=PROBE_DESTINATION, location=location),
        fix=t(lang, "open_redirect_fix"),
        impact_if_ignored=t(lang, "open_redirect_impact"),
        confidence=1.0,
        url=url,
    )


def run(
    base_url: str,
    contract: Contract,
    reachability: str,
    *,
    session_headers: dict[str, str] | None = None,
    session_cookies: dict[str, str] | None = None,
    lang: str = "it",
) -> list[Finding]:
    """Esegue il controllo open redirect sui ``contract.redirect_probes``.

    Per ogni template si inietta il canary (:data:`PROBE_DESTINATION`), si
    risolve l'URL in assoluto rispetto a ``base_url`` e — superato il gate
    allowlist fail-closed — si invia una GET senza seguire i redirect. Un
    finding scatta solo se la risposta di redirect punta all'host del canary.

    :param base_url: origine dell'app su cui risolvere i template relativi.
    :param contract: contratto del progetto; ``redirect_probes`` fornisce i
        template e ``allowed_targets`` alimenta il gate valutato **prima** di
        ogni richiesta (un URL non consentito non genera traffico).
    :param reachability: modalità di raggiungibilità (``localhost``/``docker``/…),
        propagata alla rimappatura host-side per la sola connessione effettiva.
    :param session_headers: header della sessione autenticata (es. ``Authorization``).
    :param session_cookies: cookie della sessione autenticata.
    :param lang: lingua dei :class:`Finding` prodotti (``"it"`` default o ``"en"``).

    :returns: lista di finding (vuota se nessun probe è vulnerabile). Se
        ``redirect_probes`` è vuoto non viene inviata alcuna richiesta. Un errore
        di trasporto su un singolo probe lo salta senza sollevare.
    """
    findings: list[Finding] = []
    for template in contract.redirect_probes:
        url = _probe_url(base_url, template)
        # Gate allowlist fail-closed sull'URL ORIGINALE, prima di qualunque
        # richiesta: fuori allowlist => nessun traffico.
        try:
            assert_target_allowed(contract, url)
        except TargetNotAllowed:
            continue
        response = _request(url, reachability, session_headers, session_cookies)
        if response is None:
            continue
        location = _is_open_redirect(response)
        if location is not None:
            findings.append(_finding(url, location, lang))
    return findings
