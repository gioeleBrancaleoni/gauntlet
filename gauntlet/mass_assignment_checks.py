"""Rilevamento deterministico dell'assegnazione di massa (*mass assignment*).

L'*assegnazione di massa* è il bug per cui un'API fonde l'intero corpo di un
update nei campi di un oggetto senza filtrarli, lasciando al client la
possibilità di impostare attributi che dovrebbe poter solo leggere (p.es.
``role``, ``isAdmin``, ``owner``). Questo modulo lo rileva **senza indovinare**,
con un oracolo in due tempi — *scrittura + ri-lettura* — su campi e valori
generici dichiarati dal contratto (:class:`gauntlet.contract.MassAssignmentProbe`).

Oracolo (deterministico, nessun falso positivo):

1. pre-GET della risorsa come proprietario: si legge il valore iniziale del
   campo vietato (``original``, eventualmente assente).
2. scrittura: un update (``PATCH`` per default) col solo campo vietato impostato
   al valore sentinella.
3. re-GET della risorsa: si rilegge il campo (``current``).

La vulnerabilità è **confermata** solo quando ``current`` riflette il valore
sentinella **e** quel valore è un cambiamento reale rispetto a ``original``
(campo prima assente, o con un valore diverso). Un update che risponde ``2xx``
ma non muta davvero il campo, o una risorsa che aveva già quel valore, **non**
producono alcun finding: non si segnala mai sul solo status della scrittura.

**Sicurezza.** Il modulo è **distruttivo** (scrive) ed è aggressivo-only. Prima
di ogni scrittura si passa dal gate di conferma distruttiva
(:func:`gauntlet.safety.confirm_destructive`): senza via libera esplicito la
sonda è saltata e **nessuna** richiesta parte (nemmeno la pre-GET). Prima di
ogni richiesta si passa inoltre dal gate allowlist fail-closed
(:func:`gauntlet.safety.assert_target_allowed`), valutato sull'URL *originale*
del contratto; la rimappatura host-side docker
(:func:`gauntlet.safety.host_side_url`) avviene solo dopo, per la sola
connessione effettiva, e non può creare bypass dell'allowlist. Dopo la sonda, se
il campo aveva un valore iniziale, si tenta un **ripristino best-effort** al
valore originale (errori ignorati). Gli errori di trasporto saltano la singola
sonda senza mai sollevare.
"""

from __future__ import annotations

import json
from typing import Callable
from urllib.parse import urlsplit

import httpx

from gauntlet.contract import Contract, MassAssignmentProbe
from gauntlet.i18n import t
from gauntlet.models import Finding
from gauntlet.safety import (
    TargetNotAllowed,
    assert_target_allowed,
    confirm_destructive,
    host_side_url,
)

#: Timeout per ogni richiesta della sonda (secondi).
_TIMEOUT = 15.0


def _has_scheme(url: str) -> bool:
    return bool(urlsplit(url).scheme)


def _resolve(template: str, probe_id: str, base_url: str | None) -> str | None:
    """URL assoluto da ``template``, o ``None`` se non risolvibile.

    Sostituisce ``{id}`` con ``probe_id``. Un template già assoluto è usato così
    com'è; un path relativo richiede ``base_url`` (altrimenti ``None`` => salto).
    """
    url = template.format(id=probe_id) if "{id}" in template else template
    if _has_scheme(url):
        return url
    if base_url:
        return base_url.rstrip("/") + "/" + url.lstrip("/")
    return None


def _field_value(response: httpx.Response, field: str) -> object | None:
    """Valore di ``field`` nel corpo JSON della risposta, o ``None``.

    ``None`` se il corpo non è JSON, non è un oggetto, o il campo è assente/null:
    in tutti questi casi il campo è trattato come "non presente".
    """
    try:
        data = response.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data.get(field)


def _json_spelling(value: object) -> str:
    """Grafia JSON del valore nel testo del finding.

    Serializza sempre via JSON, così il testo mostra token JSON validi e
    coerenti: un booleano come ``true``/``false``, ``null``, i numeri nudi e le
    stringhe fra virgolette doppie (``"admin"``). I template non aggiungono
    apici attorno al valore, così il corpo d'esempio resta JSON valido
    (es. ``{"isAdmin": true}``).
    """
    return json.dumps(value)


def _finding(probe: MassAssignmentProbe, url: str, lang: str) -> Finding:
    """Costruisce il :class:`Finding` di mass assignment confermato."""
    return Finding(
        source="mass-assignment",
        severity="alta",
        title=t(lang, "mass_assignment_title"),
        description=t(
            lang,
            "mass_assignment_desc",
            url=url,
            field=probe.forbidden_field,
            value=_json_spelling(probe.forbidden_value),
        ),
        evidence=t(
            lang,
            "mass_assignment_evidence",
            url=url,
            field=probe.forbidden_field,
            value=_json_spelling(probe.forbidden_value),
        ),
        fix=t(lang, "mass_assignment_fix"),
        impact_if_ignored=t(lang, "mass_assignment_impact"),
        confidence=1.0,
        url=url,
    )


def _get(url: str, reachability: str, headers: dict, cookies: dict | None) -> httpx.Response:
    return httpx.request(
        "GET",
        host_side_url(url, reachability),
        headers=headers,
        cookies=cookies,
        follow_redirects=False,
        timeout=_TIMEOUT,
    )


def _write(
    method: str,
    url: str,
    payload: dict,
    reachability: str,
    headers: dict,
    cookies: dict | None,
) -> httpx.Response:
    return httpx.request(
        method,
        host_side_url(url, reachability),
        json=payload,
        headers=headers,
        cookies=cookies,
        follow_redirects=False,
        timeout=_TIMEOUT,
    )


def _probe_one(
    probe: MassAssignmentProbe,
    write_url: str,
    read_url: str,
    reachability: str,
    headers: dict,
    cookies: dict | None,
    lang: str,
) -> Finding | None:
    """Esegue l'oracolo write + re-GET su una singola sonda.

    Restituisce un :class:`Finding` se la scrittura del campo vietato è
    confermata dalla ri-lettura, altrimenti ``None``. Un errore di trasporto su
    pre-GET, scrittura o re-GET salta la sonda (``None``) senza sollevare. Il
    ripristino al valore originale, quando applicabile, è best-effort.
    """
    # Il contratto può indicare il metodo in minuscolo: va maiuscolato perché
    # molti server trattano il verbo HTTP in modo case-sensitive.
    method = probe.method.upper()
    try:
        pre = _get(read_url, reachability, headers, cookies)
        original = _field_value(pre, probe.forbidden_field)

        _write(
            method,
            write_url,
            {probe.forbidden_field: probe.forbidden_value},
            reachability,
            headers,
            cookies,
        )

        post = _get(read_url, reachability, headers, cookies)
        current = _field_value(post, probe.forbidden_field)
    except httpx.HTTPError:
        return None

    # Confermato solo se la re-GET riflette il valore sentinella E rappresenta un
    # cambiamento reale (campo prima assente, o con un valore diverso). Il guard
    # ``current is not None`` impedisce che un campo assente/``null`` nella
    # re-GET (``_field_value`` restituisce ``None`` in entrambi i casi) confermi
    # a vuoto, anche quando la stessa sentinella è ``None``.
    confirmed = (
        current is not None
        and str(current) == str(probe.forbidden_value)
        and (original is None or str(original) != str(probe.forbidden_value))
    )

    # Ripristino best-effort: se il campo aveva un valore iniziale, si prova a
    # riscriverlo, ignorando ogni errore (non deve mai interrompere il run).
    if original is not None:
        try:
            _write(
                method,
                write_url,
                {probe.forbidden_field: original},
                reachability,
                headers,
                cookies,
            )
        except httpx.HTTPError:
            pass

    return _finding(probe, write_url, lang) if confirmed else None


def run(
    base_url: str,
    contract: Contract,
    reachability: str,
    *,
    session_headers: dict[str, str] | None = None,
    session_cookies: dict[str, str] | None = None,
    confirm: Callable[[str], bool] | None,
    lang: str = "it",
) -> list[Finding]:
    """Esegue il rilevamento di mass assignment e restituisce i :class:`Finding`.

    :param base_url: origine con cui risolvere gli ``url_template``/``read_template``
        scritti come path relativi; superfluo quando i template sono già assoluti.
    :param contract: il contratto del progetto. Le sonde provengono da
        ``contract.mass_assignment``; ``allowed_targets`` alimenta il gate
        allowlist fail-closed valutato **prima** di ogni richiesta (scrittura e
        letture): un URL fuori allowlist salta la sonda senza inviare nulla.
    :param reachability: modalità di raggiungibilità (``localhost``/``docker``/…),
        propagata alla rimappatura host-side per la sola connessione effettiva.
    :param session_headers: header della sessione proprietario (p.es.
        ``Authorization``) inviati con ogni richiesta; assenti => nessun header.
    :param session_cookies: cookie della sessione proprietario; assenti => nessuno.
    :param confirm: hook di conferma distruttiva. Ogni scrittura è aggressivo-only
        e passa per :func:`confirm_destructive`: se ``None`` o se restituisce
        ``False`` la sonda è saltata e nessuna richiesta parte.
    :param lang: lingua dei :class:`Finding` prodotti (``"it"`` default o ``"en"``).

    :returns: lista di finding (uno per sonda confermata). Una sonda con URL non
        risolvibile, fuori allowlist, non confermata dall'oracolo o interrotta da
        un errore di trasporto non produce finding e non interrompe le altre.
    """
    headers = session_headers or {}
    cookies = session_cookies or None

    findings: list[Finding] = []
    for probe in contract.mass_assignment:
        write_url = _resolve(probe.url_template, probe.id, base_url)
        read_url = _resolve(probe.read_template or probe.url_template, probe.id, base_url)
        if write_url is None or read_url is None:
            continue

        # Gate allowlist fail-closed su ENTRAMBI gli URL (scrittura e lettura),
        # prima di qualunque richiesta: fuori allowlist => nessun traffico.
        try:
            assert_target_allowed(contract, write_url)
            assert_target_allowed(contract, read_url)
        except TargetNotAllowed:
            continue

        # Gate di conferma distruttiva: nessuna scrittura (né pre-GET) senza via
        # libera esplicito.
        if not confirm_destructive(
            f"Mass-assignment: scrittura su {write_url}", confirm
        ):
            continue

        finding = _probe_one(
            probe, write_url, read_url, reachability, headers, cookies, lang
        )
        if finding is not None:
            findings.append(finding)
    return findings
