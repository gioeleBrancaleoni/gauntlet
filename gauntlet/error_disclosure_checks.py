"""Controllo della divulgazione di errori/stack trace (read-only, default).

Molte applicazioni, di fronte a un input malformato, rispondono con uno stack
trace o un dump di errore del framework/ORM: una fuga di informazioni che svela
tecnologia, struttura del codice, percorsi del filesystem e talvolta frammenti
di query. Questo modulo lo rileva richiedendo risorse protette note con un ``id``
**deliberatamente malformato** (lo costruisce il chiamante) e cercando nel corpo
*firme specifiche* di errore, non parole generiche.

**Onestà del controllo (confidenza ~0.7).** Il rilevamento è **basato su
pattern**: le firme sono curate e specifiche per ridurre i falsi positivi, ma non
possono eliminarli del tutto (una risposta legittima potrebbe contenere per caso
una stringa-firma — p.es. un percorso ``/app/...`` di un asset, o la parola
``MySQL`` in un messaggio informativo). Perciò il finding ha confidenza ``0.7`` e
una formulazione prudente, e l'evidenza riporta **la firma trovata**, non l'intero
corpo (che potrebbe contenere dati sensibili).

**Sicurezza.** Il modulo è **non distruttivo**: solo richieste ``GET``, emesse
come proprietario (header di sessione passati dal chiamante). Prima di ogni
richiesta passa dal gate allowlist fail-closed
(:func:`gauntlet.safety.assert_target_allowed`): una probe URL fuori allowlist
non genera traffico. La connessione host-side effettiva usa la rimappatura docker
(:func:`gauntlet.safety.host_side_url`) *dopo* il gate, come il resto della skill.
"""

from __future__ import annotations

import re

import httpx

from gauntlet.contract import Contract
from gauntlet.i18n import t
from gauntlet.models import Finding
from gauntlet.safety import TargetNotAllowed, assert_target_allowed, host_side_url

#: Timeout per ogni richiesta di sonda (secondi).
_TIMEOUT = 15.0

#: Numero massimo di caratteri della firma riportati nell'evidenza (mai l'intero
#: corpo, che potrebbe contenere dati sensibili).
_EVIDENCE_MAX = 160

#: Soglia di stato HTTP oltre la quale una risposta è considerata "di errore".
_ERROR_STATUS = 400

#: Firme *specifiche* di stack trace / errori di framework/ORM. Ogni voce è
#: ``(etichetta, pattern, solo_su_errore)``: si segnala SOLO se un pattern
#: combacia. Sono curate per essere distintive (prefissi/formati di errore, non
#: parole comuni), così da tenere bassi i falsi positivi; la confidenza 0.7
#: riconosce che non li elimina.
#:
#: ``solo_su_errore=True`` restringe una firma più ambigua alle sole risposte con
#: stato >= :data:`_ERROR_STATUS`: è il caso del percorso di filesystem (che su
#: una 2xx normale potrebbe comparire legittimamente, p.es. una rotta SPA o un
#: asset) e del codice ``ER_*`` MySQL (che combacia anche con normali costanti
#: applicative ``ER_*`` come ``ER_MODEL``). Le altre firme, molto più distintive
#: (prefissi/formati di errore inconfondibili), valgono su qualunque stato.
_SIGNATURES: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    # Python
    ("Traceback (most recent call last)", re.compile(r"Traceback \(most recent call last\)"), False),
    ("SyntaxError:", re.compile(r"\bSyntaxError:"), False),
    # JavaScript / Node
    ("ReferenceError:", re.compile(r"\bReferenceError:"), False),
    # JSON "stack" field: SOLO se adiacente a un vero marcatore di frame (una
    # stringa 'stack' seguita a breve distanza da 'at func(' o da 'file:riga:col'),
    # così un campo JSON legittimo chiamato "stack" (es. {"stack":["python"]}) non
    # combacia — un valore-array non apre nemmeno la stringa richiesta.
    (
        "JSON \"stack\" field with frame",
        re.compile(r'"stack"\s*:\s*".{0,200}?(?:\bat [\w$.<>]+ ?\(|:\d+:\d+)', re.DOTALL),
        False,
    ),
    # Java (frame di stack: at pkg.Class.method(File.java:NN))
    ("Java stack frame", re.compile(r"\bat [\w.$]+\([\w$]+\.java:\d+\)"), False),
    # Database / ORM
    ("SQLSTATE", re.compile(r"\bSQLSTATE\b"), False),
    # Codice errore MySQL ``ER_*``: firma ambigua (combacia anche con normali
    # costanti ``ER_*`` applicative, es. ``ER_MODEL``). Error-gated: vale SOLO su
    # risposte di errore (>= _ERROR_STATUS), dove un ``ER_*`` è plausibilmente un
    # vero codice d'errore MySQL e non una costante di dominio.
    ("MySQL error code (ER_*)", re.compile(r"\bER_[A-Z][A-Z0-9_]{2,}\b"), True),
    ("ORA- Oracle error", re.compile(r"\bORA-\d{5}\b"), False),
    ("PG:: (Ruby/PostgreSQL)", re.compile(r"\bPG::\w+"), False),
    ("SequelizeDatabaseError", re.compile(r"\bSequelizeDatabaseError\b"), False),
    ("MySQL error text", re.compile(r"\bMySQL server\b|\bYou have an error in your SQL syntax\b"), False),
    # Percorso del filesystem: firma più ambigua, valida SOLO su risposte di
    # errore (>= _ERROR_STATUS). '/app/' è escluso perché collide con le rotte
    # SPA comuni (es. href="/app/dashboard"); restano '/home/', '/usr/', '/var/'.
    ("filesystem path in error", re.compile(r"(?:/home/|/usr/|/var/)[\w./-]{3,}"), True),
)


def _request(
    url: str, session_headers: dict, reachability: str
) -> httpx.Response | None:
    """GET della sonda come proprietario, o ``None`` su errore di trasporto.

    I redirect non sono seguiti. ``url`` resta quello originale già gateato dal
    chiamante; la rimappatura host-side (docker) avviene solo qui per la
    connessione effettiva, senza poter creare bypass dell'allowlist.
    """
    try:
        return httpx.request(
            "GET",
            host_side_url(url, reachability),
            headers=dict(session_headers),
            follow_redirects=False,
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError:
        return None


def _first_signature(body: str, status: int) -> tuple[str, str] | None:
    """Prima firma specifica trovata nel corpo, come ``(etichetta, estratto)``.

    L'estratto è il testo effettivamente combaciato (troncato a
    :data:`_EVIDENCE_MAX`), mai l'intero corpo. ``None`` se nessuna firma combacia.
    Le firme marcate ``solo_su_errore`` sono considerate soltanto quando lo
    ``status`` è di errore (>= :data:`_ERROR_STATUS`): così una firma più ambigua
    (il percorso di filesystem) non può scattare su una normale risposta 2xx.
    """
    is_error = status >= _ERROR_STATUS
    for label, pattern, error_only in _SIGNATURES:
        if error_only and not is_error:
            continue
        match = pattern.search(body)
        if match:
            return label, match.group(0)[:_EVIDENCE_MAX]
    return None


def _disclosure_finding(
    url: str, response: httpx.Response, signature: tuple[str, str], lang: str
) -> Finding:
    label, snippet = signature
    return Finding(
        source="error-disclosure",
        severity="media",
        title=t(lang, "ed_title"),
        description=t(lang, "ed_desc", url=url, status=response.status_code),
        evidence=t(
            lang,
            "ed_evidence",
            url=url,
            status=response.status_code,
            signature=label,
            snippet=repr(snippet),
        ),
        fix=t(lang, "ed_fix"),
        impact_if_ignored=t(lang, "ed_impact"),
        confidence=0.7,
        url=url,
    )


def run(
    probe_urls: list[str],
    session_headers: dict,
    *,
    contract: Contract,
    reachability: str,
    lang: str = "it",
) -> list[Finding]:
    """Sonda la divulgazione di errori/stack trace e restituisce i :class:`Finding`.

    :param probe_urls: URL delle risorse protette con un ``id`` deliberatamente
        malformato, costruiti dal chiamante (p.es. in :mod:`gauntlet.cli`).
    :param session_headers: header della sessione del proprietario con cui fare
        le GET (il controllo è read-only).
    :param contract: contratto del progetto; il suo ``allowed_targets`` alimenta
        il gate allowlist fail-closed valutato **prima** di ogni richiesta: una
        probe URL fuori allowlist non genera traffico.
    :param reachability: modalità di raggiungibilità, propagata alla rimappatura
        host-side per la sola connessione effettiva.
    :param lang: lingua dei :class:`Finding` prodotti (``"it"`` default o ``"en"``).

    :returns: un finding ``media`` (confidenza ``0.7``) per ogni probe URL la cui
        risposta contiene una firma specifica di errore; ``[]`` se nessuna firma
        combacia (comportamento atteso di un server che non divulga stack trace).
    """
    findings: list[Finding] = []
    for url in probe_urls:
        # Gate allowlist fail-closed sull'URL ORIGINALE, prima della richiesta.
        try:
            assert_target_allowed(contract, url)
        except TargetNotAllowed:
            continue
        response = _request(url, session_headers, reachability)
        if response is None:
            continue
        try:
            body = response.text
        except Exception:  # pragma: no cover - corpo non decodificabile
            continue
        signature = _first_signature(body, response.status_code)
        if signature is None:
            continue
        findings.append(_disclosure_finding(url, response, signature, lang))
    return findings
