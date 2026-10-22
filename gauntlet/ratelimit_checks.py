"""Controllo dell'assenza di rate limiting sul login (AGGRESSIVE-ONLY).

Un login senza rate limiting lascia spazio al *credential stuffing* e al brute
force. Questo modulo lo *osserva* nel modo più diretto: invia alcuni tentativi
di login **falliti** consecutivi (username reale, password deliberatamente
errata) e guarda se il server reagisce con un qualche throttling (HTTP ``429``
oppure un header ``Retry-After``). Se dopo ``attempts`` tentativi non si è visto
alcun segnale di limitazione, lo segnala.

**Perché è aggressive-only (destructive-ish).** Tentativi di login falliti
ripetuti possono innescare il *lockout* dell'account bersaglio: non è una pura
lettura. Per questo il modulo gira **solo** quando il run è in modalità
aggressive (consenso a lotto upfront) e mai di default. I tentativi sono pochi,
sequenziali e limitati (:data:`_MAX_ATTEMPTS`).

**Onestà del controllo (confidenza ~0.6).** L'esito è un'**osservazione su N
tentativi**, non una prova assoluta: un limiter che scatta solo oltre una soglia
più alta, o basato su IP con finestra ampia, potrebbe non attivarsi in così pochi
tentativi. Di conseguenza il finding ha confidenza ``0.6`` e una formulazione
prudente ("nessun throttling osservato in N tentativi"), non "il login è
sicuramente privo di rate limiting". Se invece *anche un solo* tentativo mostra
throttling, non si segnala nulla.

**Sicurezza.** La password è sempre la sonda errata :data:`_WRONG_PASSWORD`:
non ci si autentica mai davvero. Prima di inviare qualunque richiesta il modulo
passa dal gate allowlist fail-closed
(:func:`gauntlet.safety.assert_target_allowed`): un ``login_url`` fuori allowlist
non produce traffico e il modulo restituisce ``[]``. La connessione host-side
effettiva usa la rimappatura docker (:func:`gauntlet.safety.host_side_url`)
*dopo* il gate, come il resto della skill.
"""

from __future__ import annotations

import httpx

from gauntlet.contract import Contract, LoginConfig
from gauntlet.i18n import t
from gauntlet.models import Finding
from gauntlet.safety import TargetNotAllowed, assert_target_allowed, host_side_url

#: Password deliberatamente errata usata in ogni tentativo: garantisce che il
#: controllo non autentichi mai davvero (nessuna sessione reale creata).
_WRONG_PASSWORD = "gauntlet-wrong-password-probe"

#: Tetto massimo ai tentativi, qualunque valore chieda il chiamante: il controllo
#: resta piccolo e sequenziale, per non trasformarsi in un brute force.
_MAX_ATTEMPTS = 20

#: Timeout per ogni tentativo (secondi).
_TIMEOUT = 15.0


def _request(
    login_cfg: LoginConfig, username: str, reachability: str
) -> httpx.Response | None:
    """Invia un tentativo di login FALLITO, o ``None`` su errore di trasporto.

    Usa lo stesso formato del login reale (``form`` => dati di form; ``json`` /
    ``token`` => corpo JSON) ma con la password sonda errata. I redirect non sono
    seguiti. ``login_url`` resta quello originale già gateato dal chiamante; la
    rimappatura host-side (docker) avviene solo qui per la connessione effettiva.
    """
    credentials = {
        login_cfg.username_field: username,
        login_cfg.password_field: _WRONG_PASSWORD,
    }
    url = host_side_url(login_cfg.login_url, reachability)
    try:
        if login_cfg.method == "form":
            return httpx.request(
                "POST", url, data=credentials, follow_redirects=False, timeout=_TIMEOUT
            )
        return httpx.request(
            "POST", url, json=credentials, follow_redirects=False, timeout=_TIMEOUT
        )
    except httpx.HTTPError:
        return None


def _is_throttled(response: httpx.Response) -> bool:
    """``True`` se la risposta indica throttling/limitazione del login.

    Segnali considerati: HTTP ``429 Too Many Requests`` (il segnale canonico) e
    la presenza di un header ``Retry-After`` (alcuni server limitano con ``503``
    + ``Retry-After``). Qualunque di questi basta a NON segnalare.
    """
    if response.status_code == 429:
        return True
    if response.headers.get("Retry-After"):
        return True
    return False


def _no_ratelimit_finding(login_url: str, received: int, lang: str) -> Finding:
    """Finding ``alta`` (confidenza ``0.6``) per assenza osservata di throttling.

    ``received`` è il numero di risposte **effettivamente** ricevute: sia la
    descrizione sia l'evidenza usano questo stesso valore, così i due testi non
    divergono mai quando errori di trasporto riducono il conteggio dei tentativi.
    """
    return Finding(
        source="rate-limit",
        severity="alta",
        title=t(lang, "rl_title"),
        description=t(lang, "rl_desc", url=login_url, attempts=received),
        evidence=t(lang, "rl_evidence", url=login_url, attempts=received),
        fix=t(lang, "rl_fix"),
        impact_if_ignored=t(lang, "rl_impact"),
        confidence=0.6,
        url=login_url,
    )


def run(
    login_cfg: LoginConfig,
    username: str,
    *,
    contract: Contract,
    reachability: str,
    attempts: int = 8,
    lang: str = "it",
) -> list[Finding]:
    """Sonda l'assenza di rate limiting sul login e restituisce i :class:`Finding`.

    :param login_cfg: configurazione di login del contratto (URL, metodo, nomi
        dei campi). Si invia al suo ``login_url``.
    :param username: username reale da usare nei tentativi (la password è sempre
        la sonda errata :data:`_WRONG_PASSWORD`: non si autentica mai).
    :param contract: contratto del progetto; il suo ``allowed_targets`` alimenta
        il gate allowlist fail-closed valutato **prima** di qualunque richiesta.
    :param reachability: modalità di raggiungibilità, propagata alla rimappatura
        host-side per la sola connessione effettiva.
    :param attempts: numero di tentativi (default ``8``), limitato a
        :data:`_MAX_ATTEMPTS`.
    :param lang: lingua dei :class:`Finding` prodotti (``"it"`` default o ``"en"``).

    :returns: un solo finding ``alta`` (confidenza ``0.6``) se in ``attempts``
        tentativi non si è osservato alcun throttling; ``[]`` se è comparso un
        segnale di throttling (anche uno solo), se il ``login_url`` è fuori
        allowlist, o se nessuna risposta è stata ricevuta (solo errori di
        trasporto: nulla da affermare).
    """
    # Gate allowlist fail-closed sull'URL ORIGINALE: un login_url fuori allowlist
    # non genera alcun traffico.
    try:
        assert_target_allowed(contract, login_cfg.login_url)
    except TargetNotAllowed:
        return []

    bounded = max(1, min(int(attempts), _MAX_ATTEMPTS))
    received = 0
    for _ in range(bounded):
        response = _request(login_cfg, username, reachability)
        if response is None:
            continue
        received += 1
        if _is_throttled(response):
            # Throttling osservato: il login limita i tentativi => nessun finding.
            return []

    if received == 0:
        # Nessuna risposta ricevuta (solo errori di trasporto): non si afferma
        # nulla sull'assenza di rate limiting.
        return []

    return [_no_ratelimit_finding(login_cfg.login_url, received, lang)]
