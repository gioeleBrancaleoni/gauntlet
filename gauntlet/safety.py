"""Gate di sicurezza di Gauntlet: allowlist *fail-closed* e conferma distruttiva.

Questo modulo è l'unica barriera che impedisce alla skill di attaccare un host
non autorizzato o di produzione. Due garanzie:

1. **Allowlist fail-closed** (:func:`assert_target_allowed`): un target è
   consentito solo se la sua *origine* normalizzata (schema + host + porta)
   coincide con quella di una voce di ``contract.allowed_targets``. Non c'è
   alcuna euristica di "rilevamento produzione": ciò che non è esplicitamente
   in allowlist è rifiutato. Qualunque path sotto un'origine consentita passa.

2. **Conferma distruttiva** (:func:`confirm_destructive`): i passi che scrivono
   (active scan, scritture cross-tenant) devono ottenere un via libera esplicito
   a runtime tramite un hook di conferma; in assenza di hook la risposta è
   negativa.

Scelte di normalizzazione dell'origine (volutamente rigide, per sicurezza):

* **schema e host** sono confrontati in minuscolo;
* **porta**: se assente si usa la porta di default dello schema (``http`` → 80,
  ``https`` → 443), così ``http://localhost`` ≠ ``http://localhost:8081``;
* **schema diverso** (es. ``https`` contro una voce ``http``) → origine diversa
  → rifiutato;
* il confronto è per uguaglianza di origine, mai per sottostringa, così
  ``http://localhost:8081.evil.com`` non combacia con ``http://localhost:8081``;
* un target da cui non è estraibile schema+host è rifiutato (fail-closed).
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from gauntlet.contract import Contract

#: Porte di default per schema, usate per normalizzare un'origine priva di porta.
_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Nome host usato dai container (es. ZAP) per raggiungere il processo host. NON
#: risolve sul lato host: va rimappato sul loopback per le connessioni host-side.
_DOCKER_INTERNAL_HOST = "host.docker.internal"

#: Indirizzo loopback su cui rimappare ``host.docker.internal`` lato host.
_DOCKER_HOST_SIDE_ADDR = "127.0.0.1"


def host_side_url(url: str, reachability: str) -> str:
    """Rimappa un URL per una connessione *host-side* in modalità ``docker``.

    In ``reachability == "docker"`` il motore di scansione (ZAP) gira in un
    container e raggiunge l'app sotto test via ``host.docker.internal``. Quel
    nome, però, risolve **solo dentro i container**: ogni connessione fatta dal
    processo host (sonda TCP del preflight, richieste ``httpx`` di
    :func:`gauntlet.authn.login` e del controllo-accessi) fallirebbe. Questa
    funzione sostituisce l'host ``host.docker.internal`` con ``127.0.0.1``
    *solo* per la connessione host-side, preservando schema, porta, path, query
    e fragment. Gli URL rivolti al container (in ``zap_runner``) non la usano e
    continuano a puntare a ``host.docker.internal``.

    Fuori da ``docker``, o quando l'host non è ``host.docker.internal``, l'URL è
    restituito invariato.

    Nota di sicurezza: questa è una pura trasformazione di indirizzo per la
    connessione e **non** sostituisce il gate allowlist. Il gate
    (:func:`assert_target_allowed` / :func:`assert_origin_allowed`) va sempre
    valutato sull'URL *originale* del contratto; solo dopo che il gate è passato
    si usa l'URL rimappato per il socket/httpx effettivo.
    """
    if reachability != "docker":
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if (parts.hostname or "").lower() != _DOCKER_INTERNAL_HOST:
        return url

    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo += f":{parts.password}"
        userinfo += "@"
    netloc = f"{userinfo}{_DOCKER_HOST_SIDE_ADDR}"
    if parts.port is not None:
        netloc += f":{parts.port}"

    return urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )


class TargetNotAllowed(Exception):
    """Sollevata quando un target non è coperto da ``allowed_targets``.

    È l'esito *fail-closed* del gate: viene sollevata per qualunque origine non
    esplicitamente consentita (host sconosciuto, schema o porta diversi, URL
    malformato).
    """


class DestructiveNotConfirmed(Exception):
    """Sollevata da un chiamante quando un passo distruttivo non è confermato.

    Il gate (:func:`confirm_destructive`) si limita a restituire un booleano; i
    chiamanti (Task 3/8) sollevano questa eccezione per interrompere un passo
    distruttivo privo di via libera esplicito.
    """


def _normalized_origin(url: str) -> tuple[str, str, int] | None:
    """Restituisce ``(schema, host, porta)`` normalizzato, o ``None``.

    Ritorna ``None`` se dall'URL non si possono estrarre sia lo schema sia
    l'host (caso fail-closed), o se lo schema non ha una porta di default nota e
    non è specificata alcuna porta.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return None

    try:
        port = parts.port
    except ValueError:
        # Porta non numerica / malformata nell'authority.
        return None
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
        if port is None:
            # Schema senza porta di default nota e senza porta esplicita.
            return None

    return (scheme, host, port)


def assert_origin_allowed(allowed_targets: list[str], target: str) -> None:
    """Verifica che ``target`` sia coperto da ``allowed_targets`` (fail-closed).

    Primitiva a lista dell'allowlist, usata da :func:`assert_target_allowed`
    (che la invoca con ``contract.allowed_targets``) e direttamente dai punti
    che dispongono della sola lista di origini consentite (es.
    :func:`gauntlet.authn.login`). Il match è per *origine* normalizzata
    (schema + host + porta): qualunque path sotto un'origine consentita passa.

    :raises TargetNotAllowed: se il target non combacia con alcuna voce della
        allowlist (comportamento fail-closed).
    """
    target_origin = _normalized_origin(target)
    if target_origin is None:
        raise TargetNotAllowed(
            f"Target rifiutato (origine non estraibile, fail-closed): {target!r}"
        )

    allowed_origins = [
        origin
        for entry in allowed_targets
        if (origin := _normalized_origin(entry)) is not None
    ]
    if target_origin in allowed_origins:
        return

    allowed_repr = ", ".join(
        f"{s}://{h}:{p}" for (s, h, p) in allowed_origins
    ) or "(nessuna origine valida in allowlist)"
    tgt_s, tgt_h, tgt_p = target_origin
    raise TargetNotAllowed(
        f"Target non in allowlist (fail-closed): {tgt_s}://{tgt_h}:{tgt_p} "
        f"non è tra le origini consentite [{allowed_repr}]."
    )


def assert_target_allowed(contract: Contract, target: str) -> None:
    """Verifica che ``target`` sia coperto da ``contract.allowed_targets``.

    Delega a :func:`assert_origin_allowed` sull'allowlist del contratto: il
    match è per *origine* normalizzata (schema + host + porta), qualunque path
    sotto un'origine consentita passa. Non restituisce nulla se il target è
    consentito.

    :raises TargetNotAllowed: se il target non combacia con alcuna voce della
        allowlist (comportamento fail-closed).
    """
    assert_origin_allowed(contract.allowed_targets, target)


def confirm_destructive(
    description: str, confirm: Callable[[str], bool] | None
) -> bool:
    """Chiede conferma per un passo distruttivo tramite l'hook ``confirm``.

    Invoca ``confirm(description)`` e ne restituisce il booleano. Se ``confirm``
    è ``None`` (nessun hook configurato) restituisce ``False``: in assenza di via
    libera esplicito il passo distruttivo non procede.
    """
    if confirm is None:
        return False
    return bool(confirm(description))
