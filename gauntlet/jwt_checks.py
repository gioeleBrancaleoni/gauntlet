"""Controlli sulle debolezze classiche della gestione dei JWT.

Ai livelli autenticati, usando il JWT reale ottenuto al login e una risorsa
protetta nota come sonda, questo modulo verifica due debolezze storiche
dell'implementazione dei JSON Web Token:

1. **alg=none accettato.** Prima si esegue un **controllo negativo**: un token
   con lo **stesso** ``alg`` del token reale ma firma deliberatamente *corrotta*,
   inviato alla stessa sonda. Se perfino questo è accettato (``2xx`` + marcatore),
   l'endpoint non verifica affatto la firma / è di fatto non autenticato: il
   meccanismo è ambiguo e si emette un finding **alta** (0.6), **non** la
   ``critica`` ``alg=none``. Solo se il controllo è *rifiutato* (il server verifica
   le firme) si forgia un token ``{"alg":"none","typ":"JWT"}`` con la **stessa**
   payload del token reale e firma **vuota** (``base64url(header).base64url(payload).``)
   e lo si invia in ``Authorization: Bearer`` sulla sonda. Se la risposta è
   ``2xx`` **e** contiene il marcatore atteso, il server ha accettato un token non
   firmato pur verificando le firme valide: debolezza **critica**. Senza marcatore
   noto il controllo non è deterministico e viene saltato (nessun finding),
   coerentemente con l'oracolo del controllo-accessi.

2. **secret HMAC debole.** Solo se l'alg del token reale è ``HS256``/``HS384``/
   ``HS512``, la firma viene rigiocata contro una piccola wordlist di segreti
   comuni: si ricalcola l'HMAC su ``header.payload`` con ogni candidato (stdlib
   :mod:`hmac`/:mod:`hashlib`) e, se uno riproduce la firma del token, il
   segreto di firma è indovinabile: debolezza **critica**. Per ``RS*``/``ES*``/
   ``none`` il controllo è saltato (non applicabile).

**Sicurezza.** Prima di inviare *qualunque* richiesta il modulo passa dal gate
allowlist fail-closed (:func:`gauntlet.safety.assert_target_allowed`): una sonda
fuori allowlist non produce traffico e il modulo restituisce ``[]``. La
connessione host-side effettiva usa la rimappatura docker
(:func:`gauntlet.safety.host_side_url`) *dopo* il gate, esattamente come
:func:`gauntlet.access_control._request`. Nessuna dipendenza esterna: solo
``base64``/``json``/``hmac``/``hashlib`` della stdlib e ``httpx`` (già dipendenza).

Il modulo è **non distruttivo**: emette solo richieste ``GET``. Un token
malformato non solleva mai: il decode senza verifica ripiega su ``[]``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import httpx

from gauntlet.contract import Contract
from gauntlet.i18n import t
from gauntlet.models import Finding
from gauntlet.safety import TargetNotAllowed, assert_target_allowed, host_side_url

#: Timeout per la richiesta della sonda (secondi).
_TIMEOUT = 15.0

#: Wordlist incorporata di segreti HMAC comuni, provati per primi perché
#: ricorrenti in configurazioni di default, tutorial e ambienti di test.
_WEAK_SECRETS: tuple[str, ...] = (
    "secret",
    "password",
    "changeme",
    "jwt",
    "key",
    "admin",
    "test",
    "crapi",
    "0",
    "123456",
)

#: Varianti di maiuscole/minuscole di ``alg=none`` da forgiare. Alcuni server
#: fanno il match dell'algoritmo in modo case-insensitive o confrontano con una
#: forma capitalizzata: si prova ciascuna variante e basta che UNA sia accettata.
_ALG_NONE_VARIANTS: tuple[str, ...] = ("none", "None", "NONE")

#: Mappa dell'algoritmo HMAC dichiarato nell'header sul relativo hash stdlib.
_HMAC_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_decode(segment: str) -> bytes:
    """Decodifica un segmento base64url (senza padding) in byte.

    Reintegra il padding ``=`` mancante prima di decodificare, così i segmenti
    JWT (che il padding non lo hanno) si decodificano correttamente.
    """
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(raw: bytes) -> str:
    """Codifica byte in base64url senza padding (forma usata dai JWT)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_jwt(token: str) -> tuple[dict, str, str] | None:
    """Decodifica header e segmenti di un JWT **senza** verificarne la firma.

    Restituisce ``(header_dict, header_segment, payload_segment)`` oppure
    ``None`` se il token è malformato (meno di due segmenti, base64 non valido,
    header non-JSON). Non solleva mai: un token malformato è semplicemente
    "niente da controllare" per il chiamante.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header_segment, payload_segment = parts[0], parts[1]
        header = json.loads(_b64url_decode(header_segment))
        if not isinstance(header, dict):
            return None
        return header, header_segment, payload_segment
    except Exception:
        return None


def _request_forged(
    probe_url: str,
    forged_token: str,
    session_headers: dict,
    reachability: str,
) -> httpx.Response | None:
    """Invia la ``GET`` di sonda con il token forgiato, o ``None`` su errore.

    Riusa gli header di sessione ma **sovrascrive** ``Authorization`` col token
    forgiato. I redirect non sono seguiti (un ``302`` verso il login non deve
    passare per ``2xx``). ``url`` resta quello originale già gateato dal
    chiamante; la rimappatura host-side (docker) avviene solo qui, per la
    connessione effettiva, senza poter creare bypass dell'allowlist.
    """
    headers = dict(session_headers)
    headers["Authorization"] = f"Bearer {forged_token}"
    try:
        return httpx.request(
            "GET",
            host_side_url(probe_url, reachability),
            headers=headers,
            follow_redirects=False,
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError:
        return None


def _is_2xx(response: httpx.Response | None) -> bool:
    return response is not None and 200 <= response.status_code < 300


def _alg_none_finding(
    probe_url: str, response: httpx.Response, marker: str, alg: str, lang: str
) -> Finding:
    return Finding(
        source="jwt",
        severity="critica",
        title=t(lang, "jwt_alg_none_title"),
        description=t(lang, "jwt_alg_none_desc", url=probe_url, status=response.status_code),
        evidence=t(
            lang,
            "jwt_alg_none_evidence",
            url=probe_url,
            status=response.status_code,
            marker=marker,
            alg=alg,
        ),
        fix=t(lang, "jwt_alg_none_fix"),
        impact_if_ignored=t(lang, "jwt_alg_none_impact"),
        confidence=1.0,
        url=probe_url,
    )


def _unverified_finding(
    probe_url: str, response: httpx.Response, marker: str, alg: str, lang: str
) -> Finding:
    """Finding ``alta`` (confidenza 0.6) per firma non verificata / non-auth.

    Emesso quando il **controllo negativo** (token a firma corrotta, stesso
    ``alg`` del token reale) viene comunque accettato sulla sonda: l'endpoint non
    verifica affatto la firma, oppure è di fatto non autenticato. Il meccanismo
    preciso è ambiguo (potrebbe essere ``alg=none``, ma anche un endpoint
    pubblico): perciò **non** si asserisce ``alg=none`` e la confidenza resta
    sotto 1.0.
    """
    return Finding(
        source="jwt",
        severity="alta",
        title=t(lang, "jwt_unverified_title"),
        description=t(
            lang, "jwt_unverified_desc", url=probe_url, status=response.status_code, alg=alg
        ),
        evidence=t(
            lang,
            "jwt_unverified_evidence",
            url=probe_url,
            status=response.status_code,
            marker=marker,
            alg=alg,
        ),
        fix=t(lang, "jwt_unverified_fix"),
        impact_if_ignored=t(lang, "jwt_unverified_impact"),
        confidence=0.6,
        url=probe_url,
    )


def _weak_secret_finding(secret: str, alg: str, lang: str) -> Finding:
    return Finding(
        source="jwt",
        severity="critica",
        title=t(lang, "jwt_weak_secret_title", secret=secret),
        description=t(lang, "jwt_weak_secret_desc", secret=secret, alg=alg),
        evidence=t(lang, "jwt_weak_secret_evidence", secret=secret, alg=alg),
        fix=t(lang, "jwt_weak_secret_fix"),
        impact_if_ignored=t(lang, "jwt_weak_secret_impact"),
        confidence=1.0,
        url=None,
    )


#: Firma deliberatamente non valida usata dal controllo negativo. Qualunque
#: server che verifichi davvero la firma la rifiuta; solo un server che non
#: verifica affatto (o un endpoint non autenticato) la accetta.
_CORRUPTED_SIGNATURE = _b64url_encode(b"gauntlet-deliberately-invalid-signature")


def _control_token(header_segment: str, payload_segment: str) -> str:
    """Token di controllo negativo: stesso header/payload del token reale (quindi
    **stesso** ``alg``) ma firma deliberatamente CORROTTA.

    Un server che verifica la firma deve rifiutarlo. Se lo accetta, non verifica
    la firma del token (o l'endpoint è di fatto non autenticato): il controllo è
    il discriminante che impedisce di scambiare un endpoint pubblico per una
    vulnerabilità ``alg=none``.
    """
    return f"{header_segment}.{payload_segment}.{_CORRUPTED_SIGNATURE}"


def _check_alg_none(
    header_segment: str,
    payload_segment: str,
    real_alg: str,
    probe_url: str,
    marker: str | None,
    session_headers: dict,
    reachability: str,
    lang: str,
) -> list[Finding]:
    """Controlla l'accettazione di un token ``alg=none`` sulla sonda.

    **Controllo negativo prima di tutto.** Si invia un token a firma corrotta
    (stesso ``alg`` del token reale, :func:`_control_token`) alla stessa sonda
    già gateata. Due esiti:

    * Il controllo è **rifiutato** (non ``2xx``, o marcatore assente): il server
      verifica le firme. Allora si prova la variante ``alg=none`` e, se **una**
      è accettata (``2xx`` + marcatore), la verifica è aggirabile => ``critica``
      ``alg=none`` (un solo finding, che annota la variante).
    * Il controllo è **anch'esso accettato** (``2xx`` + marcatore): l'endpoint
      non verifica affatto la firma / è di fatto non autenticato. Il meccanismo
      è ambiguo: **non** si asserisce ``alg=none`` ma un finding più morbido
      (``alta``, 0.6, :func:`_unverified_finding`).
    * Il controllo **non è stato inviato/valutato** (``None``: errore di
      trasporto): l'oracolo non è stabilito. Fail-closed => ``[]`` (nessun claim).
      Un fallimento del controllo non è un suo rifiuto.

    Forgia ``base64url({"alg":<variante>,"typ":"JWT"}).<payload originale>.``
    (firma vuota, stessa payload del token reale) per ciascuna variante di
    maiuscole in :data:`_ALG_NONE_VARIANTS` (``none``/``None``/``NONE``). Senza un
    ``marker`` noto il controllo non è deterministico e si ripiega su ``[]``: non
    si asserisce mai un'accettazione sul solo status code. Tutte le richieste
    passano per l'unico gate allowlist già applicato dal chiamante su ``probe_url``.
    """
    if marker is None:
        return []

    # Controllo negativo: prova che il server RIFIUTA una firma non valida.
    control = _request_forged(
        probe_url, _control_token(header_segment, payload_segment), session_headers, reachability
    )
    if control is None:
        # Il controllo non è stato inviato/valutato (errore di trasporto:
        # timeout/connessione): l'oracolo NON è stabilito. Fail-closed => nessun
        # claim, né la 'critica' alg=none né il finding morbido. Stesso principio
        # dell'IDOR sequenziale, che salta quando l'oracolo non è determinabile:
        # un FALLIMENTO del controllo non va mai scambiato per un suo RIFIUTO.
        return []
    if _is_2xx(control) and marker in control.text:
        # Il controllo è ACCETTATO: firma non verificata / endpoint non
        # autenticato. Meccanismo ambiguo => niente 'alg=none', finding morbido.
        return [_unverified_finding(probe_url, control, marker, real_alg, lang)]

    # Controllo RIFIUTATO (il server verifica le firme): ora la sonda alg=none.
    for variant in _ALG_NONE_VARIANTS:
        forged_header = _b64url_encode(
            json.dumps({"alg": variant, "typ": "JWT"}, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        forged_token = f"{forged_header}.{payload_segment}."
        response = _request_forged(probe_url, forged_token, session_headers, reachability)
        if _is_2xx(response) and marker in response.text:
            return [_alg_none_finding(probe_url, response, marker, variant, lang)]
    return []


def _check_weak_secret(
    header: dict,
    header_segment: str,
    payload_segment: str,
    token: str,
    lang: str,
) -> list[Finding]:
    """Controlla se la firma HMAC del token reale usa un segreto debole.

    Applicabile solo agli algoritmi ``HS*``: ricalcola l'HMAC su
    ``header.payload`` con ciascun segreto della wordlist e confronta la firma
    (base64url, senza padding) con quella del token. Per alg non-HMAC ritorna
    ``[]`` (controllo non applicabile).
    """
    alg = header.get("alg")
    hash_factory = _HMAC_HASHES.get(alg) if isinstance(alg, str) else None
    if hash_factory is None:
        return []
    parts = token.split(".")
    if len(parts) != 3:
        return []
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    actual_signature = parts[2]
    for secret in _WEAK_SECRETS:
        digest = hmac.new(secret.encode("utf-8"), signing_input, hash_factory).digest()
        if hmac.compare_digest(_b64url_encode(digest), actual_signature):
            return [_weak_secret_finding(secret, alg, lang)]
    return []


def run(
    token: str,
    probe_url: str,
    marker: str | None,
    session_headers: dict,
    *,
    contract: Contract,
    reachability: str,
    lang: str = "it",
) -> list[Finding]:
    """Esegue i controlli di debolezza JWT e restituisce i :class:`Finding`.

    :param token: il JWT reale ottenuto al login (senza il prefisso ``Bearer``).
    :param probe_url: URL assoluto di una risorsa protetta nota, usato come sonda.
    :param marker: marcatore atteso nel corpo della sonda (oracolo di
        accettazione per il controllo ``alg=none``); ``None`` disabilita quel
        controllo (non deterministico senza marcatore).
    :param session_headers: header della sessione autenticata; ``Authorization``
        viene sovrascritto col token forgiato nelle richieste di sonda.
    :param contract: contratto del progetto; il suo ``allowed_targets`` alimenta
        il gate allowlist fail-closed valutato **prima** di qualunque richiesta.
    :param reachability: modalità di raggiungibilità (``localhost``/``docker``/…),
        propagata alla rimappatura host-side per la sola connessione effettiva.
    :param lang: lingua dei :class:`Finding` prodotti (``"it"`` default o ``"en"``).

    :returns: lista di finding (vuota se nulla è debole: un server corretto non
        genera finding JWT — comportamento atteso). Un token malformato, una
        sonda fuori allowlist o un errore di trasporto restituiscono ``[]`` senza
        sollevare.
    """
    # Gate allowlist fail-closed sull'URL ORIGINALE: una sonda fuori allowlist non
    # genera alcun traffico e il modulo non produce finding.
    try:
        assert_target_allowed(contract, probe_url)
    except TargetNotAllowed:
        return []

    decoded = _decode_jwt(token)
    if decoded is None:
        return []
    header, header_segment, payload_segment = decoded

    real_alg = header.get("alg")
    real_alg = real_alg if isinstance(real_alg, str) else str(real_alg)

    findings: list[Finding] = []
    findings.extend(
        _check_alg_none(
            header_segment,
            payload_segment,
            real_alg,
            probe_url,
            marker,
            session_headers,
            reachability,
            lang,
        )
    )
    findings.extend(
        _check_weak_secret(header, header_segment, payload_segment, token, lang)
    )
    return findings
