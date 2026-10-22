"""Tester di controllo-accessi: isolamento tra tenant (il gioiello della corona).

Questo modulo risponde alla domanda più importante di tutta la skill: *un
cliente può raggiungere i dati di un altro cliente?* Lo fa in modo
**deterministico**, con un oracolo di proprietà, per non produrre né falsi
positivi né falsi negativi.

Due famiglie di controlli:

* **Orizzontale (IDOR/BOLA).** Per ogni risorsa seminata del tenant A, la stessa
  GET viene rigiocata con la sessione del tenant B (l'altro cliente). Il leak è
  **confermato** soltanto quando B riceve ``2xx`` **e** nel corpo compare il
  *marcatore noto del seed* di A (:attr:`Resource.seed_marker` **esplicito**).
  L'``id`` **non** è usato come marcatore di ripiego: è interpolato anche
  nell'URL, quindi un corpo che lo riflette (soft-404, self-link, envelope
  d'errore) non prova nulla. Senza ``seed_marker`` esplicito il test del leak è
  saltato e si emette solo la nota info. Status ``401/403/404`` e risposte
  ``2xx`` prive del marcatore (lista vuota compresa) sono "negato": nessun
  finding. Non si segnala mai sul solo status code — è proprio il marcatore a
  distinguere un accesso reale ai dati di A da una pagina anonima o da una
  risposta vuota.

* **Verticale (escalation di privilegi).** Un utente normale prova a raggiungere
  endpoint amministrativi noti (tra cui quelli di Directus). Un ``2xx`` è un
  finding: l'utente arriva dove non dovrebbe.

**Sicurezza.** La modalità di default è ``read-only``: solo GET, mai scritture.
In ``write`` ogni tentativo di modifica passa prima per
:func:`gauntlet.safety.confirm_destructive`; senza via libera esplicito il
tentativo è semplicemente saltato (il run non viene interrotto).

Nota di progettazione (divergenza segnalata per adjudication). Il piano fissa la
sola firma di :func:`run` e un ``Resource`` con ``kind``/``id``/``url_template``.
L'oracolo di proprietà richiede però un marcatore noto: è stato aggiunto a
``Resource`` il campo **opzionale** ``seed_marker`` (default ``None``),
retro-compatibile col parser e con i contratti esistenti. Inoltre
:func:`run` espone il solo parametro **keyword-only opzionale** ``base_url`` per
risolvere ``url_template`` scritti come path relativi; la forma documentata resta
invariata.
"""

from __future__ import annotations

from typing import Callable, Literal
from urllib.parse import urlsplit

import httpx

from gauntlet.authn import Session
from gauntlet.contract import Account, Contract, Resource
from gauntlet.i18n import t
from gauntlet.models import Finding
from gauntlet.safety import (
    TargetNotAllowed,
    assert_target_allowed,
    confirm_destructive,
    host_side_url,
)

Mode = Literal["read-only", "write"]

#: Endpoint amministrativi noti sondati nel test verticale. Mix di path admin
#: generici e di API privilegiate di Directus (CMS/headless molto diffuso nei
#: progetti target). Sono volutamente endpoint che un utente normale non deve
#: poter leggere: un ``2xx`` qui è escalation verticale.
ADMIN_ENDPOINTS: tuple[str, ...] = (
    "/admin",
    "/admin/users",
    "/admin/settings",
    "/server/info",      # Directus: info di progetto, admin-only
    "/roles",            # Directus: elenco ruoli
    "/permissions",      # Directus: regole dei permessi
    "/collections",      # Directus: schema delle collezioni
    "/settings",         # Directus: impostazioni di progetto
    "/activity",         # Directus: audit log
    "/flows",            # Directus: automazioni
    "/presets",          # Directus: preset/bookmark globali
)

#: Timeout per ogni richiesta replay (secondi).
_TIMEOUT = 15.0

#: Marcatore scritto dalla sonda PATCH cross-tenant in modalità ``write``. Dopo
#: una PATCH 2xx, una re-GET come proprietario deve mostrare questo valore nel
#: corpo per confermare che la scrittura ha davvero mutato la risorsa della
#: vittima (vedi :func:`_run_horizontal`): è l'oracolo che evita una ``critica``
#: basata sul solo status code.
_WRITE_PROBE_MARKER = "gauntlet-write-probe-marker"

#: Sessione completamente anonima (nessun header, nessun cookie) usata dal
#: controllo di autenticazione mancante: la si passa a :func:`_request` per
#: riusarne il gating/trasporto senza mai inviare credenziali.
_ANONYMOUS_SESSION = Session(cookies={}, headers={}, label="anonimo")


class OwnershipMap:
    """Oracolo di proprietà costruito dagli ``accounts``.

    Sa quale :class:`Resource` appartiene a quale etichetta di account e quali
    sono gli *altri* tenant (i candidati attaccanti per il test orizzontale).
    """

    def __init__(self, accounts: list[Account]) -> None:
        self._labels: list[str] = [a.label for a in accounts]
        #: Username per etichetta: identità dell'account, usata solo come
        #: etichetta descrittiva nei finding del fuzzing IDOR sequenziale (E2).
        #: L'oracolo di confronto NON è più lo username (poteva stare in un
        #: namespace diverso dall'``owner_field``): si confronta il valore
        #: ``owner_field`` del vicino con quello della risorsa propria.
        self.username_by_label: dict[str, str] = {a.label: a.username for a in accounts}
        self.entries: list[tuple[str, Resource]] = []
        for account in accounts:
            for resource in account.seeded_resources:
                self.entries.append((account.label, resource))

    def other_labels(self, owner_label: str) -> list[str]:
        """Etichette di tutti gli altri tenant (candidati attaccanti)."""
        return [label for label in self._labels if label != owner_label]


def _has_scheme(url: str) -> bool:
    return bool(urlsplit(url).scheme)


def _resolve_url(resource: Resource, base_url: str | None) -> str | None:
    """Costruisce l'URL assoluto della risorsa, o ``None`` se non risolvibile.

    Sostituisce ``{id}`` con ``resource.id``. Un ``url_template`` già assoluto è
    usato così com'è; un path relativo richiede ``base_url``.
    """
    template = resource.url_template
    url = template.format(id=resource.id) if "{id}" in template else template
    if _has_scheme(url):
        return url
    if base_url:
        return base_url.rstrip("/") + "/" + url.lstrip("/")
    return None


def _resolve_neighbor_url(
    resource: Resource, neighbor_id: int, base_url: str | None
) -> str | None:
    """URL assoluto del vicino ``neighbor_id``, o ``None`` se non risolvibile.

    Identico a :func:`_resolve_url` ma sostituisce ``{id}`` con un ID vicino
    (per il fuzzing IDOR sequenziale) invece che con ``resource.id``.
    """
    template = resource.url_template
    url = template.format(id=neighbor_id) if "{id}" in template else template
    if _has_scheme(url):
        return url
    if base_url:
        return base_url.rstrip("/") + "/" + url.lstrip("/")
    return None


def _neighbor_ids(base_id: int, count: int) -> list[int]:
    """ID vicini ``base_id-count .. base_id+count``, escluso ``base_id`` e gli <1.

    Limitato da ``count`` (volutamente piccolo): il fuzzing resta di superficie,
    sola lettura e circoscritto agli ID adiacenti alla risorsa seminata.
    """
    ids: list[int] = []
    for delta in range(-count, count + 1):
        if delta == 0:
            continue
        candidate = base_id + delta
        if candidate < 1:
            continue
        ids.append(candidate)
    return ids


def _owner_value(response: httpx.Response, owner_field: str) -> str | None:
    """Valore di ``owner_field`` nel corpo JSON della risposta, o ``None``.

    ``None`` se il corpo non è JSON, non è un oggetto, o il campo è assente o
    vuoto: in tutti questi casi non c'è oracolo di proprietà e il chiamante non
    asserisce alcun leak (nessun falso positivo sul solo status).
    """
    try:
        data = response.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    value = data.get(owner_field)
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _request(
    method: str,
    url: str,
    session: Session,
    reachability: str = "localhost",
    **kwargs,
) -> httpx.Response | None:
    """Esegue una richiesta come ``session`` (cookie + header), o ``None``.

    I redirect non sono seguiti: un ``302`` verso il login non deve essere
    scambiato per un ``2xx``. Gli errori di trasporto restituiscono ``None`` e
    non interrompono il run.

    ``url`` è sempre l'URL *originale* del contratto: il gate allowlist dei
    chiamanti va valutato su quello. Qui, e solo per la connessione host-side
    effettiva, in modalità ``docker`` un host ``host.docker.internal`` è rimappato
    su ``127.0.0.1`` (vedi :func:`gauntlet.safety.host_side_url`); fuori da
    docker l'URL è invariato. La rimappatura avviene dopo il gate dei chiamanti,
    quindi non può creare alcun bypass dell'allowlist.
    """
    try:
        return httpx.request(
            method,
            host_side_url(url, reachability),
            cookies=session.cookies,
            headers=session.headers,
            follow_redirects=False,
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError:
        return None


def _is_2xx(response: httpx.Response | None) -> bool:
    return response is not None and 200 <= response.status_code < 300


def _body_contains_marker(response: httpx.Response, marker: str) -> bool:
    try:
        return marker in response.text
    except Exception:  # pragma: no cover - corpo non testuale/decodificabile
        return False


def _horizontal_finding(
    url: str,
    owner_label: str,
    attacker_label: str,
    response: httpx.Response,
    marker: str,
    lang: str,
) -> Finding:
    return Finding(
        source="access-control",
        severity="critica",
        title=t(lang, "ac_horizontal_title"),
        description=t(
            lang,
            "ac_horizontal_desc",
            attacker_label=attacker_label,
            url=url,
            owner_label=owner_label,
            status=response.status_code,
            marker=marker,
        ),
        evidence=t(
            lang,
            "ac_horizontal_evidence",
            url=url,
            attacker_label=attacker_label,
            status=response.status_code,
            marker=marker,
            extract=repr(response.text[:200]),
        ),
        fix=t(lang, "ac_horizontal_fix"),
        impact_if_ignored=t(lang, "ac_horizontal_impact"),
        confidence=1.0,
        url=url,
    )


def _sequential_idor_finding(
    url: str,
    owner_label: str,
    username: str,
    owner_field: str,
    leaked_owner: str,
    response: httpx.Response,
    lang: str,
) -> Finding:
    """Finding ``critica`` per un IDOR su ID sequenziale confermato dall'oracolo.

    Emesso solo quando l'account che sonda (``owner_label``/``username``) ha
    ottenuto ``2xx`` su un ID vicino il cui ``owner_field`` nel corpo rivela un
    proprietario **diverso** dal proprio username: prova deterministica di aver
    letto l'oggetto di un altro proprietario indovinando l'ID.
    """
    return Finding(
        source="access-control",
        severity="critica",
        title=t(lang, "ac_seqidor_title"),
        description=t(
            lang,
            "ac_seqidor_desc",
            owner_label=owner_label,
            username=username,
            url=url,
            status=response.status_code,
            owner_field=owner_field,
            leaked_owner=leaked_owner,
        ),
        evidence=t(
            lang,
            "ac_seqidor_evidence",
            url=url,
            owner_label=owner_label,
            username=username,
            status=response.status_code,
            owner_field=owner_field,
            leaked_owner=leaked_owner,
            extract=repr(response.text[:200]),
        ),
        fix=t(lang, "ac_seqidor_fix"),
        impact_if_ignored=t(lang, "ac_seqidor_impact"),
        confidence=1.0,
        url=url,
    )


def _horizontal_write_finding(
    url: str,
    owner_label: str,
    attacker_label: str,
    response: httpx.Response,
    *,
    confirmed: bool,
    lang: str,
) -> Finding:
    """Finding di scrittura cross-tenant.

    ``confirmed`` distingue due esiti ben diversi:

    * ``True`` — la scrittura è stata **verificata**: una re-GET come
      proprietario mostra il marcatore della sonda nel corpo, quindi la PATCH
      dell'attaccante ha davvero mutato la risorsa della vittima. Gravità
      ``critica`` (confidenza 1.0).
    * ``False`` — la PATCH ha risposto ``2xx`` ma la mutazione **non** è stata
      confermata sulla risorsa della vittima (re-GET impossibile o marcatore
      assente). Non si asserisce mai una ``critica`` sul solo status: gravità
      ``alta``, confidenza ridotta, etichettata NON CONFERMATA.
    """
    if confirmed:
        return Finding(
            source="access-control",
            severity="critica",
            title=t(lang, "ac_write_confirmed_title"),
            description=t(
                lang,
                "ac_write_confirmed_desc",
                attacker_label=attacker_label,
                url=url,
                owner_label=owner_label,
                status=response.status_code,
            ),
            evidence=t(
                lang,
                "ac_write_confirmed_evidence",
                url=url,
                attacker_label=attacker_label,
                status=response.status_code,
                owner_label=owner_label,
                probe=_WRITE_PROBE_MARKER,
            ),
            fix=t(lang, "ac_write_confirmed_fix"),
            impact_if_ignored=t(lang, "ac_write_confirmed_impact"),
            confidence=1.0,
            url=url,
        )
    return Finding(
        source="access-control",
        severity="alta",
        title=t(lang, "ac_write_unconfirmed_title"),
        description=t(
            lang,
            "ac_write_unconfirmed_desc",
            attacker_label=attacker_label,
            status=response.status_code,
            url=url,
            owner_label=owner_label,
        ),
        evidence=t(
            lang,
            "ac_write_unconfirmed_evidence",
            url=url,
            attacker_label=attacker_label,
            status=response.status_code,
        ),
        fix=t(lang, "ac_write_unconfirmed_fix"),
        impact_if_ignored=t(lang, "ac_write_unconfirmed_impact"),
        confidence=0.5,
        url=url,
    )


def _vertical_finding(
    url: str, actor_label: str, response: httpx.Response, lang: str
) -> Finding:
    return Finding(
        source="access-control",
        severity="alta",
        title=t(lang, "ac_vertical_title"),
        description=t(
            lang,
            "ac_vertical_desc",
            actor_label=actor_label,
            url=url,
            status=response.status_code,
        ),
        evidence=t(
            lang,
            "ac_vertical_evidence",
            url=url,
            actor_label=actor_label,
            status=response.status_code,
            extract=repr(response.text[:200]),
        ),
        fix=t(lang, "ac_vertical_fix"),
        impact_if_ignored=t(lang, "ac_vertical_impact"),
        confidence=0.6,
        url=url,
    )


def _needs_marker_finding(
    url: str, owner_label: str, resource: Resource, lang: str
) -> Finding:
    return Finding(
        source="access-control",
        severity="info",
        title=t(lang, "ac_marker_title"),
        description=t(
            lang,
            "ac_marker_desc",
            url=url,
            owner_label=owner_label,
            resource_id=resource.id,
        ),
        evidence=t(
            lang,
            "ac_marker_evidence",
            kind=resource.kind,
            resource_id_repr=repr(resource.id),
        ),
        fix=t(lang, "ac_marker_fix"),
        impact_if_ignored=t(lang, "ac_marker_impact"),
        confidence=1.0,
        url=url,
    )


def _anonymous_finding(
    url: str, owner_label: str, response: httpx.Response, marker: str, lang: str
) -> Finding:
    """Finding ``critica`` per una risorsa protetta servita in anonimo.

    Emesso solo quando una GET **senza** ``Authorization`` e **senza** cookie
    riceve ``2xx`` **e** il marcatore del seed compare nel corpo: prova
    deterministica che il contenuto protetto è servito a un client non
    autenticato (oracolo del marcatore, nessuna ``critica`` sul solo status).
    """
    return Finding(
        source="access-control",
        severity="critica",
        title=t(lang, "ac_noauth_title"),
        description=t(
            lang,
            "ac_noauth_desc",
            url=url,
            owner_label=owner_label,
            status=response.status_code,
            marker=marker,
        ),
        evidence=t(
            lang,
            "ac_noauth_evidence",
            url=url,
            status=response.status_code,
            marker=marker,
            extract=repr(response.text[:200]),
        ),
        fix=t(lang, "ac_noauth_fix"),
        impact_if_ignored=t(lang, "ac_noauth_impact"),
        confidence=1.0,
        url=url,
    )


def _is_allowed(contract: Contract, url: str) -> bool:
    """``True`` se ``url`` supera il gate allowlist fail-closed del contratto.

    Avvolge :func:`gauntlet.safety.assert_target_allowed`: un'origine non in
    ``allowed_targets`` (:class:`TargetNotAllowed`) restituisce ``False`` senza
    propagare, così il chiamante salta la richiesta senza interrompere il run.
    """
    try:
        assert_target_allowed(contract, url)
        return True
    except TargetNotAllowed:
        return False


def _run_sequential_idor(
    resource: Resource,
    owner_label: str,
    owner_username: str,
    owner_session: Session | None,
    contract: Contract,
    base_url: str | None,
    lang: str,
) -> list[Finding]:
    """Fuzzing IDOR su ID sequenziali per una singola risorsa seminata (E2).

    Esegue solo se ``resource.enumerate`` è ``True``, l'``id`` è numerico e
    ``owner_field`` è dichiarato. Come **proprietario**, sonda in sola lettura
    (GET) gli ID vicini (``id ± enumerate_count``): ogni URL passa prima per il
    gate allowlist fail-closed (:func:`_is_allowed`), identico al resto del
    modulo.

    L'oracolo di proprietà è costruito nello **stesso namespace** del campo
    ``owner_field``: prima si fa la GET della risorsa **propria** (quella
    seminata, allowlist-gated anch'essa) e si legge il suo ``owner_field`` ->
    ``self_owner``. Un vicino è un IDOR confermato solo se risponde ``2xx`` **e**
    il suo ``owner_field`` è presente **e diverso da ``self_owner``**. Confronta
    cioè valore-owner con valore-owner nello stesso campo, non con lo *username*
    dell'account (che potrebbe essere in un namespace diverso — p.es. email vs
    user_id numerico — e differire sempre, generando falsi positivi).

    Se ``self_owner`` non è determinabile (``owner_field`` assente/vuoto sulla
    propria risorsa, o la GET non è ``2xx``), il test è **saltato**: senza oracolo
    non si asserisce nulla. Assenza del campo sul vicino, valore uguale al proprio
    o corpo non-JSON => nessun finding.
    """
    if not resource.enumerate or not resource.owner_field:
        return []
    if not resource.id.isdecimal():
        # ID non convertibile a int con int() (UUID, ma anche cifre Unicode non
        # decimali come gli apici che str.isdigit() accetterebbe): non enumerabile
        # per vicinanza, nessun probe. isdecimal() è il predicato esatto per int().
        return []
    if owner_session is None:
        return []

    # Identità di proprietà dell'account nello STESSO namespace: GET della propria
    # risorsa seminata (allowlist-gated) e lettura del suo owner_field.
    own_url = _resolve_url(resource, base_url)
    if own_url is None:
        return []
    if not _is_allowed(contract, own_url):
        return []
    own_response = _request("GET", own_url, owner_session, contract.reachability)
    if not _is_2xx(own_response):
        return []
    self_owner = _owner_value(own_response, resource.owner_field)
    if self_owner is None:
        # Oracolo non stabilibile (owner_field assente/vuoto sulla propria
        # risorsa): non si può distinguere il proprio da altrui => nessun test.
        return []

    findings: list[Finding] = []
    base_id = int(resource.id)
    for neighbor_id in _neighbor_ids(base_id, resource.enumerate_count):
        url = _resolve_neighbor_url(resource, neighbor_id, base_url)
        if url is None:
            continue
        # Gate allowlist fail-closed su OGNI vicino prima di qualsiasi richiesta.
        if not _is_allowed(contract, url):
            continue
        response = _request("GET", url, owner_session, contract.reachability)
        if not _is_2xx(response):
            continue
        leaked_owner = _owner_value(response, resource.owner_field)
        if leaked_owner is None or leaked_owner == self_owner:
            # Nessun oracolo, oppure oggetto proprio: nessun leak da asserire.
            continue
        findings.append(
            _sequential_idor_finding(
                url,
                owner_label,
                owner_username,
                resource.owner_field,
                leaked_owner,
                response,
                lang,
            )
        )
    return findings


def _run_horizontal(
    sessions: dict[str, Session],
    omap: OwnershipMap,
    contract: Contract,
    mode: Mode,
    confirm: Callable[[str], bool] | None,
    base_url: str | None,
    lang: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for owner_label, resource in omap.entries:
        # Fuzzing IDOR su ID sequenziali (E2): sonda i vicini dell'ID come
        # proprietario, con oracolo di proprietà. Additivo e read-only; attivo
        # solo per risorse con enumerate=True (vedi _run_sequential_idor).
        findings.extend(
            _run_sequential_idor(
                resource,
                owner_label,
                omap.username_by_label.get(owner_label, ""),
                sessions.get(owner_label),
                contract,
                base_url,
                lang,
            )
        )

        url = _resolve_url(resource, base_url)
        if url is None:
            continue
        # Gate allowlist fail-closed sull'URL risolto (anche se il template era
        # già assoluto): se l'origine non è consentita non parte NESSUNA
        # richiesta verso quella risorsa.
        if not _is_allowed(contract, url):
            continue
        # L'oracolo del leak cross-tenant richiede un ``seed_marker`` ESPLICITO.
        # L'``id`` NON è più usato come marcatore di ripiego: è interpolato anche
        # nell'URL della richiesta, quindi un corpo 2xx che si limita a riflettere
        # l'id richiesto (soft-404, self-link, envelope d'errore) non prova alcun
        # accesso ai dati della vittima. Senza marcatore esplicito non si asserisce
        # alcun leak: si emette solo la nota info (richiesta di seed_marker).
        marker = resource.seed_marker or None
        if marker is None:
            # Nessun marcatore dichiarato => niente oracolo deterministico. Non si
            # asserisce mai una 'critica': si segnala (info) perché l'utente
            # dichiari un seed_marker, e si salta il test del leak.
            findings.append(_needs_marker_finding(url, owner_label, resource, lang))

        for attacker_label in omap.other_labels(owner_label):
            attacker = sessions.get(attacker_label)
            if attacker is None:
                continue

            # Lettura del leak (solo con un marcatore reale, anche in read-only).
            if marker is not None:
                response = _request("GET", url, attacker, contract.reachability)
                if _is_2xx(response) and _body_contains_marker(response, marker):
                    findings.append(
                        _horizontal_finding(
                            url, owner_label, attacker_label, response, marker, lang
                        )
                    )

            # Scrittura (solo in write, e solo dietro conferma distruttiva).
            if mode == "write":
                description = (
                    f"Tentativo di scrittura cross-tenant su {url} come "
                    f"'{attacker_label}' (verifica IDOR in scrittura)."
                )
                if confirm_destructive(description, confirm):
                    w_response = _request(
                        "PATCH",
                        url,
                        attacker,
                        contract.reachability,
                        json={"gauntlet_probe": _WRITE_PROBE_MARKER},
                    )
                    if _is_2xx(w_response):
                        # Nessuna 'critica' sul solo status: si verifica che la
                        # scrittura abbia davvero mutato la risorsa della vittima
                        # rileggendola come proprietario e cercando il marcatore
                        # della sonda. Senza conferma => finding 'alta' NON
                        # CONFERMATA (vedi _horizontal_write_finding).
                        confirmed = _write_took_effect(
                            url, sessions.get(owner_label), contract.reachability
                        )
                        findings.append(
                            _horizontal_write_finding(
                                url,
                                owner_label,
                                attacker_label,
                                w_response,
                                confirmed=confirmed,
                                lang=lang,
                            )
                        )
                # Se non confermato: si salta, senza interrompere il run.
    return findings


def _write_took_effect(
    url: str, owner_session: Session | None, reachability: str = "localhost"
) -> bool:
    """Conferma che la PATCH ha mutato la risorsa della vittima.

    Rilegge ``url`` come **proprietario** e verifica che il marcatore della
    sonda (:data:`_WRITE_PROBE_MARKER`) compaia ora nel corpo. Se la sessione
    del proprietario non è disponibile, la re-GET fallisce o il marcatore è
    assente, restituisce ``False``: la scrittura non è confermata.

    ``reachability`` è propagato a :func:`_request` per la rimappatura host-side
    in docker mode; l'URL resta quello originale già gateato dal chiamante.
    """
    if owner_session is None:
        return False
    verify = _request("GET", url, owner_session, reachability)
    return _is_2xx(verify) and _body_contains_marker(verify, _WRITE_PROBE_MARKER)


def _derive_origin(omap: OwnershipMap, base_url: str | None) -> str | None:
    """Origine (schema://host:porta) su cui sondare gli endpoint admin.

    Preferisce ``base_url``; altrimenti la ricava dalla prima risorsa seminata
    con URL assoluto, così il test verticale colpisce lo stesso host dell'app.
    """
    if base_url:
        return _origin_of(base_url if _has_scheme(base_url) else "http://" + base_url)
    for _label, resource in omap.entries:
        url = _resolve_url(resource, None)
        if url and (origin := _origin_of(url)):
            return origin
    return None


def _admin_endpoints_for(contract: Contract) -> list[str]:
    """Lista degli endpoint admin da sondare: generici + quelli del contratto.

    Unisce :data:`ADMIN_ENDPOINTS` con ``contract.admin_endpoints`` (specifici
    del progetto) deduplicando e preservando l'ordine: prima i generici, poi gli
    extra del contratto non già presenti. Se il contratto non ne dichiara, resta
    la sola lista generica. Il gate allowlist su ogni URL (in :func:`_run_vertical`)
    non è toccato: ogni endpoint, generico o custom, resta allowlist-gated.
    """
    endpoints: list[str] = list(ADMIN_ENDPOINTS)
    seen = set(endpoints)
    for endpoint in contract.admin_endpoints:
        if endpoint not in seen:
            endpoints.append(endpoint)
            seen.add(endpoint)
    return endpoints


def _run_vertical(
    sessions: dict[str, Session], contract: Contract, origin: str | None, lang: str
) -> list[Finding]:
    findings: list[Finding] = []
    if origin is None:
        return findings
    # Solo endpoint amministrativi *reali*: i generici più quelli dichiarati nel
    # contratto. Gli endpoint meramente *scoperti* (doc/sorgente) NON entrano qui:
    # senza proprietario né marcatore non sono admin per definizione, e un loro
    # 2xx da utente normale è atteso, non un'escalation (eviterebbe falsi 'alta').
    admin_endpoints = _admin_endpoints_for(contract)
    for actor_label, session in sessions.items():
        for endpoint in admin_endpoints:
            url = origin.rstrip("/") + endpoint
            # Gate allowlist fail-closed su ogni URL admin prima di sondarlo.
            if not _is_allowed(contract, url):
                continue
            response = _request("GET", url, session, contract.reachability)
            if _is_2xx(response):
                findings.append(_vertical_finding(url, actor_label, response, lang))
    return findings


def _run_missing_auth(
    omap: OwnershipMap,
    contract: Contract,
    base_url: str | None,
    lang: str,
) -> list[Finding]:
    """Controllo di autenticazione mancante/rotta (complemento del cross-tenant).

    Per ogni risorsa seminata che dichiara un ``seed_marker``, risolve l'URL e la
    richiede in GET **anonima**: nessun header ``Authorization`` e nessun cookie
    (vedi :data:`_ANONYMOUS_SESSION`). Ogni URL passa prima per lo stesso gate
    allowlist fail-closed del resto del modulo (:func:`_is_allowed`); se
    l'origine non è consentita non parte alcuna richiesta.

    Un finding ``critica`` nasce **solo** quando la risposta è ``2xx`` **e** il
    ``seed_marker`` compare nel corpo: la risorsa protetta è servita a un client
    non autenticato. Status da solo (401/403) o marcatore assente (``2xx`` su
    pagina/lista vuota) => nessun finding. Deterministico (oracolo del
    marcatore), sola lettura.
    """
    findings: list[Finding] = []
    for owner_label, resource in omap.entries:
        marker = resource.seed_marker
        if not marker:
            # Senza marcatore dichiarato non c'è oracolo deterministico: il test
            # orizzontale segnala già l'assenza (info); qui si salta la risorsa.
            continue
        url = _resolve_url(resource, base_url)
        if url is None:
            continue
        # Gate allowlist fail-closed PRIMA della richiesta anonima.
        if not _is_allowed(contract, url):
            continue
        response = _request("GET", url, _ANONYMOUS_SESSION, contract.reachability)
        if _is_2xx(response) and _body_contains_marker(response, marker):
            findings.append(
                _anonymous_finding(url, owner_label, response, marker, lang)
            )
    return findings


def run(
    sessions: dict[str, Session],
    accounts: list[Account],
    contract: Contract,
    mode: Mode = "read-only",
    confirm: Callable[[str], bool] | None = None,
    *,
    base_url: str | None = None,
    lang: str = "it",
) -> list[Finding]:
    """Esegue i test di controllo-accessi e restituisce i :class:`Finding`.

    :param sessions: mappa ``label account -> Session`` autenticata. Le chiavi
        corrispondono alle ``label`` degli ``accounts``.
    :param accounts: i clienti con le rispettive risorse seminate, da cui si
        costruisce l':class:`OwnershipMap`.
    :param contract: il contratto del progetto. Il suo ``allowed_targets``
        alimenta il gate allowlist fail-closed: **ogni** richiesta httpx (replay
        GET orizzontale, sonda verticale, PATCH in write) è emessa solo se
        l'URL risolto ricade in un'origine consentita; altrimenti è saltata
        senza inviare nulla (anche un ``url_template`` assoluto è così gateato).
    :param mode: ``"read-only"`` (default, solo GET) o ``"write"`` (tentativi di
        modifica, ciascuno dietro :func:`confirm_destructive`).
    :param confirm: hook di conferma per i passi distruttivi in ``write``. Se
        ``None`` o se restituisce ``False``, il tentativo di scrittura è saltato.
    :param base_url: origine con cui risolvere ``url_template`` scritti come path
        relativi; superfluo quando i template sono già URL assoluti.
    :param lang: lingua con cui comporre i :class:`Finding` prodotti (``"it"``
        default o ``"en"``), attinta dal catalogo di :mod:`gauntlet.i18n`.

    Nota (Task 4): gli endpoint *scoperti* da documentazione/sorgente **non**
    sono inoltrati a questo tester. Privi di proprietario e di marcatore, non
    possono alimentare in modo affidabile né il test verticale (non sono admin)
    né quello orizzontale (nessun oracolo di proprietà): diventano solo seed per
    la scansione ZAP e sono riportati come informazione.
    """
    omap = OwnershipMap(accounts)

    findings = _run_horizontal(sessions, omap, contract, mode, confirm, base_url, lang)

    # Autenticazione mancante/rotta: complemento anonimo del test cross-tenant.
    # Read-only, allowlist-gated, oracolo del marcatore (nessuna sessione usata).
    findings.extend(_run_missing_auth(omap, contract, base_url, lang))

    origin = _derive_origin(omap, base_url)
    findings.extend(_run_vertical(sessions, contract, origin, lang))

    return findings
