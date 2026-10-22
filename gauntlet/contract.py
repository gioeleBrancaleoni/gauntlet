"""Caricamento e validazione del contratto di progetto di Gauntlet.

Il *contratto* è il file YAML che rende la skill portabile fra progetti:
descrive i target consentiti (allowlist anti-produzione, fail-closed), la
raggiungibilità di rete, la procedura di login, i due account di clienti
diversi usati per i test di isolamento tra tenant e i percorsi di
documentazione/sorgente.

Regola sui segreti: le password degli account non sono mai scritte nel YAML.
Il contratto referenzia soltanto il *nome* della variabile d'ambiente che le
contiene (``password_env``); :func:`resolve_password` la risolve a runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml

#: Metodi di autenticazione supportati dall'automazione di login.
LoginMethod = Literal["form", "json", "token", "session"]


class ContractError(Exception):
    """Sollevata quando il contratto è assente, illeggibile o malformato.

    Copre file inesistente, YAML non valido e campi obbligatori mancanti o
    del tipo sbagliato. Il messaggio è pensato per essere mostrato a chi
    configura il progetto.
    """


@dataclass
class Resource:
    """Una risorsa seminata appositamente per rendere deterministico il leak.

    ``url_template`` può contenere il segnaposto ``{id}`` per costruire l'URL
    della risorsa (es. ``/api/invoices/{id}``).

    ``seed_marker`` è il *marcatore noto del seed*: una stringa univoca che la
    risorsa contiene nel corpo quando è letta dal proprietario legittimo. È
    l'oracolo di proprietà del tester di controllo-accessi (Task 5): un leak
    cross-tenant è confermato solo se un altro tenant ottiene ``2xx`` **e** nel
    corpo compare questo marcatore. È opzionale: se assente, il tester ripiega
    sull'``id`` della risorsa, che è comunque un identificatore univoco noto.

    ``enumerate``/``owner_field``/``enumerate_count`` abilitano il fuzzing IDOR
    su ID sequenziali (E2): con ``enumerate=True``, un ``id`` numerico e un
    ``owner_field`` non vuoto, il tester sonda gli ID vicini (``id±enumerate_count``)
    con la sessione del proprietario e conferma un IDOR solo se un vicino risponde
    ``2xx`` e il suo ``owner_field`` nel corpo rivela un proprietario diverso. Sono
    opzionali e retro-compatibili: con i default (``enumerate=False``) il
    comportamento resta invariato.
    """

    kind: str
    id: str
    url_template: str
    seed_marker: str | None = None
    enumerate: bool = False
    owner_field: str | None = None
    enumerate_count: int = 3


@dataclass
class Account:
    """Un account di cliente usato nei run autenticati.

    La password non è presente: ``password_env`` è il *nome* della variabile
    d'ambiente che la contiene (vedi :func:`resolve_password`). È opzionale:
    con il login ``session`` l'account può non avere una password dedicata, e
    allora ``password_env`` è ``None`` e :func:`resolve_password` restituisce ``""``.
    """

    label: str
    username: str
    password_env: str | None = None
    tenant_id: str | None = None
    seeded_resources: list[Resource] = field(default_factory=list)


@dataclass
class LoginConfig:
    """Come autenticarsi contro l'applicazione sotto test."""

    method: LoginMethod
    login_url: str
    username_field: str
    password_field: str
    logged_in_indicator: str
    token_path: str | None = None
    #: Nome del cookie di sessione atteso nella risposta di login ``session``:
    #: il login ha successo con ``2xx`` + ``Set-Cookie`` di questo cookie, senza
    #: token né indicatore nel corpo. Obbligatorio solo con ``method == "session"``.
    success_cookie: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class MassAssignmentProbe:
    """Una sonda per il rilevamento dell'assegnazione di massa (mass assignment).

    Descrive un endpoint di update su cui tentare di scrivere un campo che il
    client non dovrebbe poter impostare (es. ``role``/``isAdmin``), per
    verificare se l'applicazione filtra i campi assegnabili.

    ``url_template`` è il path dell'update, con l'eventuale segnaposto ``{id}``
    per costruire l'URL della risorsa (es. ``/api/users/{id}``). ``id`` è
    l'identificatore della risorsa bersaglio. ``forbidden_field`` è il nome del
    campo protetto da iniettare nel corpo e ``forbidden_value`` il valore che
    non dovrebbe essere accettato (es. ``admin``). ``forbidden_value`` conserva
    il tipo dichiarato in YAML/JSON (bool, numero o stringa) così da produrre un
    corpo JSON realmente tipizzato: un sentinella ``true`` viene inviato come
    booleano ``true``, non come la stringa ``"True"``. ``method`` è il verbo HTTP
    dell'update (default ``PATCH``). ``read_template`` è il path opzionale per
    rileggere la risorsa e confermare che il campo sia stato effettivamente
    scritto; se assente, il tester ripiega sul corpo della risposta di update.
    """

    url_template: str
    id: str
    forbidden_field: str
    forbidden_value: Any
    method: str = "PATCH"
    read_template: str | None = None


@dataclass
class Contract:
    """Il contratto di progetto completo e validato."""

    name: str
    allowed_targets: list[str]
    reachability: str
    login: LoginConfig
    accounts: list[Account]
    docs_path: str | None = None
    src_path: str | None = None
    exclusions: list[str] = field(default_factory=list)
    db_reset: str | None = None
    #: Endpoint amministrativi specifici del progetto, uniti alla lista generica
    #: del tester verticale (vedi ``gauntlet.access_control``). Opzionale: assente
    #: => lista vuota, e il probe usa solo i path admin generici.
    admin_endpoints: list[str] = field(default_factory=list)
    #: Template di probe per il rilevamento di open redirect: path con il
    #: segnaposto ``{payload}`` dove iniettare la destinazione di test (es.
    #: ``/login?next={payload}``). Opzionale: assente => lista vuota.
    redirect_probes: list[str] = field(default_factory=list)
    #: Sonde per il rilevamento dell'assegnazione di massa (vedi
    #: :class:`MassAssignmentProbe`). Opzionale: assente => lista vuota, e il
    #: tester di mass assignment non ha nulla da sondare.
    mass_assignment: list[MassAssignmentProbe] = field(default_factory=list)


def _require(data: dict[str, Any], key: str, where: str) -> Any:
    """Restituisce ``data[key]`` o solleva :class:`ContractError`."""
    if key not in data or data[key] is None:
        raise ContractError(f"Campo obbligatorio mancante: '{key}' in {where}.")
    return data[key]


def _as_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"'{where}' deve essere una mappa, trovato {type(value).__name__}.")
    return value


def _as_sequence(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"'{where}' deve essere una lista, trovato {type(value).__name__}.")
    return value


def _parse_resource(raw: Any, where: str) -> Resource:
    data = _as_mapping(raw, where)
    seed_marker = data.get("seed_marker")
    owner_field = data.get("owner_field")
    enumerate_count = data.get("enumerate_count")
    return Resource(
        kind=_require(data, "kind", where),
        id=str(_require(data, "id", where)),
        url_template=_require(data, "url_template", where),
        seed_marker=str(seed_marker) if seed_marker is not None else None,
        enumerate=bool(data.get("enumerate", False)),
        owner_field=str(owner_field) if owner_field is not None else None,
        enumerate_count=int(enumerate_count) if enumerate_count is not None else 3,
    )


def _parse_mass_assignment(raw: Any, where: str) -> MassAssignmentProbe:
    data = _as_mapping(raw, where)
    read_template = data.get("read_template")
    return MassAssignmentProbe(
        url_template=_require(data, "url_template", where),
        id=str(_require(data, "id", where)),
        forbidden_field=_require(data, "forbidden_field", where),
        forbidden_value=_require(data, "forbidden_value", where),
        method=data.get("method", "PATCH"),
        read_template=str(read_template) if read_template is not None else None,
    )


def _parse_account(raw: Any, where: str) -> Account:
    data = _as_mapping(raw, where)
    seeded_raw = data.get("seeded_resources") or []
    seeded = [
        _parse_resource(r, f"{where}.seeded_resources[{i}]")
        for i, r in enumerate(_as_sequence(seeded_raw, f"{where}.seeded_resources"))
    ]
    return Account(
        label=_require(data, "label", where),
        username=_require(data, "username", where),
        password_env=data.get("password_env"),
        tenant_id=data.get("tenant_id"),
        seeded_resources=seeded,
    )


def _parse_login(raw: Any) -> LoginConfig:
    where = "login"
    data = _as_mapping(raw, where)
    method = _require(data, "method", where)
    if method not in ("form", "json", "token", "session"):
        raise ContractError(
            f"'login.method' non valido: {method!r} (ammessi: form, json, token, session)."
        )
    extra = data.get("extra") or {}
    if method == "session":
        # Login basato su cookie di sessione: il successo è provato dal
        # ``success_cookie`` (obbligatorio), non da un token/indicatore nel
        # corpo, quindi ``password_field`` e ``logged_in_indicator`` sono
        # facoltativi e normalizzati a stringa vuota.
        success_cookie = _require(data, "success_cookie", where)
        password_field = data.get("password_field", "")
        logged_in_indicator = data.get("logged_in_indicator", "")
    else:
        success_cookie = data.get("success_cookie")
        password_field = _require(data, "password_field", where)
        logged_in_indicator = _require(data, "logged_in_indicator", where)
    return LoginConfig(
        method=method,
        login_url=_require(data, "login_url", where),
        username_field=_require(data, "username_field", where),
        password_field=password_field,
        logged_in_indicator=logged_in_indicator,
        token_path=data.get("token_path"),
        success_cookie=success_cookie,
        extra=_as_mapping(extra, f"{where}.extra"),
    )


def load_contract(path: str) -> Contract:
    """Carica e valida il contratto YAML indicato da ``path``.

    Solleva :class:`ContractError` se il file non esiste, non è YAML valido o
    manca un campo obbligatorio. I segreti non vengono letti qui: usare
    :func:`resolve_password` quando serve la password di un account.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise ContractError(f"Contratto non trovato: {path}") from exc
    except yaml.YAMLError as exc:
        raise ContractError(f"YAML non valido in {path}: {exc}") from exc

    if raw is None:
        raise ContractError(f"Contratto vuoto: {path}")
    data = _as_mapping(raw, "contratto")

    allowed_targets = _as_sequence(
        _require(data, "allowed_targets", "contratto"), "allowed_targets"
    )
    if not allowed_targets:
        raise ContractError("'allowed_targets' non può essere vuoto (allowlist fail-closed).")

    accounts_raw = _as_sequence(_require(data, "accounts", "contratto"), "accounts")
    accounts = [
        _parse_account(a, f"accounts[{i}]") for i, a in enumerate(accounts_raw)
    ]
    if not accounts:
        raise ContractError("'accounts' non può essere vuoto.")

    return Contract(
        name=_require(data, "name", "contratto"),
        allowed_targets=[str(t) for t in allowed_targets],
        reachability=_require(data, "reachability", "contratto"),
        login=_parse_login(_require(data, "login", "contratto")),
        accounts=accounts,
        docs_path=data.get("docs_path"),
        src_path=data.get("src_path"),
        exclusions=[str(e) for e in (data.get("exclusions") or [])],
        db_reset=data.get("db_reset"),
        admin_endpoints=[str(e) for e in (data.get("admin_endpoints") or [])],
        redirect_probes=[str(p) for p in (data.get("redirect_probes") or [])],
        mass_assignment=[
            _parse_mass_assignment(m, f"mass_assignment[{i}]")
            for i, m in enumerate(data.get("mass_assignment") or [])
        ],
    )


def resolve_password(account: Account) -> str:
    """Risolve la password di ``account`` dalla variabile d'ambiente.

    Legge ``os.environ[account.password_env]``. Solleva :class:`ContractError`
    se la variabile non è impostata, così l'errore è chiaro al momento del run
    invece di un oscuro ``KeyError``. Se ``account.password_env`` è ``None``
    (account senza password dedicata, tipico del login ``session``) restituisce
    la stringa vuota.
    """
    if account.password_env is None:
        return ""
    try:
        return os.environ[account.password_env]
    except KeyError as exc:
        raise ContractError(
            f"Variabile d'ambiente '{account.password_env}' non impostata "
            f"per l'account '{account.label}'."
        ) from exc
