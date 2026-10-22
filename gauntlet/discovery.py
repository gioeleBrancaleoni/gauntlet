"""Scoperta di endpoint/risorse da documentazione e sorgente.

Questo modulo offre funzioni *pure* e *best-effort* che analizzano file su
disco per ricavare un elenco di endpoint candidati (metodo + percorso) da dare
in pasto alla scansione. Non effettua alcuna richiesta di rete e apre i file
solo in lettura.

Due sorgenti di informazione:

* **Documentazione** (:func:`extract_from_docs`): se sotto il percorso indicato
  si trova uno spec OpenAPI/Swagger (file ``.json``/``.yaml``/``.yml`` il cui
  contenuto è un dizionario con una chiave ``openapi``/``swagger`` e un oggetto
  ``paths``), se ne leggono percorsi e metodi. Altrimenti si analizzano i file
  HTML estraendo via regex gli URL/percorsi citati (``href``, blocchi di codice,
  percorsi tipo ``/api/...``).
* **Sorgente** (:func:`extract_from_source`): estrazione best-effort di pattern
  di route dai framework più comuni (``app.get("/x")``, ``@router.post("/x")``,
  ``fastify.get("/x")``, ``router.get('/x')``, Flask ``@app.route("/x")``).

Robustezza: un percorso assente, un file illeggibile o uno spec/HTML malformato
producono una lista vuota, mai un'eccezione.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Literal

import yaml

#: Da dove è stato ricavato un endpoint.
EndpointSource = Literal["openapi", "html", "source"]

#: Metodi HTTP riconosciuti negli spec OpenAPI e nei pattern di route.
_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "options", "head")

#: Estensioni dei file candidati a contenere uno spec OpenAPI/Swagger.
_SPEC_EXTS = (".json", ".yaml", ".yml")

#: Estensioni dei file trattati come documentazione HTML.
_HTML_EXTS = (".html", ".htm")


@dataclass(frozen=True)
class Endpoint:
    """Un endpoint candidato ricavato da doc o sorgente.

    Attributi:
        method: metodo HTTP in maiuscolo (es. ``"GET"``); default ``"GET"``
            quando il pattern non lo esplicita.
        path: percorso dell'endpoint (es. ``/api/users/{id}``).
        source: origine del dato (``"openapi"``, ``"html"`` o ``"source"``).

    È ``frozen`` (quindi hashabile) per consentire la deduplica tramite
    insiemi e l'uso come chiave.
    """

    method: str
    path: str
    source: EndpointSource


# --- Documentazione -------------------------------------------------------


def _load_spec(path: str) -> dict[str, Any] | None:
    """Carica un file come possibile spec OpenAPI/Swagger.

    Ritorna il dizionario parsato se il contenuto è un oggetto con chiave
    ``openapi``/``swagger`` e un ``paths`` di tipo dizionario; altrimenti
    ``None``. Non solleva mai: errori di lettura o di parsing danno ``None``.
    """

    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except (OSError, UnicodeDecodeError):
        return None

    data: Any = None
    # YAML è un superset di JSON, quindi copre entrambi i formati; proviamo
    # comunque prima JSON per i file .json, poi YAML come ripiego.
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None

    if not isinstance(data, dict):
        return None
    if "openapi" not in data and "swagger" not in data:
        return None
    if not isinstance(data.get("paths"), dict):
        return None
    return data


def _endpoints_from_spec(spec: dict[str, Any]) -> list[Endpoint]:
    """Estrae gli endpoint dai ``paths`` di uno spec già validato."""

    out: list[Endpoint] = []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return out
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        for method in item:
            if isinstance(method, str) and method.lower() in _HTTP_METHODS:
                out.append(Endpoint(method.upper(), path, "openapi"))
    return out


#: ``href="/..."`` o ``src="/..."`` (solo percorsi relativi che iniziano con /).
_HREF_RE = re.compile(r"""(?:href|src)\s*=\s*['"](/[^'"\s#?]*)""", re.IGNORECASE)

#: Percorsi tipo ``/api/...`` citati nel testo o nei blocchi di codice.
_PATH_RE = re.compile(r"(?<![\w/])(/(?:api|rest|v\d+|admin)/[A-Za-z0-9_\-/{}.]*)")


def _endpoints_from_html(text: str) -> list[Endpoint]:
    """Estrae percorsi da testo HTML via regex (metodo di default GET)."""

    found: list[str] = []
    found.extend(_HREF_RE.findall(text))
    found.extend(_PATH_RE.findall(text))

    out: list[Endpoint] = []
    seen: set[str] = set()
    for raw in found:
        path = raw.rstrip("/.") or "/"
        if path in seen:
            continue
        seen.add(path)
        out.append(Endpoint("GET", path, "html"))
    return out


def _iter_files(base: str) -> list[str]:
    """Elenca i file sotto ``base`` (file singolo o directory), best-effort."""

    if os.path.isfile(base):
        return [base]
    if os.path.isdir(base):
        collected: list[str] = []
        for root, _dirs, files in os.walk(base):
            for name in files:
                collected.append(os.path.join(root, name))
        return sorted(collected)
    return []


def extract_from_docs(docs_path: str) -> list[Endpoint]:
    """Estrae endpoint dalla documentazione sotto ``docs_path``.

    Se almeno un file candidato risulta uno spec OpenAPI/Swagger valido, la
    scoperta usa gli spec trovati. Altrimenti analizza i file HTML. Percorso
    assente/illeggibile o contenuti malformati producono ``[]``.
    """

    try:
        files = _iter_files(docs_path)
    except OSError:
        return []

    spec_endpoints: list[Endpoint] = []
    for path in files:
        if path.lower().endswith(_SPEC_EXTS):
            spec = _load_spec(path)
            if spec is not None:
                spec_endpoints.extend(_endpoints_from_spec(spec))
    if spec_endpoints:
        return _dedupe(spec_endpoints)

    html_endpoints: list[Endpoint] = []
    for path in files:
        if not path.lower().endswith(_HTML_EXTS):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        html_endpoints.extend(_endpoints_from_html(text))
    return _dedupe(html_endpoints)


# --- Sorgente -------------------------------------------------------------

#: ``obj.get("/x")`` / ``@router.post('/x')`` / ``fastify.delete("/x")`` …
#: Il metodo è catturato dal verbo; il percorso deve iniziare con ``/``.
_ROUTE_VERB_RE = re.compile(
    r"\.(get|post|put|delete|patch|options|head)\s*\(\s*['\"](/[^'\"]*)['\"]",
    re.IGNORECASE,
)

#: Flask / Express generico: ``@app.route("/x")`` / ``router.route('/x')``.
#: Metodo non esplicito dal pattern → default GET.
_ROUTE_GENERIC_RE = re.compile(
    r"\.route\s*\(\s*['\"](/[^'\"]*)['\"]",
    re.IGNORECASE,
)

#: Estensioni dei file sorgente analizzati.
_SRC_EXTS = (".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".go", ".rb")


def _endpoints_from_source_text(text: str) -> list[Endpoint]:
    """Estrae endpoint da testo sorgente via pattern di route."""

    out: list[Endpoint] = []
    for method, path in _ROUTE_VERB_RE.findall(text):
        out.append(Endpoint(method.upper(), path, "source"))
    for path in _ROUTE_GENERIC_RE.findall(text):
        out.append(Endpoint("GET", path, "source"))
    return out


def extract_from_source(src_path: str) -> list[Endpoint]:
    """Estrae endpoint dai file sorgente sotto ``src_path`` (best-effort).

    Percorso assente/illeggibile produce ``[]``; i file non analizzabili
    vengono semplicemente saltati.
    """

    try:
        files = _iter_files(src_path)
    except OSError:
        return []

    out: list[Endpoint] = []
    for path in files:
        if not path.lower().endswith(_SRC_EXTS):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        out.extend(_endpoints_from_source_text(text))
    return _dedupe(out)


# --- Unione ---------------------------------------------------------------


def _dedupe(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Rimuove i duplicati per ``(method, path)`` preservando l'ordine.

    A parità di ``(method, path)`` vince la prima occorrenza (quindi la prima
    origine incontrata).
    """

    out: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for ep in endpoints:
        key = (ep.method, ep.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(ep)
    return out


def discover(
    docs_path: str | None,
    src_path: str | None,
    use_docs: bool,
    use_source: bool,
) -> list[Endpoint]:
    """Unisce gli endpoint da documentazione e/o sorgente secondo i flag.

    Vengono considerate solo le sorgenti abilitate dai rispettivi flag e con
    un percorso non ``None``. Il risultato è deduplicato per ``(method, path)``;
    a parità di chiave prevale la documentazione (processata per prima).
    """

    collected: list[Endpoint] = []
    if use_docs and docs_path:
        collected.extend(extract_from_docs(docs_path))
    if use_source and src_path:
        collected.extend(extract_from_source(src_path))
    return _dedupe(collected)
