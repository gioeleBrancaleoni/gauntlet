"""Tests for endpoint/resource discovery (``gauntlet.discovery``)."""

from gauntlet.discovery import (
    Endpoint,
    discover,
    extract_from_docs,
    extract_from_source,
)

FIXTURES = "tests/fixtures"


def test_extract_openapi_paths():
    eps = extract_from_docs(f"{FIXTURES}/openapi.json")
    assert set(eps) == {
        Endpoint("GET", "/api/users", "openapi"),
        Endpoint("POST", "/api/users", "openapi"),
        Endpoint("GET", "/api/users/{id}", "openapi"),
    }


def test_extract_html_urls():
    eps = extract_from_docs(f"{FIXTURES}/manuale.html")
    paths = {e.path for e in eps}
    assert "/api/orders" in paths
    assert "/api/products" in paths
    # Tutti i risultati HTML hanno origine "html".
    assert all(e.source == "html" for e in eps)
    # I link esterni assoluti non diventano endpoint.
    assert not any(p.startswith("http") for p in paths)


def test_extract_source_routes():
    eps = extract_from_source(f"{FIXTURES}/src_sample")
    assert Endpoint("GET", "/health", "source") in eps
    assert Endpoint("POST", "/api/login", "source") in eps


def test_missing_paths_return_empty():
    assert extract_from_docs(f"{FIXTURES}/non_esiste") == []
    assert extract_from_source(f"{FIXTURES}/non_esiste") == []
    assert discover(None, None, use_docs=True, use_source=True) == []


def test_discover_unions_and_dedupes():
    eps = discover(
        f"{FIXTURES}/openapi.json",
        f"{FIXTURES}/src_sample",
        use_docs=True,
        use_source=True,
    )
    # Unione: contiene endpoint sia da docs sia da source.
    assert Endpoint("GET", "/api/users", "openapi") in eps
    assert Endpoint("GET", "/health", "source") in eps
    # Deduplica per (method, path): nessun duplicato.
    keys = [(e.method, e.path) for e in eps]
    assert len(keys) == len(set(keys))


def test_discover_respects_flags():
    only_source = discover(
        f"{FIXTURES}/openapi.json",
        f"{FIXTURES}/src_sample",
        use_docs=False,
        use_source=True,
    )
    assert all(e.source == "source" for e in only_source)
    assert only_source  # non vuoto
