"""Smoke test for the shared models imported by later tasks (3, 5, 6)."""

from gauntlet.models import Finding


def test_finding_is_constructible():
    f = Finding(
        source="zap",
        severity="alta",
        title="SQL injection",
        description="Parametro vulnerabile a SQL injection.",
        evidence="GET /api/users?id=1' -> errore SQL",
        fix="Usare query parametrizzate.",
        impact_if_ignored="Esfiltrazione dell'intero database.",
        confidence=0.9,
        url="http://localhost:8081/api/users",
    )
    assert f.source == "zap"
    assert f.url is None or f.url.startswith("http")


def test_finding_accepts_open_redirect_source():
    # Il source "open-redirect" è ammesso dal tipo (additivo, Task open-redirect).
    f = Finding(
        source="open-redirect",
        severity="media",
        title="Open redirect",
        description="Il parametro di redirect accetta un host esterno.",
        evidence="GET /go?u=https://evil.example -> 302 Location: https://evil.example",
        fix="Validare la destinazione contro una allowlist di host interni.",
        impact_if_ignored="Phishing credibile su dominio legittimo.",
        confidence=0.8,
        url="http://localhost:8081/go",
    )
    assert f.source == "open-redirect"


def test_finding_accepts_mass_assignment_source():
    # Il source "mass-assignment" è ammesso dal tipo (additivo, Task mass-assignment).
    f = Finding(
        source="mass-assignment",
        severity="alta",
        title="Mass assignment",
        description="Un campo protetto è scrivibile tramite update non filtrato.",
        evidence="PATCH /api/users/1 {\"role\": \"admin\"} -> role=admin dopo la lettura",
        fix="Usare una allowlist di campi assegnabili (DTO/schema di input).",
        impact_if_ignored="Escalation di privilegi a amministratore.",
        confidence=0.9,
        url="http://localhost:8081/api/users/1",
    )
    assert f.source == "mass-assignment"
