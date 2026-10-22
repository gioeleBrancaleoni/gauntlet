"""Test del renderer HTML (gauntlet.report_html)."""

from __future__ import annotations

import re

from gauntlet.i18n import severity_label, t
from gauntlet.models import Finding
from gauntlet.report_html import render_html

META = {"livello": 2, "target": "https://example.test", "aggressive": False,
        "data": "2026-01-01 10:00"}
EVIDENCE = '<script>alert(1)</script> a & b "c"'


def _f(sev="alta", title="Titolo", evidence="", **kw) -> Finding:
    return Finding(
        source="zap", severity=sev, title=title, description="desc",
        evidence=evidence, fix="fix", impact_if_ignored="impatto",
        confidence=0.8, url=kw.get("url", ""),
    )


def test_documento_completo():
    out = render_html([_f()], META)
    assert out.lower().startswith("<!doctype html")
    assert '<meta charset="utf-8">' in out
    assert "<style>" in out
    assert out.rstrip().endswith("</html>")


def test_escaping_evidenza_e_campi():
    out = render_html(
        [_f(evidence=EVIDENCE, title="<b>x</b>", url="http://a/?q=<i>")],
        {**META, "target": "<img src=x>", "zap_interrotto": "<u>m</u>",
         "endpoint_scoperti": ["/a<b>"]},
    )
    assert "&lt;script&gt;alert(1)&lt;/script&gt; a &amp; b &quot;c&quot;" in out
    for raw in ("<script>", "<b>x</b>", "<img src=x>", "<u>m</u>", "/a<b>", "<i>"):
        assert raw not in out


def test_localizzazione():
    f = [_f("critica")]
    en = render_html(f, META, lang="en")
    it = render_html(f, META, lang="it")
    assert severity_label("en", "critica") in en
    assert "Security Report" in en
    assert severity_label("it", "critica") in it
    assert "Report di sicurezza" in it
    assert '<html lang="en">' in en


def test_ordine_e_classe_gravita():
    fs = [_f(s, title=f"T-{s}") for s in ("info", "media", "critica", "bassa", "alta")]
    out = render_html(fs, META)
    classi = re.findall(r'<article class="finding sev-(\w+)"', out)
    assert classi == ["critica", "alta", "media", "bassa", "info"]
    pos = [out.index(f"T-{s}") for s in classi]
    assert pos == sorted(pos)


def test_caso_vuoto():
    out = render_html([], META, lang="it")
    assert "Nessun problema di sicurezza" in out
    assert t("it", "no_findings").split("\n\n")[1][:30] in out
    assert '<article' not in out


def test_autoconsistente():
    out = render_html([_f(evidence=EVIDENCE, url="https://x.test/p")], META)
    assert not re.search(r'(href|src)\s*=\s*["\']?https?://', out)
    assert "<script" not in out.replace("&lt;script", "")
    assert '<link rel="stylesheet"' not in out


def test_evidenza_in_details_pre():
    out = render_html([_f(evidence=EVIDENCE)], META)
    assert re.search(r"<details><summary>.*?</summary><pre>.*&lt;script&gt;.*</pre></details>",
                     out, re.S)
    assert "<details>" not in render_html([_f()], META)
