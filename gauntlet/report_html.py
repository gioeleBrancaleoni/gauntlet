"""Generatore del report HTML autoconsistente, gemello del report Markdown.

Produce un unico documento HTML completo (CSS inline, nessuna risorsa esterna,
nessuno script) con lo stesso contenuto e le stesse chiavi i18n di
:mod:`gauntlet.report`: intestazione con i dati del run, avviso sui dati
sensibili, riepilogo con chip colorati per gravità e una scheda per ogni
problema, ordinata da ``critica`` a ``info``. L'evidenza è in un blocco
``<details>`` richiudibile.

Tutto il testo che proviene dai finding o dai metadati viene passato da
:func:`html.escape`: le prove possono contenere corpi di risposta con ``<``,
``>``, ``&`` o virgolette e non devono mai produrre tag attivi.

Funzione pubblica: :func:`render_html` (pura e deterministica, a parità di
``meta["data"]``).
"""

from __future__ import annotations

import html
import re
from datetime import datetime

from gauntlet.i18n import severity_hint, severity_label, source_label, t
from gauntlet.models import Finding
from gauntlet.report import _SEVERITY_ORDER, _severity_key

_CSS = """
:root{--critica:#c62828;--alta:#ef6c00;--media:#f9a825;--bassa:#1976d2;--info:#757575;}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;
background:#f5f6f8;color:#1c1e21;line-height:1.5}
main{max-width:860px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0 0 8px;font-size:1.7rem}
h2{margin:32px 0 12px;font-size:1.25rem}
.meta{list-style:none;padding:0;margin:0}
.meta li{margin:2px 0}
.warning{background:#fff4e5;border-left:5px solid var(--alta);padding:12px 16px;
border-radius:4px;margin:16px 0}
.warning.zap{background:#fdecea;border-left-color:var(--critica)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.chip{color:#fff;border-radius:999px;padding:4px 12px;font-weight:600;font-size:.9rem}
.chip.sev-media{color:#1c1e21}
.sev-critica{--c:var(--critica)}.sev-alta{--c:var(--alta)}.sev-media{--c:var(--media)}
.sev-bassa{--c:var(--bassa)}.sev-info{--c:var(--info)}
.chip{background:var(--c,var(--info))}
.finding{background:#fff;border-left:6px solid var(--c,var(--info));border-radius:6px;
padding:16px 20px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.12)}
.finding h3{margin:0 0 8px;font-size:1.1rem}
.finding p{margin:8px 0;overflow-wrap:anywhere}
.badge{display:inline-block;color:#fff;background:var(--c,var(--info));border-radius:4px;
padding:1px 8px;font-weight:600}
.sev-media .badge{color:#1c1e21}
details{margin:8px 0}
summary{cursor:pointer;font-weight:600}
pre{background:#1e1e1e;color:#f0f0f0;padding:12px;border-radius:4px;overflow-x:auto;
white-space:pre-wrap;overflow-wrap:anywhere}
.origin{color:#555;font-size:.9rem}
"""


def _md(text: str) -> str:
    """Rende il testo di un catalogo i18n (con markup Markdown leggero) in HTML.

    Il catalogo è statico e fidato; i valori dinamici vanno già escapati prima
    di essere passati a ``t(...)``. Qui si tolgono i prefissi ``#``/``-``/``>``,
    si converte ``**x**`` in ``<strong>`` e si eliminano gli ``_`` d'enfasi.
    """
    blocchi: list[str] = []
    for par in text.split("\n\n"):
        righe = [re.sub(r"^\s*(#+|-|>)\s*", "", r) for r in par.split("\n")]
        corpo = " ".join(r for r in righe if r)
        corpo = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", corpo)
        corpo = re.sub(r"^_(.*)_$", r"\1", corpo.strip())
        if par.lstrip().startswith("#"):
            blocchi.append(f"<h2>{corpo}</h2>")
        else:
            blocchi.append(f"<p>{corpo}</p>")
    return "\n".join(blocchi)


def _inline(text: str) -> str:
    """Come :func:`_md` ma senza il tag ``<p>``: per testo inline in un elemento."""
    out = _md(text)
    return re.sub(r"^<(p|h2)>|</(p|h2)>$", "", out)


def _e(value: object) -> str:
    """Escape HTML (incluse le virgolette) di un valore proveniente da dati esterni."""
    return html.escape(str(value), quote=True)


def _render_header(meta: dict, lang: str) -> str:
    unspecified = t(lang, "meta_unspecified")
    livello = _e(meta.get("livello", unspecified))
    target = _e(meta.get("target", unspecified))
    data = _e(meta.get("data") or datetime.now().strftime("%Y-%m-%d %H:%M"))
    modalita = t(lang, "yes") if bool(meta.get("aggressive", False)) else t(lang, "no")

    parti = [
        f"<h1>{_inline(t(lang, 'report_title'))}</h1>",
        _md(t(lang, "report_intro")),
        _md(t(lang, "meta_section")),
        '<ul class="meta">',
        f"<li>{_inline(t(lang, 'meta_target', target=target))}</li>",
        f"<li>{_inline(t(lang, 'meta_level', livello=livello))}</li>",
        f"<li>{_inline(t(lang, 'meta_aggressive', modalita=modalita))}</li>",
        f"<li>{_inline(t(lang, 'meta_date', data=data))}</li>",
        "</ul>",
        f'<div class="warning">{_md(t(lang, "sensitive_warning"))}</div>',
    ]
    zap = meta.get("zap_interrotto")
    if zap:
        nota = t(lang, "meta_zap_interrupted", motivo=_e(zap))
        parti.append(f'<div class="warning zap">{_md(nota)}</div>')
    endpoint = meta.get("endpoint_scoperti") or []
    if endpoint:
        parti.append(_md(t(lang, "endpoints_section")))
        parti.append(_md(t(lang, "endpoints_intro")))
        voci = "".join(f"<li><code>{_e(v)}</code></li>" for v in endpoint)
        parti.append(f"<ul>{voci}</ul>")
    return "\n".join(parti)


def _render_summary(findings: list[Finding], lang: str) -> str:
    conteggi = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in findings:
        if f.severity in conteggi:
            conteggi[f.severity] += 1
    chips = "".join(
        f'<span class="chip sev-{sev}">{_e(severity_label(lang, sev))}: '
        f"{conteggi[sev]}</span>"
        for sev in _SEVERITY_ORDER
    )
    return (
        f"{_md(t(lang, 'summary_section'))}\n"
        f"{_md(t(lang, 'summary_total', total=len(findings)))}\n"
        f'<div class="chips">{chips}</div>'
    )


def _render_finding(finding: Finding, lang: str) -> str:
    sev = finding.severity if finding.severity in _SEVERITY_ORDER else "info"
    label = _e(severity_label(lang, finding.severity))
    hint = _e(severity_hint(lang, finding.severity))
    origine = _e(source_label(lang, finding.source))
    parti = [
        f'<article class="finding sev-{sev}">',
        f"<h3>{_e(finding.title)}</h3>",
        f'<p>{_inline(t(lang, "fh_severity"))} <span class="badge">{label}</span>'
        f"{' — ' + hint if hint else ''}</p>",
        f"<p>{_inline(t(lang, 'fh_found'))} {_e(finding.description)}</p>",
    ]
    if finding.url:
        parti.append(f"<p>{_inline(t(lang, 'fh_where'))} {_e(finding.url)}</p>")
    if finding.evidence:
        parti.append(
            f"<details><summary>{_inline(t(lang, 'fh_evidence'))}</summary>"
            f"<pre>{_e(finding.evidence)}</pre></details>"
        )
    parti += [
        f"<p>{_inline(t(lang, 'fh_fix'))} {_e(finding.fix)}</p>",
        f"<p>{_inline(t(lang, 'fh_impact'))} {_e(finding.impact_if_ignored)}</p>",
        '<p class="origin">'
        + _inline(
            t(lang, "fh_origin", origine=origine, conf=f"{finding.confidence:.0%}")
        )
        + "</p>",
        "</article>",
    ]
    return "\n".join(parti)


def render_html(findings: list[Finding], meta: dict, *, lang: str = "it") -> str:
    """Restituisce il report come documento HTML completo e autoconsistente.

    I ``findings`` sono ordinati per gravità (``critica`` → ``info``) come nel
    report Markdown. ``meta`` ha le stesse chiavi di
    :func:`gauntlet.report.write_report` (``livello``, ``target``,
    ``aggressive``, ``data``, opzionali ``zap_interrotto`` e
    ``endpoint_scoperti``). Ogni testo proveniente da finding e meta è
    escapato; non c'è alcuna risorsa esterna.

    Args:
        findings: i risultati da riportare (anche lista vuota).
        meta: dati dell'esecuzione.
        lang: lingua di impalcature ed etichette (``"it"`` default o ``"en"``).
    """
    ordinati = sorted(findings, key=_severity_key)
    corpo = [_render_header(meta, lang), _render_summary(ordinati, lang)]
    if not ordinati:
        corpo.append(_md(t(lang, "no_findings")))
    else:
        corpo.append(_md(t(lang, "issues_section")))
        corpo += [_render_finding(f, lang) for f in ordinati]

    titolo = _e(re.sub(r"^#+\s*", "", t(lang, "report_title")))
    return (
        "<!doctype html>\n"
        f'<html lang="{_e(lang)}">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{titolo}</title>\n<style>{_CSS}</style>\n</head>\n"
        f"<body>\n<main>\n{chr(10).join(corpo)}\n</main>\n</body>\n</html>\n"
    )
