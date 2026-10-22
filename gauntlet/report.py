"""Generatore del report localizzato, per chi non è esperto di sicurezza.

Questo modulo trasforma una lista di :class:`~gauntlet.models.Finding` in un
file Markdown leggibile da chiunque: niente gergo inglese lasciato senza
spiegazione, ogni problema descritto con parole semplici e, soprattutto, **cosa
fare** per risolverlo e **cosa succede se lo si ignora**.

La lingua delle impalcature e delle etichette è scelta dal chiamante (``lang``,
default ``"it"``) e attinta dal catalogo in :mod:`gauntlet.i18n`. Il contenuto
dei finding (titolo, descrizione, ecc.) è già nella lingua con cui è stato
prodotto a monte; qui si localizza solo l'ossatura e l'etichetta di gravità.

I risultati sono ordinati per gravità (``critica`` → ``info``): chi legge trova
in cima ciò che va sistemato subito. Il report viene scritto in
``<progetto>/gauntlet-runs/<timestamp>/report.md`` così che ogni esecuzione
conservi il proprio esito senza sovrascrivere i precedenti.

Funzione pubblica: :func:`write_report`.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from gauntlet.i18n import severity_hint, severity_label, source_label, t
from gauntlet.models import Finding, Severity

#: Ordine di gravità dal più urgente al meno urgente. L'indice di una gravità in
#: questa tupla è la chiave di ordinamento del report. Sono i valori *interni*
#: dell'enum (sempre in italiano): solo l'etichetta mostrata è localizzata.
_SEVERITY_ORDER: tuple[Severity, ...] = ("critica", "alta", "media", "bassa", "info")


def _severity_key(finding: Finding) -> int:
    """Chiave di ordinamento: più bassa = più grave (quindi prima nel report)."""
    try:
        return _SEVERITY_ORDER.index(finding.severity)  # type: ignore[arg-type]
    except ValueError:
        # Gravità sconosciuta: la mettiamo in fondo, senza far fallire il report.
        return len(_SEVERITY_ORDER)


def _format_meta(meta: dict, lang: str) -> str:
    """Intestazione del report con i dati del run (livello, target, data)."""
    unspecified = t(lang, "meta_unspecified")
    livello = meta.get("livello", unspecified)
    target = meta.get("target", unspecified)
    data = meta.get("data") or datetime.now().strftime("%Y-%m-%d %H:%M")
    aggressive = bool(meta.get("aggressive", False))
    modalita_aggressiva = t(lang, "yes") if aggressive else t(lang, "no")
    endpoint_scoperti = meta.get("endpoint_scoperti") or []

    righe = [
        t(lang, "report_title"),
        "",
        t(lang, "report_intro"),
        "",
        t(lang, "meta_section"),
        "",
        t(lang, "meta_target", target=target),
        t(lang, "meta_level", livello=livello),
        t(lang, "meta_aggressive", modalita=modalita_aggressiva),
        t(lang, "meta_date", data=data),
        "",
        t(lang, "sensitive_warning"),
    ]
    zap_interrotto = meta.get("zap_interrotto")
    if zap_interrotto:
        righe += [
            "",
            t(lang, "meta_zap_interrupted", motivo=zap_interrotto),
        ]
    if endpoint_scoperti:
        righe += [
            "",
            t(lang, "endpoints_section"),
            "",
            t(lang, "endpoints_intro"),
            "",
        ]
        righe += [f"- `{voce}`" for voce in endpoint_scoperti]
    return "\n".join(righe)


def _format_summary(findings: list[Finding], lang: str) -> str:
    """Riepilogo con il conteggio dei problemi per gravità."""
    conteggi = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in findings:
        if f.severity in conteggi:
            conteggi[f.severity] += 1

    righe = [
        t(lang, "summary_section"),
        "",
        t(lang, "summary_total", total=len(findings)),
        "",
    ]
    for sev in _SEVERITY_ORDER:
        righe.append(f"- {severity_label(lang, sev)}: {conteggi[sev]}")
    return "\n".join(righe)


def _format_finding(index: int, finding: Finding, lang: str) -> str:
    """Un singolo problema, con tutte le sezioni localizzate per il lettore."""
    label = severity_label(lang, finding.severity)
    hint = severity_hint(lang, finding.severity)
    origine = source_label(lang, finding.source)

    righe = [
        f"### {index}. {finding.title}",
        "",
        f"{t(lang, 'fh_severity')} {label} — {hint}".rstrip(" —"),
        "",
        f"{t(lang, 'fh_found')} {finding.description}",
    ]
    if finding.url:
        righe += ["", f"{t(lang, 'fh_where')} {finding.url}"]
    if finding.evidence:
        righe += [
            "",
            t(lang, "fh_evidence"),
            "",
            "```",
            finding.evidence,
            "```",
        ]
    righe += [
        "",
        f"{t(lang, 'fh_fix')} {finding.fix}",
        "",
        f"{t(lang, 'fh_impact')} {finding.impact_if_ignored}",
        "",
        t(lang, "fh_origin", origine=origine, conf=f"{finding.confidence:.0%}"),
    ]
    return "\n".join(righe)


def write_report(
    findings: list[Finding], project_path: str, meta: dict, *, lang: str = "it"
) -> Path:
    """Scrive il report Markdown localizzato e restituisce il percorso del file.

    I ``findings`` sono ordinati per gravità (``critica`` → ``info``) e il file è
    scritto in ``<project_path>/gauntlet-runs/<timestamp>/report.md``; le cartelle
    vengono create se non esistono. ``meta`` fornisce i dati del run mostrati
    nell'intestazione: ``livello`` (livello di conoscenza dell'attaccante, 1–4),
    ``target`` (URL analizzato), ``aggressive`` (bool: modalità aggressiva sì/no)
    e, opzionale, ``data`` (altrimenti usa l'istante corrente).

    Args:
        findings: i risultati di sicurezza da riportare (lista anche vuota).
        project_path: cartella del progetto in cui creare ``gauntlet-runs/``.
        meta: dati dell'esecuzione (``livello``, ``target``, ``aggressive``,
            ``data``).
        lang: lingua delle impalcature e delle etichette (``"it"`` default o
            ``"en"``); i contenuti dei finding sono già nella lingua prodotta a
            monte.

    Returns:
        Il :class:`pathlib.Path` del file ``report.md`` scritto (accanto a lui
        viene scritto anche ``report.html``).
    """
    ordinati = sorted(findings, key=_severity_key)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(project_path) / "gauntlet-runs" / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / "report.md"

    sezioni: list[str] = [
        _format_meta(meta, lang),
        _format_summary(ordinati, lang),
    ]

    if not ordinati:
        sezioni.append(t(lang, "no_findings"))
    else:
        sezioni.append(t(lang, "issues_section"))
        for i, finding in enumerate(ordinati, start=1):
            sezioni.append(_format_finding(i, finding, lang))

    report_path.write_text("\n\n".join(sezioni) + "\n", encoding="utf-8")
    # Import locale: report_html importa a sua volta da questo modulo (ciclo).
    from gauntlet import report_html

    # Versione HTML autoconsistente accanto al Markdown (stessi finding ordinati).
    (run_dir / "report.html").write_text(
        report_html.render_html(ordinati, meta, lang=lang), encoding="utf-8"
    )
    return report_path
