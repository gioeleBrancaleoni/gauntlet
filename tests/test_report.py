"""Test per il generatore di report in italiano (Task 6)."""

from pathlib import Path

from gauntlet.models import Finding
from gauntlet.report import write_report


def _finding(severity: str, title: str) -> Finding:
    return Finding(
        source="zap",
        severity=severity,
        title=title,
        description=f"Descrizione di {title}.",
        evidence=f"Prova per {title}.",
        fix=f"Rimedio per {title}.",
        impact_if_ignored=f"Conseguenza di {title}.",
        confidence=0.9,
        url="http://localhost:8081",
    )


def test_report_orders_by_severity_and_writes_italian(tmp_path):
    findings = [
        _finding("bassa", "Header mancante"),
        _finding("critica", "Leak tra clienti"),
    ]
    path = write_report(
        findings,
        str(tmp_path),
        meta={"livello": 2, "target": "http://localhost:8081"},
    )

    assert isinstance(path, Path)
    assert path.exists()
    assert path.name == "report.md"
    # Il report sta dentro gauntlet-runs/<timestamp>/ nel progetto.
    assert path.parent.parent.name == "gauntlet-runs"
    assert path.parent.parent.parent == tmp_path

    text = path.read_text(encoding="utf-8")
    # La critica precede la bassa.
    assert text.index("Leak tra clienti") < text.index("Header mancante")
    # Etichette italiane per il lettore non esperto.
    assert "Come correggere" in text and "Se ignori" in text
    # Il meta del run compare nell'intestazione.
    assert "http://localhost:8081" in text
    assert "2" in text


def test_report_header_contains_run_meta(tmp_path):
    path = write_report(
        [_finding("media", "Cookie senza flag")],
        str(tmp_path),
        meta={"livello": 1, "target": "http://example.test", "data": "2026-10-21"},
    )
    text = path.read_text(encoding="utf-8")
    assert "http://example.test" in text
    assert "2026-10-21" in text


def test_report_meta_shows_knowledge_level_and_aggressive_mode(tmp_path):
    # Il "livello" è il livello di conoscenza (1–4), non l'aggressività: va
    # etichettato come tale. La modalità aggressiva è una riga separata (sì/no).
    path = write_report(
        [_finding("media", "Cookie senza flag")],
        str(tmp_path),
        meta={
            "livello": 3,
            "target": "http://example.test",
            "aggressive": True,
            "data": "2026-10-21",
        },
    )
    text = path.read_text(encoding="utf-8")
    assert "Livello di conoscenza:" in text
    assert "Livello di aggressività" not in text
    assert "Modalità aggressiva:" in text
    assert "Modalità aggressiva:** sì" in text


def test_report_meta_aggressive_defaults_to_no(tmp_path):
    # Senza il campo aggressive (o False) la riga mostra "no".
    path = write_report(
        [_finding("media", "Cookie senza flag")],
        str(tmp_path),
        meta={"livello": 1, "target": "http://example.test"},
    )
    text = path.read_text(encoding="utf-8")
    assert "Modalità aggressiva:** no" in text


def test_report_renders_english_when_lang_en(tmp_path):
    path = write_report(
        [_finding("critica", "Cross tenant leak")],
        str(tmp_path),
        meta={
            "livello": 2,
            "target": "http://localhost:8081",
            "aggressive": True,
            "data": "2026-10-21",
        },
        lang="en",
    )
    text = path.read_text(encoding="utf-8")
    # Etichette inglesi presenti, quelle italiane assenti.
    assert "How to fix" in text
    assert "If you ignore the issue" in text
    assert "Come correggere" not in text
    assert "Se ignori il problema" not in text
    # Meta localizzato: livello di conoscenza e modalità aggressiva in inglese.
    assert "Knowledge level:" in text
    assert "Aggressive mode:** yes" in text


def test_report_defaults_to_italian(tmp_path):
    path = write_report(
        [_finding("media", "Header mancante")],
        str(tmp_path),
        meta={"livello": 1, "target": "http://example.test"},
    )
    text = path.read_text(encoding="utf-8")
    assert "Come correggere" in text
    assert "How to fix" not in text


def test_report_header_signals_interrupted_zap_scan(tmp_path):
    # Quando il run è proseguito dopo un crash ZAP (meta["zap_interrotto"]),
    # l'intestazione segnala la copertura ZAP parziale e riporta il motivo.
    motivo = "ConnectionError: daemon non raggiungibile"
    path = write_report(
        [_finding("media", "Cookie senza flag")],
        str(tmp_path),
        meta={
            "livello": 1,
            "target": "http://example.test",
            "zap_interrotto": motivo,
        },
    )
    text = path.read_text(encoding="utf-8")
    assert "**Scansione ZAP interrotta:**" in text
    assert motivo in text
    # La riga di avviso sta nell'intestazione, prima del riepilogo.
    assert text.index("Scansione ZAP interrotta") < text.index("## Riepilogo")


def test_report_header_signals_interrupted_zap_scan_english(tmp_path):
    motivo = "ConnectionError: daemon unreachable"
    path = write_report(
        [_finding("media", "Cookie without flag")],
        str(tmp_path),
        meta={
            "livello": 1,
            "target": "http://example.test",
            "zap_interrotto": motivo,
        },
        lang="en",
    )
    text = path.read_text(encoding="utf-8")
    assert "**ZAP scan interrupted:**" in text
    assert motivo in text
    assert "Scansione ZAP interrotta" not in text


def test_report_header_omits_zap_warning_when_not_interrupted(tmp_path):
    # Retro-compat: senza la chiave, la riga di avviso NON compare.
    path = write_report(
        [_finding("media", "Cookie senza flag")],
        str(tmp_path),
        meta={"livello": 1, "target": "http://example.test"},
    )
    text = path.read_text(encoding="utf-8")
    assert "Scansione ZAP interrotta" not in text
    assert "ZAP scan interrupted" not in text


def test_report_handles_no_findings(tmp_path):
    path = write_report(
        [],
        str(tmp_path),
        meta={"livello": 2, "target": "http://localhost:8081"},
    )
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    # Nessun finding: messaggio rassicurante, non un report vuoto.
    assert "nessun" in text.lower() or "0" in text


def test_write_report_also_writes_html_next_to_md(tmp_path):
    path = write_report(
        [_finding("alta", "Leak tra clienti")],
        str(tmp_path),
        meta={"livello": 2, "target": "http://localhost:8081"},
    )
    html_path = path.with_name("report.html")
    # Il .md resta il valore restituito; l'.html è scritto nella stessa cartella.
    assert path.name == "report.md" and path.exists()
    assert html_path.exists()
    assert html_path.read_text(encoding="utf-8").lstrip().lower().startswith(
        "<!doctype html"
    )
    # Retro-compat: il contenuto del .md non è cambiato (niente markup HTML).
    assert "<!doctype" not in path.read_text(encoding="utf-8").lower()
