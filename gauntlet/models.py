"""Modelli condivisi fra i sottosistemi di Gauntlet.

Questo modulo contiene strutture dati stabili usate da più task del piano.
Al momento espone soltanto :class:`Finding`, il risultato normalizzato di un
controllo di sicurezza, prodotto sia dal runner ZAP sia dal tester di
controllo-accessi e consumato dal generatore di report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: Da dove proviene un risultato: scansione ZAP, test di controllo-accessi,
#: controllo sulle debolezze JWT, configurazione CORS, assenza di rate limiting
#: sul login, divulgazione di errori/stack trace, open redirect o assegnazione
#: di massa (campi protetti scrivibili tramite update non filtrato).
FindingSource = Literal[
    "zap",
    "access-control",
    "jwt",
    "cors",
    "rate-limit",
    "error-disclosure",
    "open-redirect",
    "mass-assignment",
]

#: Gravità in italiano, dalla più critica alla meramente informativa.
#: L'ordinamento del report segue questa scala (critica → info).
Severity = Literal["critica", "alta", "media", "bassa", "info"]


@dataclass
class Finding:
    """Un singolo risultato di sicurezza, normalizzato e pronto per il report.

    Attributi:
        source: origine del risultato (``"zap"``, ``"access-control"``, ``"jwt"``
            o ``"cors"``).
        severity: gravità in italiano (``critica``/``alta``/``media``/``bassa``/``info``).
        title: titolo sintetico del problema.
        description: descrizione estesa del problema riscontrato.
        evidence: prova concreta (richiesta/risposta, payload, diff cross-tenant).
        fix: rimedio consigliato.
        impact_if_ignored: conseguenza concreta se il problema viene ignorato.
        confidence: confidenza del rilevamento, da 0.0 a 1.0.
        url: URL interessato, se applicabile.
    """

    source: FindingSource
    severity: Severity
    title: str
    description: str
    evidence: str
    fix: str
    impact_if_ignored: str
    confidence: float
    url: str | None = None
