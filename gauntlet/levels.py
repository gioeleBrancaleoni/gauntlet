"""Orchestrazione dei quattro livelli di conoscenza dell'attaccante.

Gauntlet modella la postura di attacco come quattro livelli crescenti di
conoscenza che il tester ha del bersaglio. Ogni livello abilita le capacità
del precedente e ne aggiunge di nuove (monotonia crescente):

1. **cieco** — nessuna credenziale né documentazione: solo la superficie
   pubblica. Si esegue spidering e scansione attiva, ma non i test di
   controllo-accessi (servono utenti autenticati).
2. **utente** — si dispone di credenziali valide: si aggiunge
   l'autenticazione e i test di controllo-accessi cross-tenant.
3. **documentazione** — oltre alle credenziali si ha la documentazione delle
   API/endpoint, che amplia la superficie nota.
4. **sorgente** — si ha anche il codice sorgente dell'applicazione.

Questo modulo è pura configurazione, senza dipendenze esterne: traduce il
livello richiesto in un :class:`LevelPlan` che i task successivi (vedi task 9)
consumano per decidere quali azioni eseguire.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Livello minimo e massimo di conoscenza supportati.
MIN_LEVEL = 1
MAX_LEVEL = 4


@dataclass(frozen=True)
class LevelPlan:
    """Piano di azioni per un dato livello di conoscenza dell'attaccante.

    Attributi:
        level: livello richiesto (da 1 a 4).
        authenticated: se eseguire i controlli con un utente autenticato.
        run_spider: se eseguire lo spidering della superficie.
        run_active: se eseguire la scansione attiva.
        run_access_control: se eseguire i test di controllo-accessi cross-tenant.
        uses_docs: se sfruttare la documentazione delle API/endpoint.
        uses_source: se sfruttare il codice sorgente dell'applicazione.
    """

    level: int
    authenticated: bool
    run_spider: bool
    run_active: bool
    run_access_control: bool
    uses_docs: bool
    uses_source: bool


def actions_for(level: int) -> LevelPlan:
    """Restituisce il :class:`LevelPlan` per il livello di conoscenza dato.

    Args:
        level: livello di conoscenza dell'attaccante, da 1 (cieco) a 4 (sorgente).

    Returns:
        Il piano di azioni corrispondente al livello.

    Raises:
        ValueError: se ``level`` è fuori dall'intervallo 1-4.
    """
    if level < MIN_LEVEL or level > MAX_LEVEL:
        raise ValueError(
            f"livello non valido: {level!r}; atteso un intero fra "
            f"{MIN_LEVEL} e {MAX_LEVEL}"
        )

    # Lo spidering e la scansione attiva girano a ogni livello, sempre sulla
    # superficie disponibile; le altre capacità si accendono per soglia.
    return LevelPlan(
        level=level,
        authenticated=level >= 2,
        run_spider=True,
        run_active=True,
        run_access_control=level >= 2,
        uses_docs=level >= 3,
        uses_source=level >= 4,
    )
