"""Gauntlet — skill riutilizzabile di security-testing (DAST) per app web.

Il pacchetto espone il caricatore del contratto di progetto e i modelli
condivisi; i sottosistemi di scansione, autenticazione e reporting sono
aggiunti dai task successivi del piano.
"""

from __future__ import annotations

from gauntlet.contract import (
    Account,
    Contract,
    ContractError,
    LoginConfig,
    Resource,
    load_contract,
    resolve_password,
)
from gauntlet.models import Finding

__all__ = [
    "Account",
    "Contract",
    "ContractError",
    "Finding",
    "LoginConfig",
    "Resource",
    "load_contract",
    "resolve_password",
]

__version__ = "0.1.0"
