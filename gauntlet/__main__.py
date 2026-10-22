"""Esecuzione come modulo: ``python -m gauntlet run --project <path> --level <N>``.

Delega a :func:`gauntlet.cli.main` e ne propaga il codice di uscita.
"""

from __future__ import annotations

from gauntlet.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
