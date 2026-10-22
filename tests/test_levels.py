"""Test per l'orchestrazione dei quattro livelli di conoscenza dell'attaccante.

Verifica che :func:`gauntlet.levels.actions_for` mappi correttamente il livello
di conoscenza (1 cieco → 4 sorgente) sul piano di azioni da eseguire.
"""

from __future__ import annotations

import pytest

from gauntlet.levels import LevelPlan, actions_for


def test_level1_is_blind_unauthenticated():
    p = actions_for(1)
    assert p.authenticated is False
    assert p.run_access_control is False
    assert p.uses_docs is False
    assert p.uses_source is False
    # Il livello cieco esegue comunque spidering e scansione sulla superficie pubblica.
    assert p.run_spider is True
    assert p.run_active is True


def test_level2_is_authenticated_with_access_control():
    p = actions_for(2)
    assert p.authenticated is True
    assert p.run_access_control is True
    assert p.uses_docs is False
    assert p.uses_source is False
    assert p.run_spider is True
    assert p.run_active is True


def test_level3_adds_docs():
    p = actions_for(3)
    assert p.authenticated is True
    assert p.run_access_control is True
    assert p.uses_docs is True
    assert p.uses_source is False


def test_level4_uses_source():
    p = actions_for(4)
    assert p.authenticated
    assert p.run_access_control
    assert p.uses_docs
    assert p.uses_source


def test_level_field_matches_requested():
    for level in (1, 2, 3, 4):
        assert actions_for(level).level == level


def test_levels_are_cumulative():
    plans = [actions_for(level) for level in (1, 2, 3, 4)]
    # Ogni livello conserva le capacità del precedente (monotonia crescente).
    for attr in ("authenticated", "run_access_control", "uses_docs", "uses_source"):
        values = [getattr(p, attr) for p in plans]
        assert values == sorted(values), f"{attr} non è monotòno: {values}"


@pytest.mark.parametrize("level", [0, 5, -1, 100])
def test_out_of_range_raises_value_error(level):
    with pytest.raises(ValueError):
        actions_for(level)
