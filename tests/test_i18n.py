"""Test della localizzazione del report (``gauntlet.i18n``).

La lingua del report è scelta automaticamente: in ``auto`` si rileva quella di
sistema e, se supportata, si usa; altrimenti si ripiega sull'inglese. Un
override esplicito forza una lingua. La rilevazione non deve mai sollevare.
"""

import gauntlet.i18n as i18n
from gauntlet.i18n import MESSAGES, SUPPORTED, resolve_language, source_label, t

_ENV_VARS = ("LC_ALL", "LC_MESSAGES", "LANG")


def _clear_locale_env(monkeypatch):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_supported_languages():
    assert SUPPORTED == ("it", "en")


def test_explicit_supported_is_returned():
    assert resolve_language("en") == "en"
    assert resolve_language("it") == "it"


def test_explicit_unsupported_falls_back_to_english():
    # Un override esplicito ma non supportato (es. "de") ripiega sull'inglese.
    assert resolve_language("de") == "en"


def test_auto_detects_italian_from_lang(monkeypatch):
    _clear_locale_env(monkeypatch)
    monkeypatch.setenv("LANG", "it_IT.UTF-8")
    assert resolve_language("auto") == "it"
    assert resolve_language(None) == "it"


def test_auto_unsupported_system_falls_back_to_english(monkeypatch):
    _clear_locale_env(monkeypatch)
    monkeypatch.setenv("LANG", "fr_FR")
    assert resolve_language("auto") == "en"


def test_lc_all_takes_precedence_over_lang(monkeypatch):
    monkeypatch.setenv("LC_ALL", "it_IT.UTF-8")
    monkeypatch.setenv("LANG", "fr_FR")
    assert resolve_language("auto") == "it"


def test_detection_never_raises(monkeypatch):
    _clear_locale_env(monkeypatch)

    def _boom(*args, **kwargs):
        raise ValueError("locale non disponibile")

    monkeypatch.setattr(i18n.locale, "getlocale", _boom)
    assert resolve_language("auto") == "en"
    assert resolve_language(None) == "en"


def test_catalog_has_both_languages_with_same_keys():
    assert "it" in MESSAGES and "en" in MESSAGES
    assert set(MESSAGES["it"]) == set(MESSAGES["en"])


def test_t_returns_localized_string():
    assert t("en", "fh_fix") == "**How to fix:**"
    assert t("it", "fh_fix") == "**Come correggere:**"


def test_t_formats_placeholders():
    assert "SEED-A" in t("en", "ac_horizontal_desc",
                          attacker_label="b", url="u", owner_label="a",
                          status=200, marker="SEED-A")


def test_zap_interrupted_key_exists_for_both_languages():
    # La riga di avviso "scansione ZAP interrotta" deve esistere in entrambe le
    # lingue, essere una vera stringa (non il nome della chiave) e non vuota.
    key = "meta_zap_interrupted"
    for lang in SUPPORTED:
        value = MESSAGES[lang][key]
        assert value and value != key


def test_open_redirect_family_present_in_both_languages():
    # La famiglia open_redirect_* deve esistere in it e en, con stringhe vere
    # (non il nome della chiave) e non vuote.
    for suffix in ("title", "desc", "evidence", "fix", "impact"):
        key = f"open_redirect_{suffix}"
        for lang in SUPPORTED:
            value = MESSAGES[lang][key]
            assert value and value != key


def test_open_redirect_renders_placeholders():
    # I segnaposto {url}, {probe}, {location} sono resi in entrambe le lingue e
    # le due traduzioni del desc differiscono (traduzioni effettive).
    kwargs = dict(
        url="http://host/go?next=x",
        probe="https://canary.example/landing",
        location="https://canary.example/landing",
    )
    it_desc = t("it", "open_redirect_desc", **kwargs)
    en_desc = t("en", "open_redirect_desc", **kwargs)
    assert kwargs["url"] in it_desc and kwargs["url"] in en_desc
    assert it_desc != en_desc
    assert "{" not in it_desc and "{" not in en_desc


def test_mass_assignment_family_present_in_both_languages():
    # La famiglia mass_assignment_* deve esistere in it e en, con stringhe vere
    # (non il nome della chiave) e non vuote.
    for suffix in ("title", "desc", "evidence", "fix", "impact"):
        key = f"mass_assignment_{suffix}"
        for lang in SUPPORTED:
            value = MESSAGES[lang][key]
            assert value and value != key


def test_mass_assignment_renders_placeholders():
    # I segnaposto {url}, {field}, {value} sono resi in entrambe le lingue e le
    # due traduzioni del desc differiscono (traduzioni effettive).
    kwargs = dict(url="http://host/api/users/1", field="role", value="admin")
    it_desc = t("it", "mass_assignment_desc", **kwargs)
    en_desc = t("en", "mass_assignment_desc", **kwargs)
    assert kwargs["field"] in it_desc and kwargs["field"] in en_desc
    assert kwargs["value"] in it_desc and kwargs["value"] in en_desc
    assert it_desc != en_desc
    assert "{" not in it_desc and "{" not in en_desc


def test_source_labels_for_new_checks_present_in_both_languages():
    # Le etichette d'origine dei due controlli più recenti (mass-assignment e
    # open-redirect) devono esistere in it e en, essere stringhe vere (non il
    # nome della chiave) e non vuote, così `source_label` stampa un nome
    # leggibile invece della sigla grezza dell'origine.
    for key in ("src_mass-assignment", "src_open-redirect"):
        for lang in SUPPORTED:
            value = MESSAGES[lang][key]
            assert value and value != key


def test_source_label_resolves_friendly_name_for_new_checks():
    # source_label deve risolvere un nome amichevole (non la sigla grezza) per le
    # origini dei due controlli, in entrambe le lingue.
    for source in ("mass-assignment", "open-redirect"):
        for lang in SUPPORTED:
            label = source_label(lang, source)
            assert label and label != source


def test_zap_interrupted_renders_motivo_placeholder():
    # Il segnaposto {motivo} è reso in entrambe le lingue e le due traduzioni
    # differiscono tra loro (traduzioni effettive, non copia).
    motivo = "ConnectionError: boom"
    it_line = t("it", "meta_zap_interrupted", motivo=motivo)
    en_line = t("en", "meta_zap_interrupted", motivo=motivo)
    assert motivo in it_line
    assert motivo in en_line
    assert it_line != en_line
    # Nessun segnaposto residuo non sostituito.
    assert "{motivo}" not in it_line and "{motivo}" not in en_line
