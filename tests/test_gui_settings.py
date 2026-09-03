"""Règles de l'écran de paramètres : pré-remplissage, validation, persistance.

Hors mode gelé, `config_path` se base sur le répertoire courant : `monkeypatch.chdir`
suffit donc à isoler chaque test dans son propre dossier de profils.
"""

import pytest

from tracee_agent.config.loader import load_config
from tracee_agent.gui.settings import (
    DEFAULT_DEBUG_SERVER_URL,
    DEFAULT_SERVER_URL,
    Settings,
    SettingsError,
    build_config,
    load_settings,
    save_config,
    server_url,
)

_VALID = Settings(token="trc_agt_abc", interface="eno1")


@pytest.fixture(autouse=True)
def profiles_folder(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def write_profile(folder, name: str, body: str) -> None:
    (folder / name).write_text(body, encoding="utf-8")


# --- Pré-remplissage ---------------------------------------------------------------


def test_first_launch_offers_empty_fields(profiles_folder):
    assert load_settings() == Settings()


def test_a_broken_profile_still_opens_the_screen(profiles_folder):
    """L'écran sert à réparer une configuration : il doit s'ouvrir quand elle est cassée."""
    write_profile(profiles_folder, "config.yaml", "server: [ceci n'est pas: du yaml valide")

    assert load_settings() == Settings()


def test_existing_profile_prefills_the_fields(profiles_folder):
    write_profile(
        profiles_folder,
        "config.yaml",
        "server:\n"
        "  url: 'wss://tracee.example.com/ws/agent'\n"
        "  token: 'trc_agt_abc'\n"
        "capture:\n"
        "  default_interface: 'eno1'\n",
    )

    assert load_settings() == _VALID


def test_debug_profile_is_read_from_its_own_file(profiles_folder):
    write_profile(
        profiles_folder,
        "config.local.yaml",
        "server:\n  url: 'ws://localhost:8000/ws/agent'\n  token: 'trc_agt_local'\n",
    )

    assert load_settings(debug=True).token == "trc_agt_local"
    assert load_settings().token == ""  # le profil normal reste vierge


# --- URL du serveur : non saisie, seulement affichée -------------------------------


def test_a_bare_machine_already_knows_which_server_to_reach(profiles_folder):
    """Binaire posé sur un Bureau vierge : il ne manque que le token."""
    assert server_url() == DEFAULT_SERVER_URL
    assert server_url(debug=True) == DEFAULT_DEBUG_SERVER_URL


def test_an_existing_profile_overrides_the_default_url(profiles_folder):
    write_profile(
        profiles_folder,
        "config.yaml",
        "server:\n  url: 'wss://tracee.mondomaine.fr/ws/agent'\n  token: 't'\n",
    )

    assert server_url() == "wss://tracee.mondomaine.fr/ws/agent"
    assert build_config(_VALID).server.url == "wss://tracee.mondomaine.fr/ws/agent"


def test_a_hand_edited_url_that_is_not_a_websocket_is_reported(profiles_folder):
    write_profile(profiles_folder, "config.yaml", "server:\n  url: 'https://x'\n  token: 't'\n")

    with pytest.raises(SettingsError, match="config.yaml"):
        build_config(_VALID)


# --- Validation de la saisie -------------------------------------------------------


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (Settings(interface="eno1"), "token d'agent est obligatoire"),
        (Settings(token="t"), "Choisir une interface"),
    ],
)
def test_incomplete_input_is_refused_with_a_readable_message(settings, expected):
    with pytest.raises(SettingsError, match=expected):
        build_config(settings)


def test_surrounding_whitespace_is_trimmed():
    """Un token collé depuis la page Agents traîne souvent une espace ou un saut de ligne."""
    config = build_config(Settings(token="  trc_agt_abc\n", interface=" eno1 "))

    assert config.server.token == "trc_agt_abc"
    assert config.capture.default_interface == "eno1"


def test_settings_untouched_by_the_screen_survive(profiles_folder):
    """Ce qui a été réglé à la main dans le YAML n'est pas écrasé par un passage à l'écran."""
    write_profile(
        profiles_folder,
        "config.yaml",
        "server:\n"
        "  url: 'wss://ancien/ws'\n"
        "  token: 'ancien'\n"
        "capture:\n"
        "  default_interface: 'wlan0'\n"
        "  snaplen: 512\n"
        "logging:\n"
        "  level: 'DEBUG'\n"
        "  file: '/var/log/tracee-agent.log'\n",
    )

    config = build_config(_VALID)

    assert config.capture.snaplen == 512
    assert config.logging.level == "DEBUG"
    assert config.logging.file == "/var/log/tracee-agent.log"
    assert config.server.url == "wss://ancien/ws"
    assert config.capture.default_interface == "eno1"  # la saisie, elle, prime
    assert config.server.token == "trc_agt_abc"


def test_defaults_apply_when_there_is_no_previous_profile():
    config = build_config(_VALID)

    assert config.capture.snaplen == 1600
    assert config.logging.level == "INFO"


# --- Persistance -------------------------------------------------------------------


def test_saving_then_reopening_shows_the_same_values(profiles_folder):
    """Parcours de démo : ce qui a été saisi est retrouvé au lancement suivant."""
    saved = save_config(build_config(_VALID))

    assert saved == profiles_folder / "config.yaml"
    assert load_settings() == _VALID


def test_saving_persists_the_default_url_for_the_next_launch(profiles_folder):
    save_config(build_config(_VALID))

    assert load_config("config.yaml").server.url == DEFAULT_SERVER_URL


def test_each_profile_keeps_its_own_token(profiles_folder):
    save_config(build_config(_VALID))
    save_config(build_config(Settings(token="local", interface="lo"), debug=True), debug=True)

    assert load_config("config.yaml").server.token == "trc_agt_abc"
    assert load_config("config.local.yaml").server.token == "local"
    assert load_config("config.local.yaml").server.url == DEFAULT_DEBUG_SERVER_URL
