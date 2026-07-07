"""Tests du chargement et de la validation de la configuration."""

import pytest

from tracee_agent.config.loader import ConfigError, load_config


def _write(tmp_path, content: str) -> str:
    file = tmp_path / "config.yaml"
    file.write_text(content, encoding="utf-8")
    return str(file)


def test_config_valide_applique_les_defauts(tmp_path):
    path = _write(
        tmp_path,
        """
server:
  url: "wss://example/ws"
  token: "abc"
""",
    )
    config = load_config(path)

    assert config.server.url == "wss://example/ws"
    assert config.capture.snaplen == 1600  # défaut du schéma
    assert config.logging.level == "INFO"  # défaut du schéma


def test_config_fichier_absent_leve_config_error():
    with pytest.raises(ConfigError):
        load_config("/chemin/inexistant/config.yaml")


def test_config_champ_inconnu_rejete(tmp_path):
    # `extra="forbid"` dans le schéma → une typo doit échouer, pas être ignorée.
    path = _write(
        tmp_path,
        """
server:
  url: "wss://example/ws"
  token: "abc"
  oops: 1
""",
    )
    with pytest.raises(ConfigError):
        load_config(path)
