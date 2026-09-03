"""Écriture du config.yaml par l'écran de paramètres."""

import os

import pytest

from tracee_agent.config.loader import load_config
from tracee_agent.config.schema import AgentConfig
from tracee_agent.config.writer import ConfigWriteError, write_config


@pytest.fixture
def config() -> AgentConfig:
    return AgentConfig.model_validate(
        {
            "server": {"url": "wss://tracee.example.com/ws/agent", "token": "trc_agt_abc"},
            "capture": {"default_interface": "eno1", "snaplen": 1600},
            "logging": {"level": "DEBUG", "file": None},
        }
    )


def test_written_config_is_read_back_identically(config, tmp_path):
    """Contrat entre l'écran de paramètres et le chargement au démarrage."""
    path = tmp_path / "config.yaml"

    write_config(config, path)

    assert load_config(str(path)) == config


def test_written_config_carries_a_header(config, tmp_path):
    path = tmp_path / "config.yaml"

    write_config(config, path)

    assert path.read_text(encoding="utf-8").startswith("# Configuration de l'agent Tracee.")


def test_writing_replaces_the_previous_file_and_leaves_no_temporary(config, tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("server:\n  url: 'ws://ancien'\n  token: 'ancien'\n", encoding="utf-8")

    write_config(config, path)

    assert load_config(str(path)).server.token == "trc_agt_abc"
    assert list(tmp_path.iterdir()) == [path]


def test_missing_folder_reports_a_readable_error(config, tmp_path):
    path = tmp_path / "absent" / "config.yaml"

    with pytest.raises(ConfigWriteError, match="Écriture impossible"):
        write_config(config, path)


def test_an_interrupted_write_leaves_the_previous_config_intact(config, monkeypatch, tmp_path):
    """Raison d'être du remplacement atomique : jamais de YAML à moitié écrit."""
    path = tmp_path / "config.yaml"
    previous = "server:\n  url: 'ws://ancien'\n  token: 'ancien'\n"
    path.write_text(previous, encoding="utf-8")

    def fail(*_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", fail)

    with pytest.raises(ConfigWriteError):
        write_config(config, path)

    assert path.read_text(encoding="utf-8") == previous
    assert list(tmp_path.iterdir()) == [path]  # le temporaire a été nettoyé
