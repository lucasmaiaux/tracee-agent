"""Chargement + validation du fichier de configuration YAML."""

from pathlib import Path

import yaml
from pydantic import ValidationError

from tracee_agent.config.schema import AgentConfig


class ConfigError(Exception):
    """Erreur de configuration, avec un message destiné à l'utilisateur."""


def load_config(path: str) -> AgentConfig:
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"Fichier de configuration introuvable : {path}")
    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML invalide dans {path} :\n{exc}") from exc
    try:
        return AgentConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Configuration invalide :\n{exc}") from exc
