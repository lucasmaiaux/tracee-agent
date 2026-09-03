"""Écriture du fichier de configuration, pendant de ``loader.load_config``.

Sert l'écran de paramètres : ce que l'utilisateur saisit y est persisté pour être
pré-rempli au lancement suivant. Le fichier est réécrit en entier depuis le modèle
validé — PyYAML sérialise une structure, pas un texte, et ne sait donc pas préserver
les commentaires d'un fichier édité à la main.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from tracee_agent.config.schema import AgentConfig

_HEADER = (
    "# Configuration de l'agent Tracee.\n"
    "# Écrite par l'écran de paramètres ; modifiable à la main.\n"
    "# Contient le token M2M de l'agent : ne pas partager ni committer.\n"
)


class ConfigWriteError(Exception):
    """Écriture impossible, avec un message destiné à l'utilisateur."""


def write_config(config: AgentConfig, path: Path) -> None:
    """Écrit la configuration en YAML, en remplaçant le fichier existant.

    L'écriture passe par un fichier temporaire, renommé ensuite sur la cible. Un
    remplacement interrompu (disque plein, coupure) laisse alors l'ancien fichier
    intact, là où une écriture directe produirait un YAML tronqué qui ferait échouer
    le démarrage suivant. Le temporaire est créé dans le **même dossier** : le
    renommage n'est atomique qu'à l'intérieur d'un volume.

    Args:
        config: Configuration validée à persister.
        path: Fichier cible, créé ou remplacé.

    Raises:
        ConfigWriteError: Dossier absent, droits insuffisants, disque plein.
    """
    body = yaml.safe_dump(config.model_dump(), sort_keys=False, allow_unicode=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        temporary.write_text(_HEADER + body, encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ConfigWriteError(f"Écriture impossible dans {path} : {exc.strerror or exc}") from exc
