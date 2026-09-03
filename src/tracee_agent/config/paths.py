"""Emplacement des fichiers modifiables par l'utilisateur, selon le mode d'exécution.

Un exécutable PyInstaller se **décompresse au lancement** dans un dossier temporaire
(``sys._MEIPASS``), détruit à la fermeture du process. Dans ce mode, ``__file__`` — et
donc tout chemin calculé « à côté du code » — pointe dans ce dossier jetable : une
configuration écrite là disparaîtrait au redémarrage suivant. Le seul repère stable est
``sys.executable``, qui désigne le binaire tel que l'utilisateur l'a posé sur sa machine.

En développement, l'agent tourne depuis le venv : ``sys.executable`` vaut alors
``.venv/bin/python``, sans intérêt comme repère. On retombe sur le répertoire de travail
courant, qui est déjà la convention du Makefile (``CONFIG ?= config.yaml``).
"""

from __future__ import annotations

import sys
from pathlib import Path

CONFIG_FILENAME = "config.yaml"

# Profil de mise au point : vise un backend local plutôt que le serveur de production.
# C'est un fichier distinct et non un simple niveau de log, parce que le token M2M d'un
# agent déclaré sur le backend local n'est pas celui du serveur distant — les garder
# séparés évite de recoller un token à chaque bascule. Pendant graphique de `make
# local-dev`, qui pointe déjà ce fichier.
DEBUG_CONFIG_FILENAME = "config.local.yaml"


def is_frozen() -> bool:
    """Indique si le code tourne depuis un exécutable PyInstaller.

    PyInstaller pose ``sys.frozen`` à ``True`` dans le binaire qu'il produit ;
    l'attribut est absent d'un interpréteur CPython normal.
    """
    return bool(getattr(sys, "frozen", False))


def app_dir() -> Path:
    """Renvoie le dossier de référence des fichiers utilisateur.

    Returns:
        Le dossier contenant le binaire si l'agent est gelé, le répertoire de travail
        courant sinon.
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def config_path(*, debug: bool = False) -> Path:
    """Renvoie le fichier de configuration du profil demandé.

    Utilisé quand aucun ``--config`` n'est fourni : la ligne de commande garde la
    priorité, ce sélecteur ne sert qu'aux lancements sans argument.

    Args:
        debug: Vise le profil de mise au point (backend local) au lieu du profil normal.
    """
    return app_dir() / (DEBUG_CONFIG_FILENAME if debug else CONFIG_FILENAME)
