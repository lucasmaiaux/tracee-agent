"""Détection des privilèges nécessaires à la capture.

Ouvrir un socket brut est une opération privilégiée sur les deux plateformes visées.
Sans elle, ``PacketCapture.start`` échoue à l'ouverture du socket — un message
d'erreur technique, incompréhensible pour qui a simplement double-cliqué sur le
binaire. Ce module sert à **prévenir avant** plutôt qu'à expliquer après.

C'est volontairement un avertissement et non un verrou : sous Linux, root n'est pas
la seule voie — ``setcap cap_net_raw+ep`` autorise la capture à un utilisateur
ordinaire, et ``geteuid() == 0`` répondrait alors « non privilégié » à un agent
parfaitement capable de capturer. Le seul juge fiable reste l'ouverture du socket.
"""

from __future__ import annotations

import ctypes
import os
import sys

_WINDOWS_HINT = (
    "Privilèges administrateur requis pour capturer.\n"
    "Relancer l'agent par un clic droit → « Exécuter en tant qu'administrateur »."
)

_POSIX_HINT = (
    "Privilèges root requis pour capturer.\n"
    "Relancer avec sudo, ou autoriser le binaire une fois pour toutes :\n"
    "sudo setcap cap_net_raw,cap_net_admin+ep <chemin du binaire>"
)


def is_privileged() -> bool:
    """Indique si le process détient les privilèges habituellement requis pour capturer.

    Un ``False`` ne garantit pas l'échec de la capture (cas des capabilities Linux),
    et un ``True`` ne garantit pas son succès (interface absente, Npcap manquant).
    """
    if sys.platform == "win32":
        # `windll` n'existe que sur Windows ; l'appel passe par le shell plutôt que
        # par une comparaison de SID, qui demanderait bien plus de code pour le
        # même verdict.
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def privilege_warning() -> str | None:
    """Renvoie l'avertissement à afficher, ou ``None`` si les privilèges sont présents."""
    if is_privileged():
        return None
    return _WINDOWS_HINT if sys.platform == "win32" else _POSIX_HINT
