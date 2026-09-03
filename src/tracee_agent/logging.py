"""Configuration du logging structuré (structlog) pour l'agent.

Note : ce module s'appelle `logging` mais n'entre pas en conflit avec le
module standard. En Python 3 les imports sont *absolus* par défaut, donc le
`import logging` ci-dessous vise bien la stdlib ; seul `tracee_agent.logging`
désigne ce fichier.
"""

import logging
import os
import sys
from datetime import datetime
from typing import TextIO

import structlog

# ANSI cyan vif (bright) : distingue les logs DEBUG du vert d'INFO. On prend la
# variante « bright » (96) car le cyan simple (36) est rendu très sombre par
# certains thèmes de terminal, au point d'être illisible.
_DEBUG_COLOR = "\x1b[96m"


def _readable_timestamp(_: object, __: str, event_dict: dict[str, object]) -> dict[str, object]:
    """Horodatage lisible pour la console : heure locale, millisecondes.

    Produit ``2026-07-06 14:11:54.849`` : on écarte le ``T``/``Z`` de l'ISO
    (bruit visuel) et on tronque les microsecondes à 3 chiffres. Réservé au
    terminal ; les fichiers gardent l'ISO complet (voir ``configure_logging``).
    """
    now = datetime.now().astimezone()
    event_dict["timestamp"] = now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}"
    return event_dict


def _escape(value: str) -> str:
    """Rend les octets de contrôle en ``\\xHH``, en gardant sauts de ligne et tabulations."""
    return "".join(c if c in "\n\t" or c.isprintable() else f"\\x{ord(c):02x}" for c in value)


def _escape_control_chars(_: object, __: str, event_dict: dict[str, object]) -> dict[str, object]:
    """Neutralise les octets de contrôle des valeurs journalisées (assainissement de sortie).

    Une donnée venue du réseau (ex. un SNI tiré d'un flux mal formé) peut contenir
    un ESC ou un autre caractère de contrôle qui, envoyé brut au terminal,
    corromprait l'affichage (injection de séquence d'échappement). On l'échappe ici,
    façon Suricata/Zeek — sans toucher aux ``\\n``/``\\t`` qui structurent les tracebacks.
    """
    for key, value in event_dict.items():
        if isinstance(value, str) and not value.isprintable():
            event_dict[key] = _escape(value)
    return event_dict


def configure_logging(level: str = "INFO", log_file: str | None = None) -> None:
    """Configure structlog pour tout l'agent (idempotent).

    Args:
        level: Niveau minimal ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
        log_file: Fichier de destination des logs ; stderr si None.
    """
    numeric_level = logging.getLevelNamesMapping()[level]

    stream: TextIO | None = sys.stderr
    if log_file is not None:
        # Ouvert pour la durée de vie du process ; fermé à la sortie par l'OS.
        stream = open(log_file, "a", encoding="utf-8")  # noqa: SIM115
    if stream is None:
        # Exécutable construit sans console : Windows ne fournit alors aucune sortie
        # standard et `sys.stderr` vaut None. Journaliser dans le vide plutôt que de
        # laisser structlog écrire sur None — l'exception tomberait au premier message,
        # et il n'y aurait aucune console pour l'afficher.
        stream = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115

    # La console (terminal) privilégie la lisibilité ; un fichier privilégie un
    # format machine stable (ISO, UTC) pour le grep et l'agrégation.
    interactive = stream.isatty()
    timestamper = (
        _readable_timestamp if interactive else structlog.processors.TimeStamper(fmt="iso")
    )

    level_styles = structlog.dev.ConsoleRenderer.get_default_level_styles()
    level_styles["debug"] = _DEBUG_COLOR

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _escape_control_chars,  # assainit avant rendu : jamais d'octet brut au terminal
            structlog.dev.ConsoleRenderer(
                colors=interactive,
                sort_keys=False,  # garde l'ordre d'insertion des champs, pas l'alphabétique
                level_styles=level_styles,
            ),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(file=stream),
        cache_logger_on_first_use=True,
    )
