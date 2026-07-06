"""Configuration du logging structuré (structlog) pour l'agent.

Note : ce module s'appelle `logging` mais n'entre pas en conflit avec le
module standard. En Python 3 les imports sont *absolus* par défaut, donc le
`import logging` ci-dessous vise bien la stdlib ; seul `tracee_agent.logging`
désigne ce fichier.
"""

import logging
import sys
from datetime import datetime
from typing import TextIO

import structlog

# ANSI cyan : distingue les logs DEBUG (secondaires) du vert d'INFO. Sans ça,
# structlog colore debug et info de la même couleur (tous deux verts).
_DEBUG_COLOR = "\x1b[36m"


def _readable_timestamp(_: object, __: str, event_dict: dict[str, object]) -> dict[str, object]:
    """Horodatage lisible pour la console : heure locale, millisecondes.

    Produit ``2026-07-06 14:11:54.849`` : on écarte le ``T``/``Z`` de l'ISO
    (bruit visuel) et on tronque les microsecondes à 3 chiffres. Réservé au
    terminal ; les fichiers gardent l'ISO complet (voir ``configure_logging``).
    """
    now = datetime.now().astimezone()
    event_dict["timestamp"] = now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}"
    return event_dict


def configure_logging(level: str = "INFO", log_file: str | None = None) -> None:
    """Configure structlog pour tout l'agent (idempotent).

    Args:
        level: Niveau minimal ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
        log_file: Fichier de destination des logs ; stderr si None.
    """
    numeric_level = logging.getLevelNamesMapping()[level]

    stream: TextIO = sys.stderr
    if log_file is not None:
        # Ouvert pour la durée de vie du process ; fermé à la sortie par l'OS.
        stream = open(log_file, "a", encoding="utf-8")  # noqa: SIM115

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
