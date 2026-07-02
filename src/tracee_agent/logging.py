"""Configuration du logging structuré (structlog) pour l'agent.

Note : ce module s'appelle `logging` mais n'entre pas en conflit avec le
module standard. En Python 3 les imports sont *absolus* par défaut, donc le
`import logging` ci-dessous vise bien la stdlib ; seul `tracee_agent.logging`
désigne ce fichier.
"""

import logging
import sys
from typing import TextIO

import structlog


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

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # Couleurs seulement en terminal interactif, pas dans un fichier.
            structlog.dev.ConsoleRenderer(colors=stream.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(file=stream),
        cache_logger_on_first_use=True,
    )
