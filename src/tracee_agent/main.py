"""Point d'entrée CLI de l'agent Tracee."""

import argparse

import structlog

from tracee_agent.config.loader import ConfigError, load_config
from tracee_agent.logging import configure_logging

logger = structlog.get_logger("tracee_agent")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tracee-agent",
        description="Agent de capture réseau pour Tracee",
    )
    parser.add_argument("--config", required=True, help="Chemin du fichier config.yaml")
    parser.add_argument("--interface", help="Interface à capturer (surcharge la config)")
    parser.add_argument("--verbose", action="store_true", help="Logs détaillés (DEBUG)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # Bootstrap : on ne connaît pas encore la config, on part d'un niveau par défaut
    # pour pouvoir déjà rapporter une éventuelle erreur de chargement.
    configure_logging("DEBUG" if args.verbose else "INFO")
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        logger.error("configuration_invalide", erreur=str(exc))
        raise SystemExit(2) from None

    # Reconfigure selon la config (--verbose garde la priorité sur le niveau du fichier).
    level = "DEBUG" if args.verbose else config.logging.level
    configure_logging(level, config.logging.file)

    interface = args.interface or config.capture.default_interface
    logger.info("agent_demarre", interface=interface, serveur=config.server.url)


if __name__ == "__main__":
    main()
