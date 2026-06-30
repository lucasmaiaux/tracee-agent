"""Point d'entrée CLI de l'agent Tracee."""

import argparse
import logging

from tracee_agent.config.loader import ConfigError, load_config

logger = logging.getLogger("tracee_agent")


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
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        logger.error("%s", exc)
        raise SystemExit(2)

    interface = args.interface or config.capture.default_interface
    logger.info("tracee-agent démarre (interface=%s, serveur=%s)", interface, config.server.url)


if __name__ == "__main__":
    main()
