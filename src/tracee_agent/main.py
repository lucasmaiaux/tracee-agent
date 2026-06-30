"""Point d'entrée CLI de l'agent Tracee."""

import argparse
import logging

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
    logger.info(
        "tracee-agent démarre (config=%s, interface=%s)",
        args.config,
        args.interface or "depuis la config",
    )
    # La capture réelle arrivera à l'Epic 06 (#6). Ici on valide juste le squelette.


if __name__ == "__main__":
    main()
