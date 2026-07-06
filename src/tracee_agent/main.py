"""Point d'entrée CLI de l'agent Tracee."""

import argparse
import asyncio

import structlog

from tracee_agent.capture.interfaces import format_interfaces, list_interfaces
from tracee_agent.capture.sniffer import CaptureError, PacketCapture
from tracee_agent.config.loader import ConfigError, load_config
from tracee_agent.config.schema import AgentConfig
from tracee_agent.logging import configure_logging
from tracee_agent.parser import parse_packet

logger = structlog.get_logger("tracee_agent")

# File bornée entre la capture et son consommateur : au-delà, on préfère perdre
# des paquets (backpressure) plutôt que gonfler la mémoire indéfiniment.
_QUEUE_MAXSIZE = 10_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tracee-agent",
        description="Agent de capture réseau pour Tracee",
    )
    parser.add_argument("--config", help="Chemin du fichier config.yaml")
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Lister les interfaces réseau capturables et quitter",
    )
    parser.add_argument("--interface", help="Interface à capturer (surcharge la config)")
    parser.add_argument("--verbose", action="store_true", help="Logs détaillés (DEBUG)")
    return parser.parse_args()


async def _consume(queue: asyncio.Queue[bytes]) -> None:
    """Décode chaque paquet capturé et journalise son 5-tuple.

    Le parsing est branché ici ; l'émission des événements vers le serveur
    (WebSocket) viendra avec le transport (#18). Les paquets hors périmètre
    (non-IP, ni TCP/UDP, ou trop tronqués) sont ignorés par ``parse_packet``.
    """
    while True:
        data = await queue.get()
        packet = parse_packet(data)
        if packet is None:
            continue
        logger.debug(
            "paquet_decode",
            protocole=packet.protocol,
            source=f"{packet.source_ip}:{packet.source_port}",
            destination=f"{packet.dest_ip}:{packet.dest_port}",
            taille=packet.packet_size,
            payload=packet.payload_size,
        )


async def _run(config: AgentConfig, interface: str | None) -> None:
    if interface is None:
        # Un agent de capture ne doit pas écouter « au hasard » : on refuse de
        # démarrer plutôt que de laisser Scapy choisir une interface implicite.
        logger.error("aucune_interface_configuree")
        raise SystemExit(2)

    queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
    capture = PacketCapture(interface, config.capture.snaplen, queue)
    try:
        capture.start()
    except CaptureError as exc:
        logger.error("capture_indisponible", erreur=str(exc))
        raise SystemExit(1) from None
    try:
        await _consume(queue)
    finally:
        capture.stop()  # arrêt propre même sur Ctrl+C / annulation


def main() -> None:
    args = parse_args()
    # Bootstrap : on ne connaît pas encore la config, on part d'un niveau par défaut
    # pour pouvoir déjà rapporter une éventuelle erreur de chargement.
    configure_logging("DEBUG" if args.verbose else "INFO")

    if args.list_interfaces:
        # Produit de la commande → stdout (comme --help), pas un log de diagnostic.
        print(format_interfaces(list_interfaces()))
        return

    if args.config is None:
        logger.error("config_requise", indice="fournir --config ou utiliser --list-interfaces")
        raise SystemExit(2)

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

    try:
        asyncio.run(_run(config, interface))
    except KeyboardInterrupt:
        logger.info("agent_arrete")


if __name__ == "__main__":
    main()
