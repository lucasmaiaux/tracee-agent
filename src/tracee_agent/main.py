"""Point d'entrée CLI de l'agent Tracee."""

import argparse
import asyncio

import structlog

from tracee_agent.capture.interfaces import format_interfaces, list_interfaces
from tracee_agent.capture.sniffer import CaptureError, PacketCapture
from tracee_agent.config.loader import ConfigError, load_config
from tracee_agent.config.schema import AgentConfig
from tracee_agent.flow import FlowAggregator
from tracee_agent.identifier import ServiceIdentifier
from tracee_agent.logging import configure_logging
from tracee_agent.parser import ClientHelloReassembler, parse_dns, parse_packet
from tracee_agent.transport.client import AgentConnection
from tracee_agent.transport.messages import build_event

logger = structlog.get_logger("tracee_agent")

# File bornée entre la capture et son consommateur : au-delà, on préfère perdre
# des paquets (backpressure) plutôt que gonfler la mémoire indéfiniment.
_QUEUE_MAXSIZE = 10_000

# Fenêtre d'agrégation : toutes les 2 s, les flux accumulés deviennent des events.
# Fenêtre courte = globe temps réel (l'équivalent d'un « active timeout » NetFlow court).
_FLUSH_INTERVAL_SECONDS = 2.0


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


async def _consume(
    queue: asyncio.Queue[bytes],
    aggregator: FlowAggregator,
    identifier: ServiceIdentifier,
    reassembler: ClientHelloReassembler,
) -> None:
    """Décode chaque paquet, l'agrège dans son flux, alimente l'identification et journalise.

    Tout paquet IP retenu par ``parse_packet`` est imputé à son flux (agrégateur) ; en
    parallèle, les messages DNS et les ClientHello TLS alimentent l'identification de
    service (cache DNS + carnet SNI), consultée plus tard au flush. Les paquets hors
    périmètre (non-IP ou trop tronqués) sont ignorés par ``parse_packet``.

    Journalisation d'observation : un log DEBUG par paquet décodé (mode ``--verbose`` /
    ``dev-all``) et un log INFO à chaque nouveau SNI détecté (mode ``dev``).
    """
    while True:
        data = await queue.get()
        packet = parse_packet(data)
        if packet is None:
            continue
        aggregator.add(packet)
        logger.debug(
            "paquet_decode",
            protocole=packet.protocol,
            source=f"{packet.source_ip}:{packet.source_port}",
            destination=f"{packet.dest_ip}:{packet.dest_port}",
            taille=packet.packet_size,
            payload=packet.payload_size,
        )

        # Observation DNS : les messages sur UDP/53 alimentent le cache IP → domaine
        # (les réponses portent les résolutions ; une requête est un no-op).
        if packet.protocol == "udp" and 53 in (packet.source_port, packet.dest_port):
            message = parse_dns(packet.payload)
            if message is not None:
                identifier.observe_dns(message)

        # Identification par SNI : un ClientHello TLS révèle le domaine visé,
        # éventuellement reconstitué à partir de plusieurs segments. On mémorise le SNI
        # pour tout le flux ; il sera résolu au flush (SNI > DNS) via ``identifier.resolve``.
        if packet.protocol == "tcp" and packet.payload:
            flow = (packet.source_ip, packet.source_port, packet.dest_ip, packet.dest_port)
            sni = reassembler.feed(flow, packet.payload)
            if sni is not None:
                identifier.observe_sni(flow, sni)
                # Nouveau SNI détecté → une ligne INFO (comportement dev historique).
                logger.info(
                    "service_identifie",
                    source="sni",
                    service=sni,
                    destination=packet.dest_ip,
                )


async def _flush_loop(
    aggregator: FlowAggregator,
    identifier: ServiceIdentifier,
    connection: AgentConnection,
    interface: str,
) -> None:
    """Transforme périodiquement les flux accumulés en events prêts à envoyer.

    Toutes les ``_FLUSH_INTERVAL_SECONDS``, pour chaque flux de la fenêtre écoulée : on
    résout son ``service_hint`` (SNI > DNS) puis on dépose l'``event`` dans la file
    d'envoi du transport (dépôt non bloquant, perdu si la file sature).
    """
    while True:
        await asyncio.sleep(_FLUSH_INTERVAL_SECONDS)
        for record in aggregator.flush():
            flow = (record.source_ip, record.source_port, record.dest_ip, record.dest_port)
            hint = identifier.resolve(flow)
            connection.enqueue_event(build_event(interface, record, hint))


async def _run(config: AgentConfig, interface: str | None) -> None:
    if interface is None:
        # Un agent de capture ne doit pas écouter « au hasard » : on refuse de
        # démarrer plutôt que de laisser Scapy choisir une interface implicite.
        logger.error("aucune_interface_configuree")
        raise SystemExit(2)

    queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
    capture = PacketCapture(interface, config.capture.snaplen, queue)
    connection = AgentConnection(config.server)
    aggregator = FlowAggregator()
    # État d'identification partagé sur toute la session : réassembleur de ClientHello
    # (un SNI peut s'étaler sur plusieurs segments TCP) et identificateur (carnet SNI par
    # flux + cache DNS observé), alimentés par _consume et consultés par _flush_loop.
    identifier = ServiceIdentifier()
    reassembler = ClientHelloReassembler()
    try:
        capture.start()
    except CaptureError as exc:
        logger.error("capture_indisponible", erreur=str(exc))
        raise SystemExit(1) from None

    # Trois tâches concurrentes : réseau (connexion, avec reconnexion auto #19),
    # décodage/agrégation, flush périodique. La connexion se relance seule à chaque
    # coupure ; on ne s'arrête donc que si une tâche meurt (capture morte) ou si le serveur
    # rejette l'agent définitivement (token/version) — d'où le FIRST_COMPLETED ci-dessous.
    tasks = [
        asyncio.create_task(connection.run()),
        asyncio.create_task(_consume(queue, aggregator, identifier, reassembler)),
        asyncio.create_task(_flush_loop(aggregator, identifier, connection, interface)),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            task.result()  # propage une éventuelle exception (hors annulation)
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
