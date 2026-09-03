"""Moteur de l'agent : le pipeline capture → parsing → agrégation → envoi.

Vit à l'écart du point d'entrée parce qu'il a **deux** frontaux : la ligne de commande
(``main``) et l'écran de paramètres, qui le fait tourner dans un thread de travail. Le
moteur ignore lequel l'appelle — il remonte ses échecs en exception et laisse chacun
décider quoi en faire.
"""

import asyncio

import structlog

from tracee_agent.capture.sniffer import CaptureError, PacketCapture
from tracee_agent.config.schema import AgentConfig
from tracee_agent.flow import FlowAggregator
from tracee_agent.identifier import ServiceIdentifier
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


async def run_agent(config: AgentConfig, interface: str | None) -> None:
    """Fait tourner l'agent jusqu'à son arrêt (annulation, capture morte ou refus serveur).

    Ne décide jamais du sort du process : les échecs remontent en exception, à charge de
    l'appelant de les traduire. La ligne de commande en fait un code de sortie, l'écran de
    paramètres un message — et une ``SystemExit`` levée ici serait de toute façon avalée en
    silence par ``threading`` quand l'agent tourne dans un thread de travail.

    L'annulation de la coroutine est le moyen d'arrêt normal : le ``finally`` libère
    l'interface au passage de la ``CancelledError``.

    Raises:
        CaptureError: Aucune interface sélectionnée, ou capture impossible à démarrer.
    """
    if interface is None:
        # Un agent de capture ne doit pas écouter « au hasard » : on refuse de
        # démarrer plutôt que de laisser Scapy choisir une interface implicite.
        raise CaptureError("Aucune interface sélectionnée.")

    queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
    capture = PacketCapture(interface, config.capture.snaplen, queue)
    connection = AgentConnection(config.server)
    aggregator = FlowAggregator()
    # État d'identification partagé sur toute la session : réassembleur de ClientHello
    # (un SNI peut s'étaler sur plusieurs segments TCP) et identificateur (carnet SNI par
    # flux + cache DNS observé), alimentés par _consume et consultés par _flush_loop.
    identifier = ServiceIdentifier()
    reassembler = ClientHelloReassembler()
    # Échec ici (interface absente, droits insuffisants) : `CaptureError` remonte à
    # l'appelant, déjà journalisée par `PacketCapture.start`.
    capture.start()

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
        # Ordre voulu : libérer l'interface d'abord, annuler ensuite. Les deux appels sont
        # synchrones, donc inratables — un `await` ici serait relancé par l'annulation en
        # cours et pourrait sauter la libération de l'interface. Le nettoyage des tâches
        # annulées revient à `asyncio.run`, qui les attend avant de fermer la boucle.
        capture.stop()
        for task in tasks:
            task.cancel()
