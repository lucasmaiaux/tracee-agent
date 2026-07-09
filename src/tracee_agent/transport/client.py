"""Client WebSocket de l'agent vers le serveur Tracee.

Responsabilités : ouvrir la connexion WSS authentifiée, annoncer l'agent via ``hello``
(US #17), puis faire tourner **en parallèle** la réception (serveur → agent) et
l'émission des ``event`` (agent → serveur, US #18). La reconnexion/backoff et le buffer
de déconnexion restent le périmètre de l'US #19.

L'émission passe par une **file de sortie** (``outbox``) : le pipeline de capture y
dépose les events sans attendre le réseau (dépôt non bloquant). Une tâche dédiée draine
cette file vers la WebSocket. Si le réseau est trop lent et que la file sature, on
préfère perdre des events plutôt que bloquer le pipeline (même logique de backpressure
que la file de capture).
"""

import asyncio
import json

import structlog
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from tracee_agent.config.schema import ServerConfig
from tracee_agent.transport.messages import PROTOCOL_VERSION, build_hello

logger = structlog.get_logger("tracee_agent.transport")

# Plafond de la file d'envoi. Au-delà (réseau trop lent), on jette les events les plus
# récents plutôt que de bloquer la capture. La mise en buffer à la reconnexion est #19.
_OUTBOX_MAXSIZE = 1000


class AgentConnection:
    """Connexion WebSocket authentifiée de l'agent au serveur.

    Args:
        config: URL (``wss://…/ws/agent``) et token M2M de l'agent.
    """

    def __init__(self, config: ServerConfig) -> None:
        self._url = config.url
        self._token = config.token
        # File d'envoi : créée maintenant pour que le producteur (capture) puisse y
        # déposer des events dès le démarrage, indépendamment de l'état de la connexion.
        self._outbox: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=_OUTBOX_MAXSIZE)

    def _headers(self) -> dict[str, str]:
        """En-têtes du handshake HTTP qui ouvre la WebSocket.

        Transmis pendant la poignée de main (encore du HTTP) : le serveur y vérifie
        l'authentification et la compatibilité de version avant d'accepter de basculer
        en WebSocket.
        """
        return {
            "Authorization": f"Bearer {self._token}",
            "X-Protocol-Version": PROTOCOL_VERSION,
        }

    def enqueue_event(self, message: dict[str, object]) -> None:
        """Dépose un message ``event`` dans la file d'envoi, sans bloquer l'appelant.

        Appelé par le pipeline de capture (au flush de l'agrégateur). Si la file est
        pleine (réseau trop lent), l'event est perdu et tracé — on protège la capture.
        """
        try:
            self._outbox.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("file_envoi_saturee_event_perdu")

    async def run(self) -> None:
        """Se connecte, envoie ``hello``, puis reçoit et émet en parallèle.

        Ne relance rien en cas d'échec (la reconnexion est l'US #19) : on journalise
        proprement chaque issue, comme au #17.
        """
        try:
            async with connect(self._url, additional_headers=self._headers()) as ws:
                await ws.send(json.dumps(build_hello()))
                logger.info("hello_envoye", serveur=self._url)
                await self._pump(ws)
        except InvalidStatus as exc:
            # Refus pendant le handshake : le serveur a répondu un code HTTP ≠ 101.
            # 401/403 → token invalide ou révoqué ; autre 4xx → version incompatible.
            logger.error("handshake_refuse", statut=exc.response.status_code)
        except ConnectionClosed as exc:
            # Fermeture anormale après ouverture (une fermeture propre termine simplement
            # la réception ci-dessous sans lever d'exception).
            logger.warning("connexion_fermee", code=exc.code, raison=exc.reason)
        except OSError as exc:
            # Serveur injoignable, DNS, TLS… : on ne plante pas l'agent pour autant.
            logger.error("connexion_impossible", erreur=str(exc))

    async def _pump(self, ws: ClientConnection) -> None:
        """Fait tourner réception et émission en parallèle jusqu'à ce que l'une s'arrête.

        La réception se termine d'elle-même à la fermeture propre du serveur ; l'émission
        est une boucle sans fin. On attend donc la **première** des deux qui s'achève, on
        annule l'autre, puis on relaie une éventuelle exception (ex. ``ConnectionClosed``
        levée par un ``send``) pour que ``run()`` la journalise.
        """
        receive = asyncio.create_task(self._receive(ws))
        send = asyncio.create_task(self._send_loop(ws))
        done, pending = await asyncio.wait({receive, send}, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            task.result()  # re-lève l'exception de la tâche terminée, s'il y en a une

    async def _receive(self, ws: ClientConnection) -> None:
        """Écoute les messages du serveur (welcome/command traités en #19)."""
        async for raw in ws:
            logger.debug("message_serveur_recu", brut=raw)

    async def _send_loop(self, ws: ClientConnection) -> None:
        """Draine la file d'envoi vers la WebSocket, un message à la fois."""
        while True:
            message = await self._outbox.get()
            await ws.send(json.dumps(message))
