"""Client WebSocket de l'agent vers le serveur Tracee.

Responsabilité (US #17) : ouvrir la connexion WSS authentifiée, annoncer l'agent
via le message ``hello``, puis rester à l'écoute jusqu'à la fermeture du serveur.
L'envoi des ``event`` (#18) et la reconnexion/heartbeat (#19) viendront enrichir
cette classe ; ils ne sont volontairement pas ici.
"""

import json

import structlog
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from tracee_agent.config.schema import ServerConfig
from tracee_agent.transport.messages import PROTOCOL_VERSION, build_hello

logger = structlog.get_logger("tracee_agent.transport")


class AgentConnection:
    """Connexion WebSocket authentifiée de l'agent au serveur.

    Args:
        config: URL (``wss://…/ws/agent``) et token M2M de l'agent.
    """

    def __init__(self, config: ServerConfig) -> None:
        self._url = config.url
        self._token = config.token

    def _headers(self) -> dict[str, str]:
        """En-têtes du handshake HTTP qui ouvre la WebSocket.

        Transmis pendant la poignée de main (encore du HTTP) : le serveur y
        vérifie l'authentification et la compatibilité de version avant d'accepter
        de basculer en WebSocket.
        """
        return {
            "Authorization": f"Bearer {self._token}",
            "X-Protocol-Version": PROTOCOL_VERSION,
        }

    async def run(self) -> None:
        """Se connecte, envoie ``hello``, puis écoute jusqu'à fermeture serveur.

        Ne relance rien en cas d'échec : la reconnexion (backoff) est le périmètre
        de l'US #19. Ici on se contente de journaliser proprement chaque issue.
        """
        try:
            async with connect(self._url, additional_headers=self._headers()) as ws:
                await ws.send(json.dumps(build_hello()))
                logger.info("hello_envoye", serveur=self._url)
                # Boucle de réception : pour l'instant on ne fait que journaliser
                # (welcome/command seront traités en #18/#19). Elle se termine
                # d'elle-même quand le serveur ferme normalement la connexion.
                async for raw in ws:
                    logger.debug("message_serveur_recu", brut=raw)
        except InvalidStatus as exc:
            # Refus pendant le handshake : le serveur a répondu un code HTTP ≠ 101.
            # 401/403 → token invalide ou révoqué ; autre 4xx → version incompatible.
            logger.error("handshake_refuse", statut=exc.response.status_code)
        except ConnectionClosed as exc:
            # Fermeture anormale après ouverture (une fermeture propre termine
            # simplement la boucle ci-dessus sans lever d'exception).
            logger.warning("connexion_fermee", code=exc.code, raison=exc.reason)
        except OSError as exc:
            # Serveur injoignable, DNS, TLS… : on ne plante pas l'agent pour autant.
            logger.error("connexion_impossible", erreur=str(exc))
