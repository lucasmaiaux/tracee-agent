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
import time

import structlog
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from tracee_agent.config.schema import ServerConfig
from tracee_agent.transport.messages import PROTOCOL_VERSION, build_heartbeat, build_hello

logger = structlog.get_logger("tracee_agent.transport")

# Plafond de la file d'envoi, qui sert aussi de tampon pendant une coupure (#19) : les
# events s'y accumulent jusqu'au reconnect. Au-delà, on jette les plus *anciens* (drop des
# plus vieux, docs/PROTOCOL.md) pour garder le trafic récent, sans jamais bloquer la capture.
_OUTBOX_MAXSIZE = 1000

# Reconnexion : délai de retry en backoff exponentiel, plafonné (docs/PROTOCOL.md § reconnexion).
_RECONNECT_BACKOFF_INITIAL_SECONDS = 1.0
_RECONNECT_BACKOFF_MAX_SECONDS = 60.0

# Période d'émission du heartbeat : le signal de présence de l'agent (docs/PROTOCOL.md).
_HEARTBEAT_INTERVAL_SECONDS = 30.0

# Codes de fermeture applicatifs non récupérables (docs/PROTOCOL.md § codes de fermeture) :
# hello invalide (4400), token rejeté (4401), version incompatible (4426). Réessayer
# renverrait le même hello / token / version → on arrête l'agent plutôt que de boucler.
_FATAL_CLOSE_CODES = frozenset({4400, 4401, 4426})


class _FatalRejection(Exception):
    """Refus applicatif non récupérable du serveur : inutile de reconnecter."""


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
        # Compteurs du heartbeat, cumulés sur toute la vie de l'agent (ils persistent aux
        # reconnexions) : total d'events émis et instant de démarrage pour l'uptime.
        self._events_sent = 0
        self._started_at = time.monotonic()

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

        Appelé par le pipeline de capture (au flush) ; sert aussi de tampon de déconnexion,
        où les events s'accumulent jusqu'au reconnect. À saturation (réseau ou coupure
        prolongés), on **écarte le plus ancien** pour garder le trafic récent — jamais on
        ne bloque la capture.
        """
        try:
            self._outbox.put_nowait(message)
        except asyncio.QueueFull:
            # File pleine : on défile le plus ancien (FIFO) pour faire place au nouveau.
            # get_nowait/put_nowait sont synchrones → séquence atomique, aucune coroutine ne
            # s'intercale, la file reste pleine entre les deux : get_nowait aboutit toujours.
            self._outbox.get_nowait()
            self._outbox.put_nowait(message)
            logger.warning("file_pleine_event_ancien_jete")

    async def run(self) -> None:
        """(Re)connecte l'agent au serveur en boucle, avec backoff exponentiel (US #19).

        Chaque connexion envoie ``hello`` puis sert la session (#17/#18). À la coupure, on
        reconnecte après un délai croissant (1→60 s), **réinitialisé** dès qu'une session
        s'est établie — une coupure ponctuelle ne doit pas hériter d'un long délai, alors
        qu'un serveur injoignable fait espacer les tentatives. Un refus non récupérable
        (token/version) arrête l'agent : réessayer ne changerait rien.
        """
        backoff = _RECONNECT_BACKOFF_INITIAL_SECONDS
        while True:
            try:
                established = await self._connect_and_serve()
            except _FatalRejection:
                return  # motif déjà journalisé ; on laisse l'agent s'arrêter proprement
            backoff = (
                _RECONNECT_BACKOFF_INITIAL_SECONDS
                if established
                else min(backoff * 2, _RECONNECT_BACKOFF_MAX_SECONDS)
            )
            await asyncio.sleep(backoff)

    async def _connect_and_serve(self) -> bool:
        """Ouvre une connexion, envoie ``hello``, puis sert jusqu'à la fermeture.

        Returns:
            ``True`` si la connexion s'est établie (même brièvement) puis a été fermée —
            une coupure « normale » que l'on reconnecte sans délai ; ``False`` si
            l'ouverture elle-même a échoué (serveur injoignable, handshake refusé), auquel
            cas l'appelant espace les tentatives via le backoff.

        Raises:
            _FatalRejection: refus applicatif non récupérable (token/version), à ne pas
                retenter.
        """
        try:
            async with connect(self._url, additional_headers=self._headers()) as ws:
                await ws.send(json.dumps(build_hello()))
                logger.info("hello_envoye", serveur=self._url)
                await self._pump(ws)
            return True  # fermeture propre côté serveur → on reconnectera
        except ConnectionClosed as exc:
            # Le serveur accepte la WS puis la ferme avec un code applicatif. On lit le code
            # sur le Close frame *reçu* (``rcvd``) — ``exc.code`` est déprécié ; une coupure
            # brutale sans close frame (``rcvd`` à None) n'a pas de code, donc non fatale.
            close = exc.rcvd
            code = close.code if close is not None else None
            reason = close.reason if close is not None else None
            if code in _FATAL_CLOSE_CODES:
                logger.error("connexion_refusee", code=code, raison=reason)
                raise _FatalRejection from exc
            logger.warning("connexion_fermee", code=code, raison=reason)
            return True  # elle était établie, elle est tombée → coupure normale
        except InvalidStatus as exc:
            # Handshake HTTP ≠ 101 (route absente, 5xx…) : non fatal a priori, on retentera.
            logger.error("handshake_refuse", statut=exc.response.status_code)
            return False
        except OSError as exc:
            # Serveur injoignable, DNS, TLS… : on ne plante pas l'agent, on retentera.
            logger.error("connexion_impossible", erreur=str(exc))
            return False

    async def _pump(self, ws: ClientConnection) -> None:
        """Fait tourner réception, émission et heartbeat en parallèle jusqu'à ce que l'un s'arrête.

        La réception se termine d'elle-même à la fermeture propre du serveur ; l'émission et
        le heartbeat sont des boucles sans fin. On attend la **première** des trois tâches
        qui s'achève, on annule les autres, puis on relaie une éventuelle exception (ex.
        ``ConnectionClosed`` levée par un ``send``) pour que ``_connect_and_serve`` la traite.
        """
        receive = asyncio.create_task(self._receive(ws))
        send = asyncio.create_task(self._send_loop(ws))
        heartbeat = asyncio.create_task(self._heartbeat_loop(ws))
        done, pending = await asyncio.wait(
            {receive, send, heartbeat}, return_when=asyncio.FIRST_COMPLETED
        )

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
            self._events_sent += 1  # compté après l'envoi réussi (cumul pour le heartbeat)

    async def _heartbeat_loop(self, ws: ClientConnection) -> None:
        """Émet un heartbeat à intervalle régulier : prouve que l'agent est vivant.

        Utile même sans trafic (capture à l'arrêt) : c'est le battement que le serveur
        attend pour maintenir l'agent « online ». Tourne le temps d'une connexion — un
        ``ws.send`` sur une connexion fermée lève ``ConnectionClosed``, qui remonte via
        ``_pump`` et déclenche la reconnexion.
        """
        while True:
            await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
            heartbeat = build_heartbeat(self._events_sent, self._uptime_seconds())
            await ws.send(json.dumps(heartbeat))

    def _uptime_seconds(self) -> int:
        """Âge du process agent, en secondes (horloge monotone, insensible aux sauts d'heure)."""
        return int(time.monotonic() - self._started_at)
