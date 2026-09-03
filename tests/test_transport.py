"""Tests du client WebSocket de l'agent (US #17 : connexion + hello ; #19 : reconnexion).

On monte un vrai serveur WebSocket éphémère sur localhost : le client s'y connecte
réellement. Cela valide de bout en bout le handshake authentifié, la sérialisation du
hello, et la boucle de reconnexion, sans dépendre du serveur Tracee.

Depuis #19, ``run()`` est une boucle infinie (elle reconnecte). Pour la tester, on la
lance comme **tâche** et on attend un effet observable (hello reçu, N connexions) avant
d'**annuler** la tâche : on ne peut plus attendre que ``run()`` se termine — sauf sur un
refus fatal (token/version), qui lui arrête l'agent (``run()`` rend la main).
"""

import asyncio
import json

import pytest
from websockets.asyncio.server import serve

from tracee_agent.config.schema import ServerConfig
from tracee_agent.transport.client import AgentConnection, ConnectionRejected


def _port(server) -> int:
    """Port réellement attribué au serveur mock (démarré sur le port 0)."""
    return server.sockets[0].getsockname()[1]


def _config(server) -> ServerConfig:
    return ServerConfig(url=f"ws://localhost:{_port(server)}/ws/agent", token="tok-test")


async def _cancel(task: asyncio.Task) -> None:
    """Annule la tâche ``run()`` et absorbe le ``CancelledError`` résultant."""
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def test_hello_envoye_avec_headers_authentifies():
    """Le client transmet les en-têtes d'auth au handshake et envoie un hello valide."""
    recu: dict[str, object] = {}
    hello_recu = asyncio.Event()

    async def handler(connection):
        recu["headers"] = connection.request.headers
        recu["message"] = await connection.recv()
        hello_recu.set()

    server = await serve(handler, "localhost", 0)
    task = asyncio.create_task(AgentConnection(_config(server)).run())
    try:
        await asyncio.wait_for(hello_recu.wait(), timeout=5)
    finally:
        await _cancel(task)
        server.close()
        await server.wait_closed()

    headers = recu["headers"]
    assert headers["Authorization"] == "Bearer tok-test"
    assert headers["X-Protocol-Version"] == "1.2"

    message = json.loads(recu["message"])
    assert message["type"] == "hello"
    assert message["payload"]["hostname"]
    assert isinstance(message["payload"]["interfaces"], list)


async def test_reconnexion_apres_coupure(monkeypatch):
    """À la coupure, le client revient : le serveur voit plusieurs connexions successives."""
    # Backoff quasi nul : on ne veut pas attendre 1 s réelle entre deux tentatives.
    monkeypatch.setattr("tracee_agent.transport.client._RECONNECT_BACKOFF_INITIAL_SECONDS", 0.01)

    connexions = 0
    deux_connexions = asyncio.Event()

    async def handler(connection):
        nonlocal connexions
        connexions += 1
        if connexions >= 2:
            deux_connexions.set()
        await connection.recv()  # hello ; le handler retourne → serveur ferme → reconnexion

    server = await serve(handler, "localhost", 0)
    task = asyncio.create_task(AgentConnection(_config(server)).run())
    try:
        await asyncio.wait_for(deux_connexions.wait(), timeout=5)
    finally:
        await _cancel(task)
        server.close()
        await server.wait_closed()

    assert connexions >= 2


async def test_buffer_jette_les_plus_anciens(monkeypatch):
    """À saturation, le tampon garde le trafic récent : ce sont les plus vieux qui tombent."""
    monkeypatch.setattr("tracee_agent.transport.client._OUTBOX_MAXSIZE", 3)
    connection = AgentConnection(ServerConfig(url="ws://localhost/ws/agent", token="t"))

    for numero in range(5):
        connection.enqueue_event({"numero": numero})

    # File de capacité 3 : les events 0 et 1 (les plus anciens) ont été écartés.
    restants = [connection._outbox.get_nowait()["numero"] for _ in range(3)]
    assert restants == [2, 3, 4]


async def test_arret_sur_refus_fatal():
    """Un refus non récupérable (token rejeté, 4401) arrête l'agent en disant pourquoi.

    Le motif doit **remonter** et non rester dans les logs : sans lui, l'écran de
    paramètres ne saurait distinguer un token périmé d'un arrêt demandé, et le cas le
    plus courant en démonstration passerait inaperçu.
    """

    async def handler(connection):
        # Le serveur accepte la WS puis la ferme avec un code applicatif fatal, comme le
        # vrai serveur Tracee sur un token invalide.
        await connection.close(code=4401, reason="token rejeté")

    server = await serve(handler, "localhost", 0)
    try:
        # run() DOIT se terminer de lui-même : sinon ce wait_for lèverait TimeoutError.
        with pytest.raises(ConnectionRejected, match="Token d'agent refusé"):
            await asyncio.wait_for(AgentConnection(_config(server)).run(), timeout=5)
    finally:
        server.close()
        await server.wait_closed()


async def test_heartbeat_emis_periodiquement(monkeypatch):
    """L'agent émet un heartbeat après le hello, portant les compteurs de présence."""
    monkeypatch.setattr("tracee_agent.transport.client._HEARTBEAT_INTERVAL_SECONDS", 0.01)

    recu: dict[str, object] = {}
    types_recus: list[str] = []
    heartbeat_recu = asyncio.Event()

    async def handler(connection):
        async for raw in connection:
            message = json.loads(raw)
            types_recus.append(message["type"])
            if message["type"] == "heartbeat":
                recu["payload"] = message["payload"]
                heartbeat_recu.set()

    server = await serve(handler, "localhost", 0)
    task = asyncio.create_task(AgentConnection(_config(server)).run())
    try:
        await asyncio.wait_for(heartbeat_recu.wait(), timeout=5)
    finally:
        await _cancel(task)
        server.close()
        await server.wait_closed()

    assert types_recus[0] == "hello"  # le hello précède toujours le 1er heartbeat
    payload = recu["payload"]
    assert "events_sent" in payload
    assert "uptime_seconds" in payload
