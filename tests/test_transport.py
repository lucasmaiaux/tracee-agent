"""Tests du client WebSocket de l'agent (US #17 : connexion + hello).

On monte un vrai serveur WebSocket éphémère sur localhost : le client s'y connecte
réellement. Cela valide de bout en bout le handshake authentifié et la
sérialisation du hello, sans dépendre du serveur Tracee (pas encore écrit).
"""

import asyncio
import json

from websockets.asyncio.server import serve

from tracee_agent.config.schema import ServerConfig
from tracee_agent.transport.client import AgentConnection


def _port(server) -> int:
    """Port réellement attribué au serveur mock (démarré sur le port 0)."""
    return server.sockets[0].getsockname()[1]


async def test_hello_envoye_avec_headers_authentifies():
    """Le client transmet les en-têtes d'auth au handshake et envoie un hello valide."""
    recu: dict[str, object] = {}

    async def handler(connection):
        recu["headers"] = connection.request.headers
        recu["message"] = await connection.recv()
        # Le handler retourne → le serveur ferme la connexion → le client sort
        # proprement de sa boucle de réception.

    server = await serve(handler, "localhost", 0)
    config = ServerConfig(url=f"ws://localhost:{_port(server)}/ws/agent", token="tok-test")
    try:
        await asyncio.wait_for(AgentConnection(config).run(), timeout=5)
    finally:
        server.close()
        await server.wait_closed()

    headers = recu["headers"]
    assert headers["Authorization"] == "Bearer tok-test"
    assert headers["X-Protocol-Version"] == "1.2"

    message = json.loads(recu["message"])
    assert message["type"] == "hello"
    assert message["payload"]["hostname"]
    assert isinstance(message["payload"]["interfaces"], list)


async def test_handshake_refuse_gere_proprement():
    """Un refus serveur (401) ne fait pas planter le client : run() se termine."""
    handler_atteint = False

    async def handler(connection):
        nonlocal handler_atteint
        handler_atteint = True

    def refuser(connection, request):
        # Rejet AVANT l'upgrade WebSocket → le client lève InvalidStatus en interne,
        # qu'il doit rattraper et journaliser (3e critère de l'US).
        return connection.respond(401, "Unauthorized\n")

    server = await serve(handler, "localhost", 0, process_request=refuser)
    config = ServerConfig(url=f"ws://localhost:{_port(server)}/ws/agent", token="mauvais")
    try:
        # Ne doit PAS lever : si run() propageait l'erreur, ce await échouerait.
        await asyncio.wait_for(AgentConnection(config).run(), timeout=5)
    finally:
        server.close()
        await server.wait_closed()

    assert handler_atteint is False  # connexion rejetée avant l'upgrade
