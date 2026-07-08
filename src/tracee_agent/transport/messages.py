"""Construction des messages du protocole agent → serveur.

Ce module ne fait **aucune** I/O réseau : il se contente de produire les
dictionnaires conformes à ``../tracee/docs/PROTOCOL.md``. Cette séparation les
rend testables sans serveur et réutilisables (``event``/``heartbeat`` à venir).
"""

import platform
import socket
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version

from tracee_agent.capture.interfaces import list_interfaces

# Version du protocole annoncée au serveur via le header X-Protocol-Version.
# Doit rester alignée avec PROTOCOL.md (repo serveur) : toute évolution s'y décide.
PROTOCOL_VERSION = "1.0"

# Format de timestamp du protocole : ISO 8601 UTC, à la seconde, suffixe « Z »
# (ex. « 2026-06-09T14:30:00Z »). strftime explicite car datetime.isoformat()
# écrirait « +00:00 » au lieu de « Z ».
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_timestamp() -> str:
    """Horodatage courant en UTC, au format attendu par le protocole."""
    return datetime.now(UTC).strftime(_TIMESTAMP_FORMAT)


def _agent_version() -> str:
    """Version de l'agent, lue depuis les métadonnées du paquet installé.

    Source unique = ``pyproject.toml`` (pas de numéro dupliqué dans le code). Si
    le paquet n'est pas installé (exécution depuis les sources brutes), on ne
    bloque pas l'agent pour un simple numéro de version.
    """
    try:
        return version("tracee-agent")
    except PackageNotFoundError:
        return "0.0.0"


def envelope(message_type: str, payload: dict[str, object]) -> dict[str, object]:
    """Enveloppe commune à tous les messages : ``{type, timestamp, payload}``.

    Factorisée ici car ``event`` et ``heartbeat`` (US #18/#19) réutiliseront
    exactement cette forme.
    """
    return {
        "type": message_type,
        "timestamp": _utc_timestamp(),
        "payload": payload,
    }


def build_hello() -> dict[str, object]:
    """Construit le message ``hello`` qui annonce l'agent au serveur.

    Rassemble l'identité de la machine (version, OS, hostname) et la liste des
    interfaces réseau visibles. Voir la section « hello » de PROTOCOL.md.
    """
    payload: dict[str, object] = {
        "agent_version": _agent_version(),
        "os": platform.system().lower(),
        "hostname": socket.gethostname(),
        "interfaces": [{"name": iface.name} for iface in list_interfaces()],
    }
    return envelope("hello", payload)
