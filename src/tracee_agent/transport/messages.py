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
from tracee_agent.flow import FlowRecord
from tracee_agent.identifier.service_identifier import ServiceHint

# Version du protocole annoncée au serveur via le header X-Protocol-Version.
# Doit rester alignée avec PROTOCOL.md (repo serveur) : toute évolution s'y décide.
# 1.2 = message `event` en biflow (compteurs directionnels, cf. PROTOCOL.md).
PROTOCOL_VERSION = "1.2"

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


def build_event(
    interface: str, flow: FlowRecord, service_hint: ServiceHint | None
) -> dict[str, object]:
    """Construit un message ``event`` à partir d'un flux agrégé (voir PROTOCOL.md § event).

    Les compteurs du ``flow`` sont ceux de la fenêtre écoulée (un delta biflow). Le
    ``service_hint`` (résolu par l'appelant via l'identifier, ``None`` si inconnu) se
    sérialise en ``{"type": source, "value": value}``.

    Args:
        interface: Interface d'où provient le flux (annoncée telle quelle au serveur).
        flow: Compteurs directionnels du flux, orienté client → serveur.
        service_hint: Service identifié localement (SNI/DNS), ou ``None``.
    """
    hint: dict[str, str] | None = None
    if service_hint is not None:
        hint = {"type": service_hint.source, "value": service_hint.value}

    payload: dict[str, object] = {
        "interface": interface,
        "source_ip": flow.source_ip,
        "source_port": flow.source_port,
        "dest_ip": flow.dest_ip,
        "dest_port": flow.dest_port,
        "protocol": flow.protocol,
        "bytes_sent": flow.bytes_sent,
        "bytes_received": flow.bytes_received,
        "packets_sent": flow.packets_sent,
        "packets_received": flow.packets_received,
        "service_hint": hint,
        "metadata": {},
    }
    return envelope("event", payload)


def build_heartbeat(events_sent: int, uptime_seconds: int) -> dict[str, object]:
    """Construit un message ``heartbeat`` (voir PROTOCOL.md § heartbeat).

    Signale que l'agent est vivant même sans trafic. Les deux compteurs sont cumulés
    **depuis le démarrage de l'agent** (portée alignée sur ``uptime`` pour rester
    cohérents) : ``events_sent`` = total d'events émis, ``uptime_seconds`` = âge du process.
    """
    payload: dict[str, object] = {
        "events_sent": events_sent,
        "uptime_seconds": uptime_seconds,
    }
    return envelope("heartbeat", payload)
