"""Décodage des couches basses d'un paquet : Ethernet → IP → TCP/UDP.

On re-parse ici les **octets bruts** sortis de la file de capture. La capture a
sérialisé le paquet en ``bytes`` (découplage thread Scapy ↔ boucle asyncio) ; on
les redonne à Scapy, seul dissecteur qu'on s'autorise pour L2–L4 (les couches
applicatives, elles, seront parsées à la main). Le décodage est une **fonction
pure** ``bytes → ParsedPacket | None`` : aucune I/O, donc testable directement
sur des fixtures.

Les tailles sont lues dans les en-têtes IP/transport (``Total Length`` IPv4,
``Payload Length`` IPv6, ``data offset`` TCP) et non via ``len(data)`` : ces
champs décrivent le paquet **réel sur le fil**, alors que ``len(data)`` est
faussé dès que ``snaplen`` écrête la trame.
"""

from __future__ import annotations

from typing import Literal

import structlog
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from tracee_agent.parser.models import ParsedPacket

logger = structlog.get_logger("tracee_agent.parser")

_IPV6_HEADER_LEN = 40  # en-tête IPv6 de base, fixe (RFC 8200 §3)
_UDP_HEADER_LEN = 8  # en-tête UDP, fixe (RFC 768)


def parse_packet(data: bytes) -> ParsedPacket | None:
    """Décode une trame Ethernet jusqu'à la couche transport.

    Args:
        data: Octets bruts d'une trame Ethernet, éventuellement écrêtée par snaplen.

    Returns:
        Le paquet décodé, ou ``None`` si la trame n'est pas IP + TCP/UDP, ou si
        elle est trop tronquée/malformée pour en tirer un 5-tuple exploitable.
    """
    try:
        packet = Ether(data)
    except Exception:  # noqa: BLE001 — Scapy peut lever sur des octets aberrants
        logger.warning("trame_indechiffrable", taille=len(data))
        return None

    ip = _ip_layer(packet)
    if ip is None:
        return None  # non-IP (ARP, etc.) : hors périmètre, ignoré silencieusement

    transport, protocol = _transport_layer(packet)
    if transport is None:
        return None  # ni TCP ni UDP (ICMP…), ou en-tête transport tronqué

    packet_size = _packet_size(ip)
    payload_size = max(0, packet_size - _ip_header_len(ip) - _l4_header_len(transport))
    # On écrête à payload_size pour retirer un éventuel bourrage Ethernet : une
    # trame < 64 octets est complétée par des zéros que Scapy expose en Padding.
    payload = bytes(transport.payload)[:payload_size]

    return ParsedPacket(
        source_ip=ip.src,
        source_port=transport.sport,
        dest_ip=ip.dst,
        dest_port=transport.dport,
        protocol=protocol,
        packet_size=packet_size,
        payload_size=payload_size,
        payload=payload,
    )


def _ip_layer(packet: Packet) -> Packet | None:
    """Retourne la couche IPv4 ou IPv6 du paquet, ou ``None`` si non-IP."""
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def _transport_layer(
    packet: Packet,
) -> tuple[Packet, Literal["tcp", "udp"]] | tuple[None, None]:
    """Retourne la couche transport et son nom, ou ``(None, None)`` si ni TCP ni UDP."""
    if TCP in packet:
        return packet[TCP], "tcp"
    if UDP in packet:
        return packet[UDP], "udp"
    return None, None


def _packet_size(ip: Packet) -> int:
    """Taille réelle du datagramme IP sur le fil, en octets (snaplen ignoré)."""
    if isinstance(ip, IPv6):
        # plen ne compte que ce qui suit l'en-tête fixe : on le rajoute.
        return _IPV6_HEADER_LEN + ip.plen
    return ip.len  # IPv4 Total Length = en-tête + données (RFC 791)


def _ip_header_len(ip: Packet) -> int:
    """Longueur de l'en-tête IP, en octets."""
    if isinstance(ip, IPv6):
        return _IPV6_HEADER_LEN
    return ip.ihl * 4  # IHL = longueur d'en-tête en mots de 32 bits (options incluses)


def _l4_header_len(transport: Packet) -> int:
    """Longueur de l'en-tête transport, en octets."""
    if isinstance(transport, TCP):
        return transport.dataofs * 4  # data offset en mots de 32 bits (options incluses)
    return _UDP_HEADER_LEN
