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

# Numéro de protocole IP (registre IANA) → nom lisible, pour les flux IP dépourvus
# de couche transport TCP/UDP. Table explicite plutôt que /etc/protocols : le nom
# devient une donnée de contrat (colonne `protocol`, filtres front), il doit être
# stable et identique sur tous les OS. Tout numéro absent retombe sur "ip-proto-<n>"
# (cf. _ip_protocol) : jamais de perte silencieuse d'un flux.
_IP_PROTOCOL_NAMES: dict[int, str] = {
    1: "icmp",  # RFC 792
    58: "icmpv6",  # RFC 4443
    50: "esp",  # IPsec, RFC 4303 — cœur d'un tunnel VPN
    47: "gre",  # RFC 2784
    132: "sctp",  # RFC 9260
}


def parse_packet(data: bytes) -> ParsedPacket | None:
    """Décode une trame Ethernet jusqu'à la couche transport.

    Args:
        data: Octets bruts d'une trame Ethernet, éventuellement écrêtée par snaplen.

    Returns:
        Le paquet décodé, ou ``None`` uniquement si la trame n'est **pas IP**
        (ARP…) ou si elle est trop aberrante pour que Scapy la dissèque. Tout
        paquet IP produit un ``ParsedPacket``, même sans couche transport TCP/UDP.
    """
    try:
        packet = Ether(data)
    except Exception:  # noqa: BLE001 — Scapy peut lever sur des octets aberrants
        logger.warning("trame_indechiffrable", taille=len(data))
        return None

    ip = _ip_layer(packet)
    if ip is None:
        return None  # non-IP (ARP, etc.) : hors périmètre, ignoré silencieusement

    packet_size = _packet_size(ip)

    transport, protocol = _transport_layer(packet)
    if transport is None:
        # Flux IP sans couche transport TCP/UDP : ICMP/ESP/GRE/SCTP, protocole
        # inconnu, ou fragment non initial / snaplen trop court qui masque l'en-tête
        # transport. Les IP src/dst suffisent à tracer l'arc ; ni ports ni charge
        # L7 délimitable (aucune identification de service ne s'y applique).
        return ParsedPacket(
            source_ip=ip.src,
            source_port=None,
            dest_ip=ip.dst,
            dest_port=None,
            protocol=_ip_protocol(ip),
            packet_size=packet_size,
            payload_size=0,
            payload=b"",
        )

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


def _ip_protocol(ip: Packet) -> str:
    """Nom du protocole transporté, lu dans l'en-tête IP (flux non-TCP/UDP).

    Le numéro se lit dans le champ « Protocol » en IPv4 (``proto``, RFC 791) ou
    « Next Header » en IPv6 (``nh``, RFC 8200) ; les deux partagent le registre
    IANA des numéros de protocole. On le traduit via ``_IP_PROTOCOL_NAMES``, avec
    un repli ``"ip-proto-<n>"`` pour tout numéro non répertorié.

    Limite connue : en IPv6, ``nh`` peut désigner un en-tête d'extension
    (Fragment, Routing…) plutôt que le protocole final, situé au bout de la chaîne.
    Hors périmètre ici (cas rare) : on renvoie alors le numéro de l'extension.
    """
    number = ip.nh if isinstance(ip, IPv6) else ip.proto
    return _IP_PROTOCOL_NAMES.get(number, f"ip-proto-{number}")


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
