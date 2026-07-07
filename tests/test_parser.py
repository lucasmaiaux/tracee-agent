"""Tests du décodage Ethernet → IP → TCP/UDP.

Les paquets sont forgés puis sérialisés avec Scapy (``bytes(pkt)``), ce qui
déclenche le calcul des champs de longueur et du bourrage Ethernet — la trame
obtenue est donc identique à ce que la capture remet dans la file. On donne ces
octets à ``parse_packet`` comme le ferait le pipeline réel.
"""

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from tracee_agent.parser import parse_packet

# Longueurs d'en-tête (octets) rappelées ici pour des assertions lisibles.
# packet_size décrit le datagramme IP : l'en-tête Ethernet n'y entre pas.
_IPV4_HEADER = 20
_IPV6_HEADER = 40
_TCP_HEADER = 20
_UDP_HEADER = 8


def test_tcp_ipv4_decode_5tuple_et_tailles():
    payload = b"GET / HTTP/1.1\r\n"
    frame = bytes(
        Ether()
        / IP(src="192.168.1.10", dst="142.250.74.110")
        / TCP(sport=54321, dport=443)
        / payload
    )

    result = parse_packet(frame)

    assert result is not None
    assert result.source_ip == "192.168.1.10"
    assert result.dest_ip == "142.250.74.110"
    assert result.source_port == 54321
    assert result.dest_port == 443
    assert result.protocol == "tcp"
    assert result.packet_size == _IPV4_HEADER + _TCP_HEADER + len(payload)
    assert result.payload_size == len(payload)
    assert result.payload == payload


def test_udp_ipv6_decode_5tuple_et_tailles():
    payload = b"\x12\x34dns-query"
    frame = bytes(
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5353, dport=53) / payload
    )

    result = parse_packet(frame)

    assert result is not None
    assert result.source_ip == "2001:db8::1"
    assert result.dest_ip == "2001:db8::2"
    assert result.source_port == 5353
    assert result.dest_port == 53
    assert result.protocol == "udp"
    # IPv6 : plen ne compte que la charge → packet_size = en-tête fixe + reste.
    assert result.packet_size == _IPV6_HEADER + _UDP_HEADER + len(payload)
    assert result.payload_size == len(payload)
    assert result.payload == payload


def test_paquet_non_ip_est_ignore():
    frame = bytes(Ether() / ARP())

    assert parse_packet(frame) is None


def test_paquet_tronque_garde_les_tailles_reelles_sans_crash():
    # Gros paquet, puis on coupe à 100 octets comme le ferait un petit snaplen.
    full = bytes(Ether() / IP() / TCP() / (b"x" * 1000))
    truncated = full[:100]

    result = parse_packet(truncated)

    assert result is not None
    # Les tailles se lisent dans l'en-tête IP, intact malgré la troncature.
    assert result.packet_size == _IPV4_HEADER + _TCP_HEADER + 1000
    assert result.payload_size == 1000
    # ...mais on n'a capturé qu'une fraction du payload : len < payload_size.
    assert len(result.payload) < result.payload_size


def test_ack_nu_ecrete_le_bourrage_ethernet():
    # Segment sans données : la trame (54 o) est sous le minimum Ethernet (60 o),
    # donc complétée par du bourrage que Scapy expose en Padding. Il ne doit pas
    # se retrouver dans le payload applicatif.
    frame = bytes(Ether() / IP() / TCP(flags="A"))

    result = parse_packet(frame)

    assert result is not None
    assert result.payload_size == 0
    assert result.payload == b""


def test_octets_aberrants_ne_crashent_pas():
    assert parse_packet(b"\x00\x01\x02\x03") is None


# --- Flux IP sans couche transport TCP/UDP (US #27) ------------------------------
# Ces protocoles portent des IP src/dst mais pas de ports : ils doivent produire un
# flux visible (arc sur le globe) plutôt que d'être jetés. On vérifie ports=None,
# protocole résolu, et payload L7 non délimité (vide).


def test_icmp_ipv4_devient_un_flux_sans_ports():
    # ICMP (ex. un ping) : couche Scapy dédiée, qui pose proto=1 dans l'en-tête IP.
    frame = bytes(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / ICMP())

    result = parse_packet(frame)

    assert result is not None
    assert result.source_ip == "192.168.1.10"
    assert result.dest_ip == "8.8.8.8"
    assert result.source_port is None
    assert result.dest_port is None
    assert result.protocol == "icmp"
    assert result.packet_size == _IPV4_HEADER + 8  # 8 = en-tête ICMP echo
    assert result.payload_size == 0
    assert result.payload == b""


def test_icmpv6_devient_un_flux_sans_ports():
    # ICMPv6 : le numéro se lit dans le champ Next Header (nh=58) de l'en-tête IPv6.
    frame = bytes(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest())

    result = parse_packet(frame)

    assert result is not None
    assert result.source_ip == "2001:db8::1"
    assert result.dest_ip == "2001:db8::2"
    assert result.source_port is None
    assert result.dest_port is None
    assert result.protocol == "icmpv6"
    assert result.payload_size == 0
    assert result.payload == b""


@pytest.mark.parametrize(
    ("ip_proto", "expected_protocol"),
    [
        (50, "esp"),  # IPsec — cœur d'un tunnel VPN
        (47, "gre"),
        (132, "sctp"),
        (99, "ip-proto-99"),  # non répertorié → fallback numérique, jamais jeté
    ],
)
def test_flux_ip_par_numero_de_protocole(ip_proto: int, expected_protocol: str):
    # On fixe le numéro de protocole à la main : le décodeur ne lit que ce champ,
    # sans dépendre d'une couche Scapy dédiée. Vaut pour les protos connus (table)
    # comme pour un numéro inconnu (fallback).
    body = b"\x00" * 16
    frame = bytes(Ether() / IP(src="10.0.0.1", dst="203.0.113.5", proto=ip_proto) / Raw(body))

    result = parse_packet(frame)

    assert result is not None
    assert result.source_ip == "10.0.0.1"
    assert result.dest_ip == "203.0.113.5"
    assert result.source_port is None
    assert result.dest_port is None
    assert result.protocol == expected_protocol
    assert result.packet_size == _IPV4_HEADER + len(body)
    assert result.payload_size == 0
    assert result.payload == b""
