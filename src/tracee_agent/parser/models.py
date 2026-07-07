"""Structures typées produites par le décodage réseau.

Ces objets sont *internes* à l'agent : ils portent le résultat du décodage d'un
paquet (couches Ethernet → IP → transport). Contrairement à la config, ils ne
viennent pas d'une source externe non sûre — c'est Scapy qui les alimente, avec
des valeurs déjà décodées et typées. D'où une ``dataclass`` (simple conteneur)
plutôt que Pydantic (validation à la frontière).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    """Un paquet IP décodé, avec sa couche transport quand elle existe.

    Représente **un** paquet observé, pas un flux agrégé : les compteurs cumulés
    (``bytes``/``packets`` du message ``event``) et l'identification de service
    seront construits par les couches suivantes à partir de cette brique.

    Tout paquet **IP** produit un ``ParsedPacket`` : une IP src/dst suffit à
    tracer un flux distant (un arc sur le globe). Les protocoles porteurs de
    ports (TCP/UDP) les renseignent ; les autres (ICMP, ESP/VPN, GRE, SCTP, ou un
    n° de protocole IP inconnu) laissent ``source_port``/``dest_port`` à ``None``.
    Seul le trafic **non-IP** (ARP, STP…), sans IP routable, est écarté en amont.

    Les tailles décrivent le paquet **réel sur le fil** : elles sont lues dans
    l'en-tête IP (``Total Length``), toujours présent même quand la capture est
    écrêtée par ``snaplen``. ``payload`` ne contient, lui, que les octets
    réellement capturés — donc ``len(payload) <= payload_size`` en cas de
    troncature.

    Attributes:
        source_ip: Adresse IP source (IPv4 ou IPv6, forme texte).
        source_port: Port source (couche transport), ou ``None`` hors TCP/UDP.
        dest_ip: Adresse IP destination (IPv4 ou IPv6, forme texte).
        dest_port: Port destination (couche transport), ou ``None`` hors TCP/UDP.
        protocol: Nom du protocole transporté : ``"tcp"``/``"udp"``, un nom connu
            (``"icmp"``, ``"esp"``, ``"gre"``…) ou un fallback ``"ip-proto-<n>"``
            quand le numéro de protocole IP n'est pas répertorié.
        packet_size: Taille réelle du datagramme IP sur le fil, en octets
            (en-têtes IP + transport + charge utile).
        payload_size: Taille réelle de la charge applicative (L7) sur le fil,
            en octets, indépendamment de la troncature. ``0`` hors TCP/UDP : on
            ne délimite pas de charge L7 pour ces flux (pas d'identification).
        payload: Octets de la charge applicative réellement capturés. Point
            d'entrée du parsing manuel (TLS/SNI, DNS). Vide (``b""``) hors TCP/UDP.
    """

    source_ip: str
    source_port: int | None
    dest_ip: str
    dest_port: int | None
    protocol: str
    packet_size: int
    payload_size: int
    payload: bytes
