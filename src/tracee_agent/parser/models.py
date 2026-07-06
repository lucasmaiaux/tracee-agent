"""Structures typées produites par le décodage réseau.

Ces objets sont *internes* à l'agent : ils portent le résultat du décodage d'un
paquet (couches Ethernet → IP → TCP/UDP). Contrairement à la config, ils ne
viennent pas d'une source externe non sûre — c'est Scapy qui les alimente, avec
des valeurs déjà décodées et typées. D'où une ``dataclass`` (simple conteneur)
plutôt que Pydantic (validation à la frontière).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    """Un paquet décodé jusqu'à la couche transport (L4).

    Représente **un** paquet observé, pas un flux agrégé : les compteurs cumulés
    (``bytes``/``packets`` du message ``event``) et l'identification de service
    seront construits par les couches suivantes à partir de cette brique.

    Les tailles décrivent le paquet **réel sur le fil** : elles sont lues dans
    l'en-tête IP (``Total Length``), toujours présent même quand la capture est
    écrêtée par ``snaplen``. ``payload`` ne contient, lui, que les octets
    réellement capturés — donc ``len(payload) <= payload_size`` en cas de
    troncature.

    Attributes:
        source_ip: Adresse IP source (IPv4 ou IPv6, forme texte).
        source_port: Port source (couche transport).
        dest_ip: Adresse IP destination (IPv4 ou IPv6, forme texte).
        dest_port: Port destination (couche transport).
        protocol: Protocole de transport, ``"tcp"`` ou ``"udp"``.
        packet_size: Taille réelle du datagramme IP sur le fil, en octets
            (en-têtes IP + transport + charge utile).
        payload_size: Taille réelle de la charge applicative (L7) sur le fil,
            en octets, indépendamment de la troncature.
        payload: Octets de la charge applicative réellement capturés. Point
            d'entrée du parsing manuel à venir (TLS/SNI, DNS).
    """

    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: Literal["tcp", "udp"]
    packet_size: int
    payload_size: int
    payload: bytes
