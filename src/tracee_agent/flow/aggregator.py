"""Regroupe les paquets en « conversations » (flux) et compte ce qui part / revient.

Entre le décodage (un ``ParsedPacket`` = un paquet) et l'envoi au serveur (un ``event``
= une conversation), cette couche fait deux choses :

1. **Ranger** chaque paquet dans la bonne conversation (ta machine ↔ un serveur), peu
   importe le sens du paquet ;
2. **Compter** séparément les octets/paquets **émis** (toi → serveur) et **reçus**
   (serveur → toi). C'est le modèle « biflow » de NetFlow / IPFIX (RFC 5103).

Elle n'envoie rien elle-même : elle accumule, et à chaque ``flush()`` (toutes les ~2 s,
c'est l'appelant qui décide) elle rend les conversations accumulées puis repart de zéro.

**Comment on devine qui est le client et qui est le serveur ?** Par les numéros de port.
Quand tu te connectes à un serveur, celui-ci a un port *petit et connu* (443 pour HTTPS,
53 pour le DNS…), et ta machine s'attribue un port *au hasard dans les grands nombres*.
Donc : **le côté au port le plus grand = le client** (= la source). C'est un simple calcul
sur le 5-tuple, sans rien mémoriser — l'aller et le retour d'une même conversation tombent
donc au même endroit, dans le bon sens.

Cette règle marche **sur tous les OS** (Linux, Windows, macOS, Android, iOS, Raspberry Pi) :
la plage exacte des ports « au hasard » change d'un système à l'autre, mais ils sont
toujours *élevés*, alors que les serveurs écoutent sur des ports *bas*. On ne code donc
aucune plage en dur. Seul angle mort : le **pair-à-pair** (BitTorrent, visio WebRTC, jeux),
où les deux côtés ont un port élevé — là on départage par IP (stable, mais le sens
émis/reçu peut être inversé). Cas minoritaire pour un poste client, assumé pour la v1.

Comme le reste du pipeline, ce module tourne dans l'unique thread de la boucle asyncio :
aucun verrou nécessaire.
"""

from __future__ import annotations

from dataclasses import dataclass

from tracee_agent.parser.models import ParsedPacket

# Un bout de conversation : (adresse IP, port). Port None hors TCP/UDP (ICMP, ESP…).
Endpoint = tuple[str, int | None]
# Clé d'une conversation orientée client → serveur : identifie le flux, sens compris.
FlowKey = tuple[str, int | None, str, int | None, str]


@dataclass(slots=True)
class FlowRecord:
    """Compteurs d'une conversation, orientée client → serveur.

    ``sent`` = ce que le client envoie (toi → serveur), ``received`` = ce qu'il reçoit.
    Ce sont les compteurs de la **fenêtre courante uniquement** : ils repartent de zéro
    à chaque flush, donc un record ne contient que le trafic des ~2 dernières secondes.
    """

    source_ip: str
    source_port: int | None
    dest_ip: str
    dest_port: int | None
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0


def _client_endpoint(a: Endpoint, b: Endpoint) -> Endpoint:
    """Renvoie celui des deux bouts qui est le « client » : le port le plus grand.

    Le port d'un endpoint sert de critère (le plus grand gagne = le client). Un port
    absent (None, hors TCP/UDP) compte comme -1 : entre deux flux sans port on tranche
    alors par l'adresse IP, juste pour avoir un résultat stable (le sens réel importe peu
    pour ces flux, ils n'ont pas d'identification de service).
    """

    def rank(endpoint: Endpoint) -> tuple[int, str]:
        # Port absent (hors TCP/UDP) → -1 : on départage alors par l'IP.
        return (endpoint[1] if endpoint[1] is not None else -1, endpoint[0])

    return max(a, b, key=rank)


class FlowAggregator:
    """Range les paquets en conversations et rend l'état accumulé à chaque flush."""

    def __init__(self) -> None:
        self._flows: dict[FlowKey, FlowRecord] = {}

    def add(self, packet: ParsedPacket) -> None:
        """Ajoute un paquet à sa conversation, du bon côté (émis ou reçu)."""
        src: Endpoint = (packet.source_ip, packet.source_port)
        dst: Endpoint = (packet.dest_ip, packet.dest_port)

        # Qui est le client (la source de la conversation) ? Le port le plus grand.
        client = _client_endpoint(src, dst)
        server = dst if client == src else src

        key: FlowKey = (client[0], client[1], server[0], server[1], packet.protocol)
        record = self._flows.get(key)
        if record is None:
            record = FlowRecord(client[0], client[1], server[0], server[1], packet.protocol)
            self._flows[key] = record

        # Si ce paquet a été émis par le client, c'est de l'« envoyé » ; sinon du « reçu ».
        if client == src:
            record.bytes_sent += packet.packet_size
            record.packets_sent += 1
        else:
            record.bytes_received += packet.packet_size
            record.packets_received += 1

    def flush(self) -> list[FlowRecord]:
        """Rend les conversations accumulées depuis le dernier flush, puis se vide.

        Chaque record porte le trafic de la fenêtre écoulée (un « delta »). Une
        conversation sans trafic à la fenêtre suivante n'y réapparaît simplement pas.
        """
        records = list(self._flows.values())
        self._flows.clear()
        return records
