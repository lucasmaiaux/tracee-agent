"""Décodage des messages DNS observés (UDP/53) → correspondances domaine ↔ IP.

Contrairement au SNI TLS (parsé à la main faute d'un support Scapy exploitable),
on **délègue le décodage à Scapy** (`scapy.layers.dns`) : il lit l'en-tête, les
questions et les réponses, et surtout **résout la compression de noms**
(RFC 1035 §4.1.4) — ces pointeurs qui font qu'un domaine n'est écrit qu'une fois
dans le message. Voir ``scripts_temp/explore_dns.py`` pour la mécanique sous le capot.

But applicatif : en écoutant les résolutions DNS qui passent en clair, on apprend
des couples ``IP → domaine`` (« cache DNS observé ») qui serviront à étiqueter les
connexions dont on ne voit pas le SNI. Ici on ne fait que **lire** un message ;
l'alimentation du cache viendra plus haut dans le pipeline.

Le décodage est une **fonction pure** ``bytes → DnsMessage | None`` : aucune I/O,
testable directement sur des fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog
from scapy.layers.dns import DNS

logger = structlog.get_logger("tracee_agent.parser")

# En-tête DNS de taille fixe (RFC 1035 §4.1.1) : id, flags et les 4 compteurs,
# 12 octets. En deçà, ce n'est pas un message DNS — et Scapy, faute d'octets,
# invente des champs par défaut (un DNSQR « www.example.com ») : on refuse avant.
_DNS_HEADER_LEN = 12

# Types d'enregistrements DNS qui portent une adresse IP (RFC 1035 §3.2.2,
# RFC 3596 §2.1). Seuls ceux-là alimentent la correspondance domaine → IP.
_TYPE_A = 1  # adresse IPv4
_TYPE_AAAA = 28  # adresse IPv6


@dataclass(frozen=True, slots=True)
class DnsRecord:
    """Un enregistrement d'adresse : un domaine résolu vers une IP.

    Attributes:
        name: Domaine résolu (sans le point final de la racine DNS).
        ip: Adresse renvoyée, IPv4 (A) ou IPv6 (AAAA), en forme texte.
    """

    name: str
    ip: str


@dataclass(frozen=True, slots=True)
class DnsMessage:
    """Résultat du décodage d'un message DNS observé.

    Requête et réponse ont le même format : une requête a simplement ``answers``
    vide. On ne conserve que ce qui sert à l'identification de service.

    Attributes:
        questions: Noms de domaine interrogés (section Question).
        answers: Réponses d'adresse A/AAAA (domaine → IP) ; vide pour une requête.
    """

    questions: list[str]
    answers: list[DnsRecord]


def parse_dns(payload: bytes) -> DnsMessage | None:
    """Décode la charge applicative d'un datagramme UDP/53.

    Args:
        payload: Octets applicatifs d'un datagramme UDP (charge au-dessus d'UDP).

    Returns:
        Le message décodé, ou ``None`` si le payload n'est pas un message DNS
        exploitable (non-DNS, tronqué, malformé). Scapy lève en tentant de
        décoder un ``qdcount``/nom aberrant : on rattrape et on renvoie ``None``.
    """
    if len(payload) < _DNS_HEADER_LEN:
        return None  # trop court pour un en-tête DNS : Scapy inventerait des champs
    try:
        message = DNS(payload)
        questions = [_hostname(question.qname) for question in message.qd or []]
        answers = [
            DnsRecord(name=_hostname(record.rrname), ip=record.rdata)
            for record in message.an or []
            if record.type in (_TYPE_A, _TYPE_AAAA)
        ]
    except Exception:  # noqa: BLE001 — Scapy lève de multiples façons sur du non-DNS
        logger.debug("dns_indechiffrable", taille=len(payload))
        return None

    return DnsMessage(questions=questions, answers=answers)


def _hostname(qname: bytes) -> str:
    """Normalise un nom Scapy (``b'www.example.com.'``) en domaine texte.

    Scapy rend les noms en octets, terminés par le point de la racine DNS ; on
    retire ce point final pour obtenir le domaine usuel.
    """
    return qname.decode().rstrip(".")
