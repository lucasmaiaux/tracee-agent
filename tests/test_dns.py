"""Tests du parsing DNS (``parser.dns``).

Les messages sont forgés avec Scapy — cohérent avec le parseur, qui lui délègue
le décodage. Le cas de **compression** est, lui, construit octet par octet : on
veut prouver qu'un nom écrit sous forme de pointeur (RFC 1035 §4.1.4) est bien
résolu de bout en bout, indépendamment de la façon dont Scapy sérialise.
"""

from scapy.layers.dns import DNS, DNSQR, DNSRR

from tracee_agent.parser.dns import DnsRecord, parse_dns


def _query(qname: str) -> bytes:
    """Octets d'une requête DNS simple (une question, aucune réponse)."""
    return bytes(DNS(rd=1, qd=DNSQR(qname=qname)))


def _response(qname: str, answers: list[tuple[str, str, str]]) -> bytes:
    """Octets d'une réponse DNS ; ``answers`` = liste de (rrname, type, rdata)."""
    records = [DNSRR(rrname=name, type=rtype, rdata=rdata) for name, rtype, rdata in answers]
    return bytes(DNS(qr=1, qd=DNSQR(qname=qname), an=records))


# Réponse pour www.example.com → 93.184.216.34, avec le nom de l'Answer encodé
# en POINTEUR (0xC00C) vers le QNAME de la question (offset 12). Cf.
# scripts_temp/explore_dns.py pour le décodage annoté.
_COMPRESSED_RESPONSE = bytes.fromhex(
    (
        "1234 8180 0001 0001 0000 0000"  # en-tête : 1 question, 1 réponse
        "03 777777 07 6578616d706c65 03 636f6d 00"  # QNAME www.example.com @offset 12
        "0001 0001"  # QTYPE=A, QCLASS=IN
        "c00c"  # Answer NAME = pointeur → offset 12
        "0001 0001 00000258 0004 5db8d822"  # A IN, TTL=600, RDLENGTH=4, 93.184.216.34
    ).replace(" ", "")
)


def test_requete_extrait_le_nom_interroge():
    message = parse_dns(_query("www.netflix.com"))
    assert message is not None
    assert message.questions == ["www.netflix.com"]


def test_requete_na_pas_de_reponse():
    message = parse_dns(_query("www.netflix.com"))
    assert message is not None
    assert message.answers == []


def test_reponse_a_extrait_domaine_et_ip():
    message = parse_dns(_response("example.com", [("example.com", "A", "93.184.216.34")]))
    assert message is not None
    assert message.answers == [DnsRecord(name="example.com", ip="93.184.216.34")]


def test_reponse_ipv4_et_ipv6():
    raw = _response(
        "example.com",
        [
            ("example.com", "A", "93.184.216.34"),
            ("example.com", "AAAA", "2606:2800:220:1:248:1893:25c8:1946"),
        ],
    )
    message = parse_dns(raw)
    assert message is not None
    assert message.answers == [
        DnsRecord(name="example.com", ip="93.184.216.34"),
        DnsRecord(name="example.com", ip="2606:2800:220:1:248:1893:25c8:1946"),
    ]


def test_types_sans_adresse_sont_ignores():
    # Un CNAME n'a pas d'IP : on ne garde que les enregistrements A/AAAA.
    raw = _response(
        "example.com",
        [("example.com", "CNAME", "cdn.example.net"), ("cdn.example.net", "A", "1.2.3.4")],
    )
    message = parse_dns(raw)
    assert message is not None
    assert message.answers == [DnsRecord(name="cdn.example.net", ip="1.2.3.4")]


def test_point_final_de_racine_est_retire():
    message = parse_dns(_query("www.example.com"))
    assert message is not None
    assert message.questions == ["www.example.com"]  # pas "www.example.com."


def test_compression_de_nom_est_resolue():
    message = parse_dns(_COMPRESSED_RESPONSE)
    assert message is not None
    assert message.questions == ["www.example.com"]
    # Le nom de la réponse n'existe qu'en pointeur : il doit être reconstitué.
    assert message.answers == [DnsRecord(name="www.example.com", ip="93.184.216.34")]


def test_message_tronque_retourne_none():
    tronque = _query("www.example.com")[:16]  # coupé en plein milieu du nom
    assert parse_dns(tronque) is None


def test_donnees_non_dns_retournent_none():
    assert parse_dns(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert parse_dns(b"\x16\x03\x01") is None  # trop court pour un en-tête DNS
    assert parse_dns(b"") is None
