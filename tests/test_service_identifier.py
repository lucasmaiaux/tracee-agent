"""Tests de l'identification de service (``identifier.service_identifier``)."""

from tracee_agent.identifier.service_identifier import ServiceHint, ServiceIdentifier
from tracee_agent.parser.dns import DnsMessage, DnsRecord

# Flux client → serveur : (ip_src, port_src, ip_dst, port_dst).
_FLOW = ("192.168.1.10", 54321, "1.2.3.4", 443)


def _dns(ip: str, domain: str) -> DnsMessage:
    """Un message DNS de réponse résolvant ``domain`` vers ``ip``."""
    return DnsMessage(questions=[], answers=[DnsRecord(name=domain, ip=ip)])


def test_sni_seul_est_utilise():
    ident = ServiceIdentifier()
    ident.observe_sni(_FLOW, "netflix.com")
    assert ident.resolve(_FLOW) == ServiceHint(source="sni", value="netflix.com")


def test_dns_seul_est_utilise():
    ident = ServiceIdentifier()
    ident.observe_dns(_dns("1.2.3.4", "example.com"))
    assert ident.resolve(_FLOW) == ServiceHint(source="dns", value="example.com")


def test_sni_prime_sur_dns():
    # Même flux identifié par les deux sources : le SNI doit l'emporter.
    ident = ServiceIdentifier()
    ident.observe_dns(_dns("1.2.3.4", "cdn-anonyme.net"))
    ident.observe_sni(_FLOW, "netflix.com")
    assert ident.resolve(_FLOW) == ServiceHint(source="sni", value="netflix.com")


def test_meme_ip_flux_avec_sni_vs_sans_sni():
    # SNI est par-flux, DNS par-IP : deux connexions vers la même IP, seule celle
    # qui a un SNI l'utilise ; l'autre retombe sur le cache DNS.
    ident = ServiceIdentifier()
    ident.observe_dns(_dns("1.2.3.4", "example.com"))
    flow_avec_sni = ("192.168.1.10", 54321, "1.2.3.4", 443)
    flow_sans_sni = ("192.168.1.10", 55555, "1.2.3.4", 443)
    ident.observe_sni(flow_avec_sni, "netflix.com")

    assert ident.resolve(flow_avec_sni) == ServiceHint(source="sni", value="netflix.com")
    assert ident.resolve(flow_sans_sni) == ServiceHint(source="dns", value="example.com")


def test_aucune_source_retourne_none():
    ident = ServiceIdentifier()
    assert ident.resolve(_FLOW) is None


def test_carnet_sni_borne_evince_le_plus_ancien():
    ident = ServiceIdentifier(max_flows=2)
    f1 = ("10.0.0.1", 1000, "1.1.1.1", 443)
    f2 = ("10.0.0.1", 1001, "2.2.2.2", 443)
    f3 = ("10.0.0.1", 1002, "3.3.3.3", 443)
    ident.observe_sni(f1, "un.com")
    ident.observe_sni(f2, "deux.com")
    ident.observe_sni(f3, "trois.com")  # évince f1 (le plus ancien)

    assert ident.resolve(f1) is None  # SNI évincé, aucun DNS → rien
    assert ident.resolve(f2) == ServiceHint(source="sni", value="deux.com")
    assert ident.resolve(f3) == ServiceHint(source="sni", value="trois.com")


def test_resolve_rafraichit_la_recence_du_carnet():
    ident = ServiceIdentifier(max_flows=2)
    f1 = ("10.0.0.1", 1000, "1.1.1.1", 443)
    f2 = ("10.0.0.1", 1001, "2.2.2.2", 443)
    f3 = ("10.0.0.1", 1002, "3.3.3.3", 443)
    ident.observe_sni(f1, "un.com")
    ident.observe_sni(f2, "deux.com")

    assert ident.resolve(f1) == ServiceHint(source="sni", value="un.com")  # f1 rafraîchi
    ident.observe_sni(f3, "trois.com")  # f2, non touché, est évincé à la place de f1

    assert ident.resolve(f2) is None
    assert ident.resolve(f1) == ServiceHint(source="sni", value="un.com")
    assert ident.resolve(f3) == ServiceHint(source="sni", value="trois.com")
