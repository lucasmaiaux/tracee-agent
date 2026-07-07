"""Tests du cache DNS observé (``identifier.dns_cache``)."""

from tracee_agent.identifier.dns_cache import DnsCache
from tracee_agent.parser.dns import DnsMessage, DnsRecord


def _message(*answers: DnsRecord) -> DnsMessage:
    """Un message DNS de réponse ne portant que les enregistrements donnés."""
    return DnsMessage(questions=[], answers=list(answers))


def test_lookup_apres_observation_retourne_le_domaine():
    cache = DnsCache()
    cache.observe(_message(DnsRecord(name="example.com", ip="93.184.216.34")))
    assert cache.lookup("93.184.216.34") == "example.com"


def test_ip_inconnue_retourne_none():
    assert DnsCache().lookup("10.0.0.1") is None


def test_derniere_resolution_gagne():
    # Une IP réattribuée (CDN) : la résolution la plus récente écrase l'ancienne.
    cache = DnsCache()
    cache.observe(_message(DnsRecord(name="ancien.com", ip="1.2.3.4")))
    cache.observe(_message(DnsRecord(name="nouveau.com", ip="1.2.3.4")))
    assert cache.lookup("1.2.3.4") == "nouveau.com"
    assert len(cache) == 1


def test_borne_de_taille_evince_la_plus_ancienne():
    cache = DnsCache(max_entries=2)
    cache.observe(_message(DnsRecord(name="a.com", ip="1.1.1.1")))
    cache.observe(_message(DnsRecord(name="b.com", ip="2.2.2.2")))
    cache.observe(_message(DnsRecord(name="c.com", ip="3.3.3.3")))

    assert len(cache) == 2
    assert cache.lookup("1.1.1.1") is None  # la plus ancienne, évincée
    assert cache.lookup("2.2.2.2") == "b.com"
    assert cache.lookup("3.3.3.3") == "c.com"


def test_lookup_rafraichit_la_recence_lru():
    cache = DnsCache(max_entries=2)
    cache.observe(_message(DnsRecord(name="a.com", ip="1.1.1.1")))
    cache.observe(_message(DnsRecord(name="b.com", ip="2.2.2.2")))

    assert cache.lookup("1.1.1.1") == "a.com"  # a.com redevient le plus récent
    cache.observe(_message(DnsRecord(name="c.com", ip="3.3.3.3")))

    # b.com, non touché, est désormais le plus ancien → évincé à la place de a.com.
    assert cache.lookup("2.2.2.2") is None
    assert cache.lookup("1.1.1.1") == "a.com"
    assert cache.lookup("3.3.3.3") == "c.com"


def test_observe_reponses_ipv4_et_ipv6():
    cache = DnsCache()
    cache.observe(
        _message(
            DnsRecord(name="example.com", ip="93.184.216.34"),
            DnsRecord(name="example.com", ip="2606:2800:220:1:248:1893:25c8:1946"),
        )
    )
    assert cache.lookup("93.184.216.34") == "example.com"
    assert cache.lookup("2606:2800:220:1:248:1893:25c8:1946") == "example.com"


def test_requete_sans_reponse_ninsere_rien():
    cache = DnsCache()
    cache.observe(DnsMessage(questions=["example.com"], answers=[]))
    assert len(cache) == 0
