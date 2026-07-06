"""Tests de la découverte et du formatage des interfaces réseau."""

from tracee_agent.capture.interfaces import InterfaceInfo, format_interfaces, list_interfaces


def test_liste_contient_le_loopback():
    # Le loopback existe sur toute machine : point d'ancrage stable pour le test.
    names = {info.name for info in list_interfaces()}
    assert "lo" in names


def test_loopback_expose_son_ipv4():
    interfaces = {info.name: info for info in list_interfaces()}
    assert "127.0.0.1" in interfaces["lo"].ipv4


def test_loopback_liste_en_premier():
    # Tri par index kernel (comme `ip addr`) : lo a l'index 1, donc toujours 1er.
    infos = list_interfaces()
    assert infos[0].name == "lo"


def test_format_lisible_et_stable():
    infos = [
        InterfaceInfo(name="lo", ipv4=["127.0.0.1"], ipv6=["::1"]),
        InterfaceInfo(name="eth0", ipv4=[], ipv6=[]),
    ]
    lines = format_interfaces(infos).splitlines()

    assert lines[0].startswith("lo")
    assert "127.0.0.1" in lines[0] and "::1" in lines[0]
    # Interface sans adresse : mention explicite plutôt qu'une colonne vide.
    assert lines[1].startswith("eth0")
    assert "(aucune adresse)" in lines[1]
