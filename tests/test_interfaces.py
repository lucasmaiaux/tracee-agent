"""Tests de la découverte, du formatage et du choix des interfaces réseau."""

import pytest

from tracee_agent.capture.interfaces import (
    InterfaceInfo,
    InterfaceSelectionError,
    format_interfaces,
    list_interfaces,
    prompt_interface,
)

# Le loopback est le seul point d'ancrage stable pour tester la découverte sur une
# machine quelconque, mais son NOM dépend de la plateforme ('lo' sous Linux,
# 'Loopback Pseudo-Interface 1' sous Windows). On l'identifie donc par son adresse,
# normalisée par la RFC 1122, contrairement au nom.
LOOPBACK_IPV4 = "127.0.0.1"


def _find_loopback(infos: list[InterfaceInfo]) -> InterfaceInfo | None:
    return next((info for info in infos if LOOPBACK_IPV4 in info.ipv4), None)


def test_liste_contient_le_loopback():
    assert _find_loopback(list_interfaces()) is not None


def test_loopback_expose_son_ipv6():
    # Repéré par son IPv4, on vérifie que l'autre famille est bien extraite aussi.
    loopback = _find_loopback(list_interfaces())
    assert loopback is not None
    assert "::1" in loopback.ipv6


def test_loopback_liste_en_premier():
    # Tri par index kernel (comme `ip addr`) : le loopback a l'index 1, donc 1er.
    infos = list_interfaces()
    assert infos[0] == _find_loopback(infos)


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


def test_choix_par_numero(monkeypatch, capsys):
    infos = [
        InterfaceInfo(name="lo", ipv4=["127.0.0.1"], ipv6=[]),
        InterfaceInfo(name="eth0", ipv4=["10.0.0.2"], ipv6=[]),
    ]
    monkeypatch.setattr("builtins.input", lambda _: "2")

    assert prompt_interface(infos) == "eth0"
    # La liste proposée reste celle de format_interfaces, juste numérotée.
    assert "2) eth0" in capsys.readouterr().out


def test_saisie_invalide_redemande(monkeypatch, capsys):
    infos = [
        InterfaceInfo(name="lo", ipv4=[], ipv6=[]),
        InterfaceInfo(name="eth0", ipv4=[], ipv6=[]),
    ]
    # Hors bornes basse, non numérique, hors bornes haute, puis valide.
    answers = iter(["0", "abc", "3", "1"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))

    assert prompt_interface(infos) == "lo"
    assert capsys.readouterr().out.count("Choix invalide") == 3


def test_liste_vide_refusee():
    with pytest.raises(InterfaceSelectionError):
        prompt_interface([])


def test_entree_non_interactive_refusee(monkeypatch):
    # Sans terminal (service systemd, pipe), input() lève EOFError : on refuse de
    # démarrer plutôt que de choisir une interface au hasard.
    def _raise_eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)

    with pytest.raises(InterfaceSelectionError):
        prompt_interface([InterfaceInfo(name="lo", ipv4=[], ipv6=[])])
