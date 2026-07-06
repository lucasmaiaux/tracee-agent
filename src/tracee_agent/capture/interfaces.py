"""Découverte des interfaces réseau capturables.

La liste vient de ``conf.ifaces`` de Scapy (et non d'une API système tierce) :
c'est la garantie que le **nom** affiché ici est exactement celui que la capture
attend en ``iface=``. Sur certaines plateformes (Windows notamment) Scapy
utilise ses propres noms d'interface — passer par lui évite d'afficher un nom
que la capture refuserait ensuite.

Lister n'ouvre aucun socket de capture : aucune élévation de privilèges requise.
"""

from __future__ import annotations

from dataclasses import dataclass

import scapy.arch  # noqa: F401 — charge le provider système qui peuple conf.ifaces
from scapy.config import conf


@dataclass(frozen=True)
class InterfaceInfo:
    """Interface réseau et ses adresses, telles que vues par Scapy."""

    name: str
    ipv4: list[str]
    ipv6: list[str]


def list_interfaces() -> list[InterfaceInfo]:
    """Renvoie les interfaces connues, triées par index kernel (loopback en tête).

    Le tri reprend l'ordre de ``ip addr`` (index d'interface croissant) : ``lo``
    a toujours l'index 1, donc il apparaît en premier — plus lisible qu'un tri
    alphabétique qui remonterait les ``br-*`` de Docker en tête.
    """
    conf.ifaces.reload()  # reflète l'état courant du système à chaque appel
    ifaces = sorted(conf.ifaces.values(), key=lambda iface: getattr(iface, "index", 0))
    infos: list[InterfaceInfo] = []
    for iface in ifaces:
        ips = getattr(iface, "ips", {})
        infos.append(
            InterfaceInfo(
                name=iface.name,
                ipv4=list(ips.get(4, [])),
                ipv6=list(ips.get(6, [])),
            )
        )
    return infos


def format_interfaces(infos: list[InterfaceInfo]) -> str:
    """Formate la liste en texte aligné, prêt à recopier dans la config."""
    lines = []
    for info in infos:
        addresses = ", ".join(info.ipv4 + info.ipv6) or "(aucune adresse)"
        # Le nom à gauche, aligné, est celui à mettre dans capture.default_interface.
        lines.append(f"{info.name:<24} {addresses}")
    return "\n".join(lines)
