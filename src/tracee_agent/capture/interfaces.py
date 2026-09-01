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


class InterfaceSelectionError(RuntimeError):
    """Choix d'interface impossible : aucune interface, ou entrée non interactive."""


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


def _format_line(info: InterfaceInfo) -> str:
    addresses = ", ".join(info.ipv4 + info.ipv6) or "(aucune adresse)"
    # Le nom à gauche, aligné, est celui à mettre dans capture.default_interface.
    return f"{info.name:<24} {addresses}"


def format_interfaces(infos: list[InterfaceInfo]) -> str:
    """Formate la liste en texte aligné, prêt à recopier dans la config."""
    return "\n".join(_format_line(info) for info in infos)


def prompt_interface(infos: list[InterfaceInfo]) -> str:
    """Affiche la liste numérotée et renvoie le nom de l'interface choisie.

    Le choix se fait par **numéro** et non par nom : sous Windows, les noms
    d'interface contiennent espaces et parenthèses (``vEthernet (WSL (Hyper-V
    firewall))``), inutilisables à la saisie.

    Ce prompt vit dans l'agent plutôt que dans le Makefile parce que ``read`` est
    un builtin POSIX, absent de cmd.exe : ``input`` fonctionne sur les trois
    plateformes, et les utilisateurs finaux n'ont ni make ni shell POSIX.

    Args:
        infos: Interfaces proposées, dans l'ordre d'affichage.

    Returns:
        Le nom Scapy de l'interface choisie, tel qu'attendu par la capture.

    Raises:
        InterfaceSelectionError: Aucune interface, entrée non interactive (stdin
            fermé, service systemd) ou saisie interrompue.
    """
    if not infos:
        raise InterfaceSelectionError("aucune interface capturable détectée")

    print("Interfaces capturables :")
    for number, info in enumerate(infos, start=1):
        print(f"  {number:>2}) {_format_line(info)}")

    while True:
        try:
            answer = input(f"Interface à capturer [1-{len(infos)}] : ").strip()
        except EOFError:
            # Pas de terminal (pipe, service) : on refuse plutôt que de deviner.
            raise InterfaceSelectionError("entrée non interactive") from None
        except KeyboardInterrupt:
            raise InterfaceSelectionError("choix interrompu") from None

        if answer.isdigit() and 1 <= int(answer) <= len(infos):
            return infos[int(answer) - 1].name
        print(f"Choix invalide : entrer un numéro entre 1 et {len(infos)}.")
