"""Capture de paquets bruts via Scapy, pontée vers asyncio.

Scapy capture en **bloquant** dans un thread dédié (``AsyncSniffer`` — dont le
nom ne renvoie pas à asyncio mais au threading). asyncio, lui, est mono-thread.
Le pont entre les deux mondes passe **exclusivement** par
``loop.call_soon_threadsafe`` : c'est la seule primitive asyncio qu'un autre
thread a le droit d'appeler. Chaque paquet est ainsi déposé dans une
``asyncio.Queue`` que le reste du pipeline (parser, transport) consomme à son
rythme.
"""

from __future__ import annotations

import asyncio

import structlog
from scapy.config import conf

# Importé pour lui-même, mais aussi pour l'effet de bord : charger ce module peuple
# la table `conf.l2types` (link type → classe de dissection) dont dépend l'inspection
# ci-dessous. Sans elle, Scapy ne sait pas résoudre le lien et rend un objet bidon.
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

logger = structlog.get_logger("tracee_agent.capture")

# Délai laissé au thread Scapy pour échouer à l'ouverture du socket (interface
# invalide / droits insuffisants) avant qu'on considère la capture démarrée.
_STARTUP_GRACE_SECONDS = 0.2


def link_layer_warning(layer: object | None) -> str | None:
    """Message d'alerte si la couche liaison n'est pas celle qu'on sait décoder.

    Le décodeur appelle ``Ether(data)`` : il attend des trames Ethernet, et lirait
    de travers tout autre format (un VPN en mode TUN livre de l'IP nue, une capture
    de bouclage a son propre en-tête, un lien PPP aussi). L'agent capturerait alors
    sans jamais rien produire.

    Args:
        layer: Classe de dissection retenue par Scapy pour ce lien, ou ``None`` si on
            n'a pas réussi à l'établir. Volontairement typé large : quand Scapy ne
            sait pas résoudre le lien, il ne rend pas ``None`` mais un objet qui n'est
            **pas une classe**, au nom trompeur de ``Raw``. Le prendre pour une couche
            ferait crier au loup sur toutes les cartes Ethernet — d'où le filtre
            ``isinstance`` ci-dessous, placé ici parce que c'est ici qu'on décide
            d'alerter.

    Returns:
        Le constat puis le geste attendu, en **deux lignes** — l'écran de paramètres
        l'affiche tel quel dans une bande de statut étroite. ``None`` quand il n'y a
        rien à signaler : lien Ethernet, ou type indéterminé (on ne crie pas sur une
        incertitude).
    """
    if layer is None or layer is Ether or not isinstance(layer, type):
        return None
    return (
        f"Lien non-Ethernet ({layer.__name__}) : rien ne sera décodé.\n"
        "Choisir une carte Ethernet ou Wi-Fi."
    )


def link_layer(interface: str) -> object | None:
    """Couche de liaison que Scapy emploierait pour ``interface``, telle quelle.

    Ouvre un socket d'écoute le temps de lire la classe déduite du *link type*, puis
    le referme. Le sniffer ne l'expose pas (il garde ses sockets dans une variable
    locale), d'où cette ouverture séparée, faite **avant** la capture pour ne jamais
    tenir deux handles à la fois.

    Publique parce que l'écran de paramètres s'en sert aussi : il avertit au clic,
    avant même que la capture démarre, plutôt que d'attendre un message qui devrait
    traverser le thread de travail.

    Best-effort : un diagnostic ne doit pas empêcher de capturer. Un échec
    d'ouverture (droits insuffisants, interface disparue) rend ``None`` — la vraie
    capture dira elle-même ce qui ne va pas. On ne filtre pas ici ce que Scapy
    renvoie : l'interprétation revient à ``link_layer_warning``.
    """
    try:
        socket = conf.L2listen(iface=interface)
    except Exception:  # noqa: BLE001 — inspection facultative, jamais bloquante
        return None
    try:
        return getattr(socket, "LL", None)
    finally:
        socket.close()


class CaptureError(RuntimeError):
    """Échec de capture : interface absente, droits insuffisants, etc."""


class PacketCapture:
    """Capture les octets d'une interface et les remet dans une file asyncio.

    La capture tourne dans un thread Scapy séparé. Chaque paquet est transféré
    vers la boucle asyncio via ``call_soon_threadsafe`` puis empilé dans
    ``queue`` sous forme d'octets bruts (trame écrêtée à ``snaplen``). Le
    consommateur (parser) lit la file quand il est disponible.

    Args:
        interface: Interface à écouter ; ignorée si ``pcap_file`` est fourni.
        snaplen: Nombre maximal d'octets conservés par paquet (> 0).
        queue: File asyncio (de préférence bornée) alimentée par la capture.
        loop: Boucle cible ; par défaut la boucle courante au ``start()``.
        pcap_file: Chemin d'un PCAP à rejouer au lieu d'une interface (tests).
    """

    def __init__(
        self,
        interface: str | None,
        snaplen: int,
        queue: asyncio.Queue[bytes],
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        pcap_file: str | None = None,
    ) -> None:
        self._interface = interface
        self._snaplen = snaplen
        self._queue = queue
        self._loop = loop
        self._pcap_file = pcap_file
        self._sniffer: AsyncSniffer | None = None

    def start(self) -> None:
        """Démarre la capture ; lève ``CaptureError`` si l'interface est invalide."""
        if self._sniffer is not None:
            raise CaptureError("La capture est déjà démarrée.")

        # Le callback tournera dans le thread Scapy et devra revenir vers cette
        # boucle : on la mémorise maintenant, tant qu'on est côté asyncio.
        self._loop = self._loop or asyncio.get_running_loop()

        source = f"pcap:{self._pcap_file}" if self._pcap_file else self._interface
        # Vérifié avant d'ouvrir la capture, et seulement sur une interface réelle : un
        # PCAP rejoué vient de nos propres tests, son format est connu.
        if self._interface is not None and self._pcap_file is None:
            warning = link_layer_warning(link_layer(self._interface))
            if warning is not None:
                # Le message est mis en forme pour un écran (deux lignes) ; un log tient
                # sur une seule, sans quoi il se coupe en deux entrées à la lecture.
                motif = warning.replace("\n", " ")
                logger.warning("lien_non_ethernet", interface=self._interface, motif=motif)

        kwargs: dict[str, object] = {"prn": self._on_packet, "store": False}
        if self._pcap_file is not None:
            kwargs["offline"] = self._pcap_file
        else:
            kwargs["iface"] = self._interface

        sniffer = AsyncSniffer(**kwargs)
        sniffer.start()

        # Une interface invalide / un manque de droits échoue à l'ouverture du
        # socket, donc dans les premières millisecondes du thread. On lui laisse
        # ce court instant pour planter, puis on récupère l'exception stockée.
        sniffer.thread.join(_STARTUP_GRACE_SECONDS)
        if sniffer.exception is not None:
            logger.error("capture_demarrage_echoue", source=source, erreur=str(sniffer.exception))
            raise CaptureError(f"Impossible de capturer sur {source!r}.") from sniffer.exception

        self._sniffer = sniffer
        logger.info("capture_demarree", source=source, snaplen=self._snaplen)

    def stop(self) -> None:
        """Arrête la capture et libère l'interface (idempotent)."""
        if self._sniffer is None:
            return
        try:
            self._sniffer.stop()  # arrête le thread et ferme le socket
        except Exception as exc:  # noqa: BLE001 — erreur survenue pendant la capture
            logger.error("capture_arret_erreur", erreur=str(exc))
        finally:
            self._sniffer = None
            logger.info("capture_arretee")

    def _on_packet(self, packet: Packet) -> None:
        # Exécuté DANS le thread Scapy : interdit de toucher la file asyncio ici.
        # On sérialise le paquet (travail CPU gardé hors de la boucle) puis on
        # repasse la main à asyncio, seul endroit sûr pour manipuler la file.
        data = bytes(packet)[: self._snaplen]
        assert self._loop is not None  # garanti par start()
        self._loop.call_soon_threadsafe(self._enqueue, data)

    def _enqueue(self, data: bytes) -> None:
        # Exécuté DANS la boucle asyncio : la file peut être manipulée sans risque.
        try:
            self._queue.put_nowait(data)
        except asyncio.QueueFull:
            # Consommateur trop lent : on préfère perdre un paquet plutôt que
            # bloquer la capture (backpressure). Tracé pour diagnostic.
            logger.warning("file_saturee_paquet_perdu")
