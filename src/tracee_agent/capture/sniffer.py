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
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

logger = structlog.get_logger("tracee_agent.capture")

# Délai laissé au thread Scapy pour échouer à l'ouverture du socket (interface
# invalide / droits insuffisants) avant qu'on considère la capture démarrée.
_STARTUP_GRACE_SECONDS = 0.2


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
