"""Tests de la capture Scapy pontée vers asyncio.

La capture est rejouée sur des PCAP générés à la volée (``tmp_path``) : pas
besoin de droits root ni d'interface réelle, et les paquets testés restent
lisibles dans le code plutôt que cachés dans un binaire committé.
"""

import asyncio
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from tracee_agent.capture.sniffer import CaptureError, PacketCapture


def _write_pcap(tmp_path: Path, packets: list) -> str:
    file = tmp_path / "sample.pcap"
    wrpcap(str(file), packets)
    return str(file)


async def _drain(pcap_file: str, snaplen: int, expected: int) -> list[bytes]:
    """Rejoue ``pcap_file`` et renvoie les octets remis dans la file."""
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    capture = PacketCapture(interface=None, snaplen=snaplen, queue=queue, pcap_file=pcap_file)
    capture.start()
    received: list[bytes] = []
    try:
        for _ in range(expected):
            # timeout : un test ne doit jamais pendre si la file reste vide.
            received.append(await asyncio.wait_for(queue.get(), timeout=2))
    finally:
        capture.stop()
    return received


def test_capture_rejoue_pcap_remet_les_paquets_dans_la_file(tmp_path):
    packets = [
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=443),
        Ether() / IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=5353, dport=53),
    ]
    pcap = _write_pcap(tmp_path, packets)

    received = asyncio.run(_drain(pcap, snaplen=65535, expected=len(packets)))

    assert len(received) == len(packets)
    assert all(isinstance(data, bytes) for data in received)


def test_snaplen_ecrete_les_paquets(tmp_path):
    # Trame volumineuse : 1000 octets de payload, bien au-delà du snaplen.
    packets = [Ether() / IP() / TCP() / (b"x" * 1000)]
    pcap = _write_pcap(tmp_path, packets)

    received = asyncio.run(_drain(pcap, snaplen=64, expected=1))

    assert len(received[0]) == 64  # conservé = snaplen, pas la trame entière


def test_interface_invalide_leve_capture_error():
    # Interface inexistante : l'ouverture du socket échoue dans le thread Scapy,
    # que le process soit root (interface absente) ou non (droits refusés) — les
    # deux cas doivent remonter une CaptureError explicite.
    async def scenario() -> None:
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        capture = PacketCapture(interface="tracee-nope0", snaplen=512, queue=queue)
        capture.start()

    with pytest.raises(CaptureError):
        asyncio.run(scenario())
