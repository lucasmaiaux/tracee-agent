"""Tests du branchement des compteurs de santé dans le pipeline de capture.

``_consume`` est la boucle qui décode et alimente l'identification : c'est là que
l'information se perd quand une machine se comporte autrement que prévu. On la
nourrit de trames forgées et on vérifie ce qu'elle en rapporte — c'est ce rapport,
et non le flux d'events, qui rend une panne d'identification visible.

La boucle ne se termine jamais : on la lance en tâche, on attend un effet
observable, puis on annule (même procédé que ``test_transport``).
"""

import asyncio

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from tls_fixtures import client_hello

from tracee_agent.flow import FlowAggregator
from tracee_agent.health import PipelineHealth
from tracee_agent.identifier import ServiceIdentifier
from tracee_agent.parser import ClientHelloReassembler
from tracee_agent.runtime import _consume

_SNAPLEN = 4096


async def _consume_frames(frames: list[bytes], *, snaplen: int = _SNAPLEN) -> PipelineHealth:
    """Fait passer des trames dans ``_consume`` et rend les compteurs obtenus."""
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    for frame in frames:
        queue.put_nowait(frame)

    health = PipelineHealth()
    task = asyncio.create_task(
        _consume(
            queue,
            FlowAggregator(),
            ServiceIdentifier(),
            ClientHelloReassembler(),
            health=health,
            snaplen=snaplen,
        )
    )
    try:
        async with asyncio.timeout(2):
            while health.packets_decoded + health.frames_ignored < len(frames):
                await asyncio.sleep(0)
    finally:
        task.cancel()
    return health


async def test_clienthello_offloade_est_decode_compte_et_identifie():
    # Le cas qui a mis 100 % des SNI par terre : en-tête à longueur nulle (TSO).
    hello = client_hello(server_name="www.exemple.fr")
    frame = bytes(Ether() / IP(len=0) / TCP(sport=54321, dport=443) / hello)

    health = await _consume_frames([frame])

    assert health.packets_decoded == 1
    assert health.headers_offloaded == 1  # la machine délègue la segmentation
    assert health.client_hellos == 1
    assert health.services_identified == 1  # ...et le SNI en sort quand même


async def test_trames_non_ip_sont_comptees_a_part():
    # Un lien qui n'est pas Ethernet ferait grimper ce compteur jusqu'à saturation :
    # c'est le signal qui distingue « pas de trafic » de « on ne sait pas le lire ».
    health = await _consume_frames([bytes(Ether() / ARP())])

    assert health.frames_ignored == 1
    assert health.packets_decoded == 0


async def test_trame_a_la_limite_du_snaplen_est_comptee_tronquee():
    # Une trame rendue pile à la taille de snaplen a, sauf coïncidence, perdu sa fin.
    # C'est le compteur qui dit qu'un ClientHello arrive incomplet.
    frame = bytes(Ether() / IP() / TCP(sport=54321, dport=443) / (b"x" * 500))
    snaplen = 128

    health = await _consume_frames([frame[:snaplen]], snaplen=snaplen)

    assert health.frames_truncated == 1


@pytest.mark.parametrize("offloaded", [True, False])
async def test_le_compteur_d_offload_ne_se_declenche_que_sur_un_entete_vide(offloaded: bool):
    ip = IP(len=0) if offloaded else IP()
    frame = bytes(Ether() / ip / TCP(sport=54321, dport=443) / b"donnees applicatives")

    health = await _consume_frames([frame])

    assert health.headers_offloaded == int(offloaded)
