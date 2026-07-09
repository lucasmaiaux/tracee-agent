"""Tests de l'agrégateur de flux (regroupement + compteurs biflow)."""

from __future__ import annotations

from tracee_agent.flow import FlowAggregator
from tracee_agent.parser.models import ParsedPacket


def _pkt(
    source_ip: str,
    source_port: int | None,
    dest_ip: str,
    dest_port: int | None,
    *,
    protocol: str = "tcp",
    size: int = 100,
) -> ParsedPacket:
    """Fabrique un ParsedPacket minimal (le contenu applicatif n'importe pas ici)."""
    return ParsedPacket(
        source_ip=source_ip,
        source_port=source_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol,
        packet_size=size,
        payload_size=0,
        payload=b"",
    )


def test_aller_retour_forment_un_seul_flux_oriente() -> None:
    """Les deux sens d'une connexion tombent dans le même flux, orienté client → serveur."""
    agg = FlowAggregator()
    # Client 192.168.1.10:54321 (port élevé) ↔ serveur 142.250.0.1:443 (port bas).
    agg.add(_pkt("192.168.1.10", 54321, "142.250.0.1", 443, size=40))  # émis
    agg.add(_pkt("142.250.0.1", 443, "192.168.1.10", 54321, size=1500))  # reçu
    agg.add(_pkt("142.250.0.1", 443, "192.168.1.10", 54321, size=1500))  # reçu

    records = agg.flush()
    assert len(records) == 1
    record = records[0]
    assert (record.source_ip, record.source_port) == ("192.168.1.10", 54321)
    assert (record.dest_ip, record.dest_port) == ("142.250.0.1", 443)
    assert record.bytes_sent == 40
    assert record.bytes_received == 3000
    assert record.packets_sent == 1
    assert record.packets_received == 2


def test_orientation_independante_de_l_ordre_d_arrivee() -> None:
    """Même si le 1er paquet vu est le retour (fenêtre au milieu d'une connexion),
    la source reste le client (port élevé), pas l'émetteur du 1er paquet."""
    agg = FlowAggregator()
    agg.add(_pkt("142.250.0.1", 443, "192.168.1.10", 54321, size=1500))  # retour en 1er

    record = agg.flush()[0]
    assert (record.source_ip, record.source_port) == ("192.168.1.10", 54321)
    assert record.bytes_received == 1500
    assert record.bytes_sent == 0


def test_flush_remet_l_accumulateur_a_zero() -> None:
    """Un flush vide l'état : le flush suivant ne renvoie rien tant qu'aucun paquet."""
    agg = FlowAggregator()
    agg.add(_pkt("192.168.1.10", 54321, "142.250.0.1", 443))
    assert len(agg.flush()) == 1
    assert agg.flush() == []


def test_flux_sans_port_icmp_reste_un_seul_flux() -> None:
    """Un flux sans port (ICMP) est regroupé de façon stable et n'échoue pas."""
    agg = FlowAggregator()
    agg.add(_pkt("192.168.1.10", None, "1.1.1.1", None, protocol="icmp", size=84))
    agg.add(_pkt("1.1.1.1", None, "192.168.1.10", None, protocol="icmp", size=84))

    records = agg.flush()
    assert len(records) == 1
    record = records[0]
    assert record.protocol == "icmp"
    assert record.bytes_sent + record.bytes_received == 168
