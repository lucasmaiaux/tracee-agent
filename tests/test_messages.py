"""Tests de construction des messages du protocole (US #18 : message `event`)."""

from __future__ import annotations

from tracee_agent.flow import FlowRecord
from tracee_agent.identifier.service_identifier import ServiceHint
from tracee_agent.transport.messages import build_event


def test_build_event_mappe_un_flux_biflow_conforme() -> None:
    """Un flux agrégé produit un `event` conforme au PROTOCOL.md (compteurs directionnels)."""
    flow = FlowRecord(
        source_ip="192.168.1.10",
        source_port=54321,
        dest_ip="142.250.0.1",
        dest_port=443,
        protocol="tcp",
        bytes_sent=40,
        bytes_received=3000,
        packets_sent=1,
        packets_received=2,
    )
    message = build_event("wlan0", flow, ServiceHint(source="sni", value="youtube.com"))

    assert message["type"] == "event"
    assert message["timestamp"]  # horodatage renseigné par l'enveloppe
    assert message["payload"] == {
        "interface": "wlan0",
        "source_ip": "192.168.1.10",
        "source_port": 54321,
        "dest_ip": "142.250.0.1",
        "dest_port": 443,
        "protocol": "tcp",
        "bytes_sent": 40,
        "bytes_received": 3000,
        "packets_sent": 1,
        "packets_received": 2,
        "service_hint": {"type": "sni", "value": "youtube.com"},
        "metadata": {},
    }


def test_build_event_flux_sans_hint_ni_ports() -> None:
    """Un flux sans service identifié ni ports (ICMP) : service_hint et ports à None."""
    flow = FlowRecord(
        source_ip="192.168.1.10",
        source_port=None,
        dest_ip="1.1.1.1",
        dest_port=None,
        protocol="icmp",
        bytes_sent=84,
        bytes_received=84,
        packets_sent=1,
        packets_received=1,
    )
    payload = build_event("eth0", flow, None)["payload"]

    assert payload["service_hint"] is None
    assert payload["source_port"] is None
    assert payload["dest_port"] is None
    assert payload["protocol"] == "icmp"
