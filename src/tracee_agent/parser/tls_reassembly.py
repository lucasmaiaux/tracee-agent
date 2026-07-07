"""Réassemblage des ClientHello TLS fragmentés sur plusieurs segments TCP.

Depuis l'adoption de l'échange de clés post-quantique (``X25519MLKEM768``), le
ClientHello dépasse fréquemment le MSS (~1460 octets) et se retrouve coupé sur
deux segments TCP — le SNI peut alors tomber dans le second. Comme tous les
inspecteurs de trafic (Suricata, Traefik, Wireshark…), on doit donc réassembler
le flux avant d'extraire le SNI.

Réassemblage *léger*, propre au ClientHello (pas une pile TCP complète) : on ne
suit un flux que s'il **commence** par un ClientHello, on lit la longueur
annoncée du record TLS pour savoir quoi attendre, et on concatène les segments
jusqu'à complétude. Les segments sont recollés dans leur **ordre d'arrivée** —
suffisant pour le cas courant (deux segments consécutifs) ; le tri par numéro de
séquence TCP serait l'évolution robuste. Le SNI n'étant lu qu'une fois le record
complet, un mauvais recollage produit ``None`` (parser défensif), jamais un faux.
"""

from __future__ import annotations

import structlog

from tracee_agent.parser.tls import extract_sni

logger = structlog.get_logger("tracee_agent.parser.tls")

# Flux TCP orienté client→serveur : (ip_src, port_src, ip_dst, port_dst).
FlowKey = tuple[str, int, str, int]

_TLS_HANDSHAKE = 0x16  # ContentType du record TLS : handshake (RFC 8446 §5.1)
_CLIENT_HELLO = 0x01  # HandshakeType : client_hello
_RECORD_HEADER_LEN = 5  # type(1) + version(2) + length(2)

# Garde-fous mémoire : un record TLS ne dépasse pas 2^14 octets (RFC 8446 §5.1) ;
# au-delà, la donnée est aberrante et le flux est abandonné. Et on borne le nombre
# de flux suivis en parallèle pour ne jamais fuir.
_MAX_BUFFER = 16640
_MAX_FLOWS = 1024


def _starts_client_hello(payload: bytes) -> bool:
    """Vrai si le segment débute un ClientHello (record handshake + type 0x01)."""
    return len(payload) >= 6 and payload[0] == _TLS_HANDSHAKE and payload[5] == _CLIENT_HELLO


def _expected_length(buffer: bytes) -> int | None:
    """Taille totale attendue du record TLS, ou ``None`` si l'en-tête est incomplet."""
    if len(buffer) < _RECORD_HEADER_LEN:
        return None
    return _RECORD_HEADER_LEN + int.from_bytes(buffer[3:5], "big")


class ClientHelloReassembler:
    """Recolle les ClientHello étalés sur plusieurs segments TCP, par flux.

    ``feed`` est appelé pour chaque segment TCP porteur de données ; il retourne
    le SNI dès qu'un ClientHello complet est reconstitué pour ce flux, sinon
    ``None``. Le cas mono-segment (petit ClientHello) est géré sans surcoût : le
    record est complet dès le premier appel.
    """

    def __init__(self, max_flows: int = _MAX_FLOWS, max_buffer: int = _MAX_BUFFER) -> None:
        self._pending: dict[FlowKey, bytes] = {}
        self._max_flows = max_flows
        self._max_buffer = max_buffer

    def feed(self, flow: FlowKey, payload: bytes) -> str | None:
        buffer = self._pending.get(flow)
        if buffer is None:
            # Nouveau flux : on ne le suit que s'il amorce un ClientHello.
            if not _starts_client_hello(payload):
                return None
            buffer = payload
        else:
            buffer += payload

        expected = _expected_length(buffer)
        if expected is not None and len(buffer) >= expected:
            self._pending.pop(flow, None)  # record complet : on libère le flux
            sni = extract_sni(buffer)
            if sni is None:
                # ClientHello entièrement reçu mais sans server_name exploitable.
                logger.debug("clienthello_sans_sni", destination=flow[2])
            return sni

        if len(buffer) >= self._max_buffer:
            self._pending.pop(flow, None)  # taille aberrante : on abandonne
            logger.warning("clienthello_abandonne", raison="record_incoherent", destination=flow[2])
            return None

        self._store(flow, buffer)
        return None

    def _store(self, flow: FlowKey, buffer: bytes) -> None:
        # Éviction du flux le plus anciennement commencé pour borner la mémoire
        # (un dict conserve l'ordre d'insertion). Un flux évincé est un ClientHello
        # jamais complété — typiquement un segment perdu ou arrivé dans le désordre.
        if flow not in self._pending and len(self._pending) >= self._max_flows:
            evicted = next(iter(self._pending))
            del self._pending[evicted]
            logger.warning("clienthello_abandonne", raison="flux_evince", destination=evicted[2])
        self._pending[flow] = buffer
