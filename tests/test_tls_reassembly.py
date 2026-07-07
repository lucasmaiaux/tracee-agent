"""Tests du réassemblage des ClientHello fragmentés sur plusieurs segments TCP."""

from tls_fixtures import client_hello, sni_extension, vec, wrap

from tracee_agent.parser.tls_reassembly import ClientHelloReassembler

_FLOW = ("10.0.0.1", 51000, "93.184.216.34", 443)
_FLOW_B = ("10.0.0.1", 51001, "1.1.1.1", 443)


def _big_client_hello(host: str) -> bytes:
    """ClientHello volumineux (padding) dépassant un segment, SNI placé tôt."""
    padding = b"\x00\x15" + vec(2, b"\x00" * 3000)  # extension padding (type 21)
    frame = wrap(sni_extension(host) + padding)
    assert len(frame) > 1460  # garantit la fragmentation sur plusieurs segments
    return frame


def test_client_hello_en_deux_segments():
    frame = _big_client_hello("www.exemple.com")
    seg1, seg2 = frame[:1400], frame[1400:]
    reassembler = ClientHelloReassembler()
    assert reassembler.feed(_FLOW, seg1) is None  # incomplet
    assert reassembler.feed(_FLOW, seg2) == "www.exemple.com"  # complété


def test_client_hello_mono_segment():
    reassembler = ClientHelloReassembler()
    frame = wrap(sni_extension("curl.exemple.com"))
    assert reassembler.feed(_FLOW, frame) == "curl.exemple.com"


def test_segments_dans_le_mauvais_ordre_ne_produisent_pas_de_faux_sni():
    # Version « ordre d'arrivée » : si le 2e segment (la suite du ClientHello)
    # arrive AVANT le 1er, il ne commence pas par un ClientHello → il est ignoré,
    # et le SNI est manqué proprement (None), jamais un faux. Le tri par numéro de
    # séquence TCP (évolution robuste) lèverait cette limite.
    frame = _big_client_hello("www.exemple.com")
    seg1, seg2 = frame[:1400], frame[1400:]
    reassembler = ClientHelloReassembler()
    assert reassembler.feed(_FLOW, seg2) is None  # suite orpheline : non suivie
    assert reassembler.feed(_FLOW, seg1) is None  # début seul : jamais complété


def test_flux_entrelaces_ne_se_melangent_pas():
    a = _big_client_hello("a.exemple.com")
    b = _big_client_hello("b.exemple.com")
    reassembler = ClientHelloReassembler()
    assert reassembler.feed(_FLOW, a[:1400]) is None
    assert reassembler.feed(_FLOW_B, b[:1400]) is None
    assert reassembler.feed(_FLOW, a[1400:]) == "a.exemple.com"
    assert reassembler.feed(_FLOW_B, b[1400:]) == "b.exemple.com"


def test_client_hello_complet_sans_sni_retourne_none():
    # Record entièrement reçu mais sans extension server_name.
    reassembler = ClientHelloReassembler()
    assert reassembler.feed(_FLOW, client_hello(server_name=None)) is None


def test_flux_non_client_hello_nest_pas_suivi():
    reassembler = ClientHelloReassembler()
    assert reassembler.feed(_FLOW, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert reassembler._pending == {}  # aucun flux mémorisé


def test_garde_fou_taille_abandonne_le_flux():
    reassembler = ClientHelloReassembler(max_buffer=2000)
    # Début de ClientHello déclarant un record énorme (0xffff) → jamais complété.
    start = b"\x16\x03\x01\xff\xff\x01" + b"\x00" * 1500
    assert reassembler.feed(_FLOW, start) is None
    assert _FLOW in reassembler._pending  # suivi tant qu'on est sous la limite
    assert reassembler.feed(_FLOW, b"\x00" * 1000) is None  # dépasse max_buffer
    assert _FLOW not in reassembler._pending  # abandonné
