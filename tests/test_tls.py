"""Tests de l'extraction du SNI, sur des ClientHello forgés à la main.

Les fixtures de forge sont dans ``tls_fixtures`` (partagées avec les tests de
réassemblage). Construire les octets champ par champ rend chaque structure
visible et le test déterministe.
"""

from tls_fixtures import client_hello, dummy_extension, sni_extension, vec, wrap

from tracee_agent.parser.tls import extract_sni


def test_extrait_le_sni():
    assert extract_sni(client_hello(server_name="www.netflix.com")) == "www.netflix.com"


def test_sni_trouve_apres_une_autre_extension():
    # Le SNI n'est pas la première extension : valide le parcours TLV.
    frame = client_hello(server_name="example.com", extra_extensions=dummy_extension())
    assert extract_sni(frame) == "example.com"


def test_client_hello_sans_sni_retourne_none():
    assert extract_sni(client_hello(server_name=None)) is None


def test_autre_type_de_handshake_est_ignore():
    # Même trame, mais msg_type handshake = 0x02 (ServerHello) au lieu de 0x01.
    frame = client_hello(server_name="example.com")
    server_hello = frame[:5] + b"\x02" + frame[6:]
    assert extract_sni(server_hello) is None


def test_handshake_tronque_retourne_none_sans_crash():
    frame = client_hello(server_name="www.example.com")
    assert extract_sni(frame[:40]) is None  # coupé avant le bloc d'extensions


def test_donnees_non_tls_retournent_none():
    assert extract_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert extract_sni(b"") is None
    assert extract_sni(b"\x16\x03\x01") is None  # record amorcé puis coupé net


def test_sni_recupere_sur_client_hello_tronque_apres_le_sni():
    # Cas réel navigateur : ClientHello volumineux coupé au MSS. Le server_name
    # vient tôt (avant une grosse extension padding) → doit rester récupérable.
    padding = b"\x00\x15" + vec(2, b"\x00" * 3000)  # extension padding (type 21), volumineuse
    frame = wrap(sni_extension("www.example.com") + padding)
    assert len(frame) > 1500  # le ClientHello complet dépasse un segment TCP
    assert extract_sni(frame[:1400]) == "www.example.com"  # tronqué, mais SNI présent


def test_sni_lui_meme_tronque_retourne_none_sans_domaine_partiel():
    # Le hostname est coupé en plein milieu : on renvoie None, jamais un domaine
    # partiel (le piège du parsing naïf qui ne borne pas ses lectures).
    frame = wrap(sni_extension("www.domaine-coupe.com"))
    assert extract_sni(frame[:-8]) is None
