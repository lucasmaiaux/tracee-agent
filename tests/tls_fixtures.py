"""Fabrique de ClientHello TLS forgés à la main, partagée par les tests SNI.

``vec`` préfixe un contenu par sa longueur (miroir du read_vector du parser) ;
``wrap`` emballe un bloc d'extensions en ClientHello puis record TLS complet.
"""


def vec(length_bytes: int, content: bytes) -> bytes:
    """Préfixe ``content`` par sa longueur codée sur ``length_bytes`` octets."""
    return len(content).to_bytes(length_bytes, "big") + content


def sni_extension(host: str) -> bytes:
    """Extension server_name (type 0) contenant un host_name (RFC 6066 §3)."""
    entry = b"\x00" + vec(2, host.encode("ascii"))  # name_type=host_name + HostName<2>
    return b"\x00\x00" + vec(2, vec(2, entry))  # ext_type=0 + ext_data<2>( ServerNameList<2> )


def dummy_extension() -> bytes:
    """Extension non-SNI quelconque (supported_groups, type 0x000a)."""
    return b"\x00\x0a" + vec(2, b"\x00\x1d")


def wrap(extensions: bytes) -> bytes:
    """Emballe un bloc d'extensions en ClientHello puis record TLS (RFC 8446 §4.1.2, §5.1)."""
    body = (
        b"\x03\x03"  # legacy_version : TLS 1.2 (inchangé même en 1.3)
        + b"\x00" * 32  # random
        + vec(1, b"")  # legacy_session_id (vide)
        + vec(2, b"\x13\x01")  # cipher_suites : TLS_AES_128_GCM_SHA256
        + vec(1, b"\x00")  # legacy_compression_methods : null
        + vec(2, extensions)
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body  # client_hello + length(uint24)
    return b"\x16\x03\x01" + vec(2, handshake)  # record : handshake + version + length


def client_hello(*, server_name: str | None = None, extra_extensions: bytes = b"") -> bytes:
    """Forge un ClientHello ; le SNI (si fourni) est placé après extra_extensions."""
    sni = sni_extension(server_name) if server_name else b""
    extensions = extra_extensions + sni
    if not extensions:
        extensions = dummy_extension()  # un ClientHello a toujours des extensions
    return wrap(extensions)
