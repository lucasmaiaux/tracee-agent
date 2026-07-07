"""Extraction du SNI (Server Name Indication) d'un ClientHello TLS.

Parsing **manuel** du handshake, sans bibliothèque DPI. Le SNI est le nom de
domaine que le client annonce en clair à l'ouverture d'une connexion TLS ; il
reste lisible même en TLS 1.3 (le ClientHello n'est jamais chiffré). On navigue
la structure en « poupées russes » — record → handshake → ClientHello →
extensions → server_name — où chaque champ de taille variable est précédé de sa
longueur (RFC 8446 §4.1.2 et §5.1, extension server_name RFC 6066 §3).

Le parsing est **défensif** : avec ``snaplen``, beaucoup de ClientHello arrivent
tronqués. Plutôt que de vérifier les bornes à chaque lecture, on lit comme si
tout était présent et toute lecture hors limites lève ``_Truncated``, rattrapée
une seule fois → ``None``. Un flux non-TLS, sans SNI ou coupé ne lève jamais.
"""

from __future__ import annotations

# Valeurs des champs discriminants (RFC 8446 / RFC 6066).
_TLS_HANDSHAKE = 0x16  # ContentType du record : handshake
_CLIENT_HELLO = 0x01  # HandshakeType : client_hello
_EXT_SERVER_NAME = 0x0000  # ExtensionType : server_name
_NAME_TYPE_HOST = 0x00  # NameType : host_name

# Tailles fixes du ClientHello, en octets.
_LEGACY_VERSION_LEN = 2
_RANDOM_LEN = 32


class _Truncated(Exception):
    """Une lecture a dépassé les octets disponibles (paquet coupé/malformé)."""


class _Reader:
    """Curseur de lecture séquentielle big-endian, borné aux octets présents."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def read(self, n: int) -> bytes:
        end = self._pos + n
        if end > len(self._data):
            raise _Truncated
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def read_int(self, n: int) -> int:
        """Lit un entier non signé sur ``n`` octets (big-endian, ordre réseau)."""
        return int.from_bytes(self.read(n), "big")

    def skip(self, n: int) -> None:
        self.read(n)  # réutilise la vérification de borne

    def read_vector(self, length_bytes: int) -> bytes:
        """Lit un vecteur préfixé : ``length_bytes`` octets de longueur, puis le contenu."""
        length = self.read_int(length_bytes)
        return self.read(length)


def extract_sni(payload: bytes) -> str | None:
    """Extrait le nom d'hôte SNI d'un ClientHello TLS, ou ``None``.

    Args:
        payload: Octets applicatifs d'un segment TCP (charge au-dessus de TCP).

    Returns:
        Le nom de domaine annoncé dans l'extension ``server_name``, ou ``None``
        si le payload n'est pas un ClientHello, n'a pas de SNI, ou est tronqué.
    """
    reader = _Reader(payload)
    try:
        # Record TLS (RFC 8446 §5.1) : type(1) version(2) length(2).
        if reader.read_int(1) != _TLS_HANDSHAKE:
            return None
        reader.skip(2 + 2)  # legacy_record_version + record length (non utilisée)

        # En-tête handshake (RFC 8446 §4) : msg_type(1) length(3, uint24).
        if reader.read_int(1) != _CLIENT_HELLO:
            return None
        reader.skip(3)

        # Corps du ClientHello (RFC 8446 §4.1.2).
        reader.skip(_LEGACY_VERSION_LEN + _RANDOM_LEN)
        reader.read_vector(1)  # legacy_session_id
        reader.read_vector(2)  # cipher_suites
        reader.read_vector(1)  # legacy_compression_methods
        reader.skip(2)  # longueur déclarée du bloc d'extensions : on ne l'exige pas
        return _find_server_name(reader)
    except _Truncated:
        return None


def _find_server_name(reader: _Reader) -> str | None:
    """Parcourt les extensions (TLV) et retourne le SNI si présent.

    Tolère un bloc tronqué : un ClientHello de navigateur dépasse souvent le MSS
    et n'arrive qu'en partie (1er segment TCP), mais l'extension server_name vient
    tôt et reste généralement dans les octets capturés. On lit donc chaque
    extension sur ce qui est réellement disponible plutôt que d'exiger tout le bloc.
    """
    # Chaque extension : type(2) + data<longueur sur 2 octets> (RFC 8446 §4.2).
    while reader.remaining >= 4:
        ext_type = reader.read_int(2)
        ext_len = reader.read_int(2)
        available = min(ext_len, reader.remaining)  # borne à ce qu'on a réellement
        ext_data = reader.read(available)
        if ext_type == _EXT_SERVER_NAME:
            return _parse_server_name(ext_data)
        if available < ext_len:
            break  # extension coupée et ce n'est pas le SNI : impossible d'avancer
    return None


def _parse_server_name(ext_data: bytes) -> str | None:
    """Décode l'extension server_name → premier host_name (RFC 6066 §3)."""
    reader = _Reader(ext_data)
    reader.skip(2)  # ServerNameList length : on itère directement les entrées
    # Chaque entrée : name_type(1) + name<longueur sur 2 octets>.
    while reader.remaining >= 3:
        name_type = reader.read_int(1)
        name = reader.read_vector(2)
        if name_type == _NAME_TYPE_HOST:
            return _decode_hostname(name)
    return None


def _decode_hostname(raw: bytes) -> str | None:
    """Un SNI valide est en ASCII (les IDN sont encodés en punycode) ; sinon rejeté."""
    if not raw:
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None
