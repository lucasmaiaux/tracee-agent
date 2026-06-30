from scapy.all import sniff, IP, TCP, Raw


def parse_sni(data: bytes) -> str | None:
    """Extrait le SNI d'un ClientHello TLS depuis les octets bruts."""
    if len(data) < 6 or data[0] != 0x16:      # 0x16 = record Handshake
        return None
    if data[5] != 0x01:                        # 0x01 = ClientHello
        return None

    pos = 9                                     # saute handshake_type(1)+len(3)
    pos += 2 + 32                               # client_version(2) + random(32)
    pos += 1 + data[pos]                        # session_id : len(1) + contenu
    pos += 2 + int.from_bytes(data[pos:pos+2], "big")   # cipher_suites
    pos += 1 + data[pos]                        # compression_methods

    ext_total = int.from_bytes(data[pos:pos+2], "big")  # longueur des extensions
    pos += 2
    end = pos + ext_total

    while pos + 4 <= end:                       # parcours des extensions (TLV)
        ext_type = int.from_bytes(data[pos:pos+2], "big")
        ext_len = int.from_bytes(data[pos+2:pos+4], "big")
        ext_data = data[pos+4:pos+4+ext_len]
        pos += 4 + ext_len
        if ext_type == 0x0000:                  # extension SNI
            name_len = int.from_bytes(ext_data[3:5], "big")
            return ext_data[5:5+name_len].decode("ascii", "replace")
    return None


def on_packet(pkt):
    if Raw not in pkt or TCP not in pkt:
        return
    try:
        sni = parse_sni(bytes(pkt[Raw].load))
    except (IndexError, UnicodeDecodeError):
        return                                  # paquet tronqué/fragmenté : on ignore
    if sni:
        print(f"🔓 SNI = {sni}   → {pkt[IP].dst}")


print("En attente d'un ClientHello… ouvre un NOUVEAU site HTTPS.")
sniff(filter="tcp port 443", prn=on_packet, timeout=60)
print("Terminé.")
