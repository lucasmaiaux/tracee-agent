"""Exploration pédagogique : la compression de noms DNS, décodée À LA MAIN.

Ce script n'est PAS du code de prod (il vit dans scripts_temp/). Son seul but :
te faire *voir* comment un message DNS range ses noms de domaine, et surtout
l'astuce de compression (RFC 1035 §4.1.4) que Scapy nous cachera ensuite.

On construit une réponse DNS pour www.example.com → 93.184.216.34, on l'affiche
octet par octet, on la décode à la main, puis on regarde ce que Scapy en fait.

Lancer :  .venv/bin/python scripts_temp/explore_dns.py
"""

# ─────────────────────────────────────────────────────────────────────────────
# 1. On forge un message DNS de RÉPONSE, à la main, octet par octet.
#    Une réponse contient le même nom deux fois (la question, puis la réponse) :
#    c'est exactement là que la compression entre en jeu.
# ─────────────────────────────────────────────────────────────────────────────

header = bytes(
    [
        0x12,
        0x34,  # ID (identifiant de la transaction, choisi par le client)
        0x81,
        0x80,  # Flags : réponse standard, sans erreur
        0x00,
        0x01,  # QDCOUNT = 1  → 1 question
        0x00,
        0x01,  # ANCOUNT = 1  → 1 réponse
        0x00,
        0x00,  # NSCOUNT = 0
        0x00,
        0x00,  # ARCOUNT = 0
    ]
)  # 12 octets, offsets 0..11

# La QUESTION commence donc à l'offset 12.
# Un nom = suite de labels « longueur + octets », terminée par un 0x00.
qname = b"\x03www\x07example\x03com\x00"  # 17 octets, offsets 12..28
question = qname + bytes([0x00, 0x01, 0x00, 0x01])  # QTYPE=A(1), QCLASS=IN(1)

# La RÉPONSE (Answer). Ici la COMPRESSION :
# au lieu de réécrire "www.example.com", on met un POINTEUR vers l'offset 12
# (là où le nom est déjà écrit, dans la question).
# Un pointeur = 2 octets dont les 2 bits de poids fort valent 11 :
#   0xC0 0x0C = 1100_0000 0000_1100  → les 14 bits bas = 0x000C = 12.
POINTER_TO_QNAME = bytes([0xC0, 0x0C])
answer = (
    POINTER_TO_QNAME
    + bytes([0x00, 0x01])  # TYPE = A
    + bytes([0x00, 0x01])  # CLASS = IN
    + bytes([0x00, 0x00, 0x02, 0x58])  # TTL = 600 s
    + bytes([0x00, 0x04])  # RDLENGTH = 4 octets
    + bytes([93, 184, 216, 34])  # RDATA = 93.184.216.34
)

message = header + question + answer


# ─────────────────────────────────────────────────────────────────────────────
# 2. Affichage : on voit les octets, zone par zone.
# ─────────────────────────────────────────────────────────────────────────────
def dump(label: str, start: int, end: int) -> None:
    chunk = message[start:end]
    hexa = " ".join(f"{b:02x}" for b in chunk)
    print(f"  offset {start:>2}..{end - 1:<2}  {label:<22} {hexa}")


print("=" * 78)
print("MESSAGE DNS COMPLET (", len(message), "octets )")
print("=" * 78)
dump("En-tête", 0, 12)
dump("Question : QNAME", 12, 29)
dump("Question : QTYPE+QCLASS", 29, 33)
dump("Answer : NAME (pointeur!)", 33, 35)
dump("Answer : TYPE+CLASS+TTL", 35, 43)
dump("Answer : RDLENGTH+RDATA", 43, 49)
print()
print("  Remarque : le nom 'www.example.com' (17 octets) n'est écrit QU'UNE fois,")
print("  à l'offset 12. Dans l'Answer il est remplacé par 2 octets : C0 0C.")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Décodage d'un nom À LA MAIN, avec suivi des pointeurs et anti-boucle.
#    Renvoie (nom, offset_juste_après_le_nom_dans_le_flux_principal).
# ─────────────────────────────────────────────────────────────────────────────
def read_name(msg: bytes, offset: int, *, verbose: bool = False) -> tuple[str, int]:
    labels: list[str] = []
    seen_pointers: set[int] = set()  # garde-fou anti-boucle
    end_after_name = None  # offset de retour : figé au 1er pointeur suivi

    while True:
        length = msg[offset]

        # Cas 1 : octet 0x00 → fin du nom.
        if length == 0:
            if verbose:
                print(f"    offset {offset:>2} : 00 → fin du nom")
            offset += 1
            break

        # Cas 2 : les 2 bits de poids fort valent 11 → c'est un POINTEUR.
        if length & 0xC0 == 0xC0:
            # 14 bits bas = offset cible (on enlève les 2 bits de marquage).
            target = ((length & 0x3F) << 8) | msg[offset + 1]
            if verbose:
                print(
                    f"    offset {offset:>2} : {length:02x} {msg[offset + 1]:02x} "
                    f"→ POINTEUR vers offset {target}"
                )
            if target in seen_pointers:
                raise ValueError(f"pointeur cyclique détecté (offset {target})")
            seen_pointers.add(target)
            # Le nom « continue » à la cible ; mais dans le flux principal, le nom
            # s'arrête juste après les 2 octets du pointeur.
            if end_after_name is None:
                end_after_name = offset + 2
            offset = target
            continue

        # Cas 3 : label normal → longueur + N octets ASCII.
        label = msg[offset + 1 : offset + 1 + length].decode("ascii")
        if verbose:
            print(f"    offset {offset:>2} : {length:02x} → label '{label}' ({length} octets)")
        labels.append(label)
        offset += 1 + length

    if end_after_name is None:  # aucun pointeur suivi : le nom finit ici même
        end_after_name = offset
    return ".".join(labels), end_after_name


print()
print("=" * 78)
print("DÉCODAGE À LA MAIN")
print("=" * 78)

print("\n[Question] nom à l'offset 12 — écrit en entier, pas de pointeur :")
q_name, after_q = read_name(message, 12, verbose=True)
print(f"  → nom = '{q_name}'")

print("\n[Answer] nom à l'offset 33 — un pointeur qui renvoie dans la question :")
a_name, _ = read_name(message, 33, verbose=True)
print(f"  → nom = '{a_name}'  (reconstitué en sautant à l'offset 12)")

ip = ".".join(str(b) for b in message[45:49])
print(f"\n  RDATA (les 4 octets de fin) = {ip}")
print(f"  Bilan : {a_name} → {ip}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Le piège : un pointeur qui pointe sur lui-même = boucle infinie.
#    Notre garde-fou (seen_pointers) doit couper proprement.
# ─────────────────────────────────────────────────────────────────────────────
print()
print("=" * 78)
print("LE PIÈGE : pointeur cyclique")
print("=" * 78)
# En-tête bidon (12 octets) puis, à l'offset 12, un pointeur vers 12 (soi-même).
piege = header + bytes([0xC0, 0x0C])
try:
    read_name(piege, 12, verbose=True)
except ValueError as exc:
    print(f"  ✋ coupé net : {exc}")
    print("  Sans ce garde-fou, un parseur naïf tournerait à l'infini.")


# ─────────────────────────────────────────────────────────────────────────────
# 5. La même chose avec Scapy : tout ce qu'on vient de faire à la main est
#    fait pour nous. C'est CE service qu'on utilisera en prod.
# ─────────────────────────────────────────────────────────────────────────────
print()
print("=" * 78)
print("CE QUE SCAPY EN FAIT (sans qu'on décode rien)")
print("=" * 78)
from scapy.layers.dns import DNS  # noqa: E402 — import tardif, script exploratoire

dns = DNS(message)
print(f"  question  : {dns.qd[0].qname.decode()}")
print(f"  réponse   : {dns.an[0].rrname.decode()} → {dns.an[0].rdata}")
print("\n  Scapy a résolu le pointeur tout seul : c'est pour ça qu'on l'utilise.")
