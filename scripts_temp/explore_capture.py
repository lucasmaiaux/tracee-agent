from scapy.all import sniff


def on_packet(pkt):

    # """Appelée pour chaque paquet capturé."""
    # print("─" * 60)
    # print(pkt.summary())  # vue condensée : les couches d'un coup d'œil

    # On pèle quelques couches de l'oignon, si elles sont là :
    # if IP in pkt:
    #     print(f"  L3  IP  : {pkt[IP].src}  →  {pkt[IP].dst}")
    # if TCP in pkt:
    #     print(f"  L4  TCP : port {pkt[TCP].sport}  →  {pkt[TCP].dport}")
    # elif UDP in pkt:
    #     print(f"  L4  UDP : port {pkt[UDP].sport}  →  {pkt[UDP].dport}")

    print(
        pkt.sprintf(
            "{IP:%IP.src% > %IP.dst% (%IP.proto%, ttl=%IP.ttl%, len=%IP.len%)}\t"
            "{TCP: | TCP %TCP.sport%→%TCP.dport% [%TCP.flags%]}"
            "{UDP: | UDP %UDP.sport%→%UDP.dport%}"
            "\t{Raw: | +payload}"
        )
    )


print("Capture de 10 paquets (ou 20s max). Génère du trafic : ouvre un site web…")
sniff(count=100, timeout=20, filter="ip", prn=on_packet)
print("Terminé.")
