from scapy.all import sniff

print("En attente d'UN paquet HTTPS… génère du trafic (ouvre un site).")
pkts = sniff(count=1, filter="tcp port 443", timeout=20)
pkts[0].show()
