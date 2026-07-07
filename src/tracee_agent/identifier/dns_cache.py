"""Cache DNS observé : associe passivement une IP au domaine qui l'a résolue.

En écoutant les réponses DNS qui transitent en clair, on apprend des couples
``IP → domaine``. C'est la source d'identification n°2 (après le SNI) pour tout
le trafic dont on ne voit pas le nom de domaine autrement : une connexion vers
``93.184.216.34`` reste anonyme, mais si on a vu passer juste avant la résolution
``example.com → 93.184.216.34``, on peut l'étiqueter. Réf : ``docs/PROJECT.md``
§5 (Cache DNS observé).

Deux propriétés portées par cette structure :

* **Taille bornée** — l'agent tourne en continu (service, des jours) ; sans
  plafond, le cache grossirait indéfiniment. Un domaine derrière un CDN renvoie
  d'ailleurs une IP différente à presque chaque résolution : le nombre d'IP
  distinctes vues croît plus vite que le nombre de sites visités. On évince donc
  en LRU (*least recently used*) au-delà d'un plafond — un garde-fou mémoire,
  jamais atteint en usage normal.
* **Pas de verrou** — la capture Scapy tourne dans son thread, mais chaque
  paquet repasse par ``loop.call_soon_threadsafe`` vers la file asyncio ; tout
  le pipeline en aval (parser → ce cache → identification) s'exécute donc dans
  **l'unique thread de la boucle**. Alimentation et lookup ne sont jamais
  concurrents : aucun ``Lock`` n'est nécessaire (cf. ``capture/sniffer.py``).

On ne fait **pas** expirer les entrées sur le TTL DNS : dans une capture, une
résolution est suivie presque aussitôt de la connexion à l'IP, et une IP
ré-résolue vers un autre domaine **écrase** simplement l'ancienne association
(*dernier écrit gagnant*). Le TTL n'apporterait qu'une auto-guérison marginale,
pour un enjeu faible (une étiquette de flux), au prix de complexité.
"""

from __future__ import annotations

from collections import OrderedDict

from tracee_agent.parser.dns import DnsMessage

# Plafond d'entrées : au-delà, on évince la moins récemment utilisée. Une machine
# ordinaire contacte au plus quelques milliers d'IP distinctes ; 100 000 laisse
# une marge confortable tout en garantissant une borne mémoire dure (~quelques Mo).
_DEFAULT_MAX_ENTRIES = 100_000


class DnsCache:
    """Cache ``IP → domaine`` alimenté par les réponses DNS observées.

    Args:
        max_entries: Nombre maximal d'associations conservées ; au-delà, la
            moins récemment utilisée est évincée (> 0).
    """

    def __init__(self, *, max_entries: int = _DEFAULT_MAX_ENTRIES) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries doit être strictement positif.")
        self._entries: OrderedDict[str, str] = OrderedDict()
        self._max_entries = max_entries

    def observe(self, message: DnsMessage) -> None:
        """Alimente le cache avec les résolutions d'adresse d'un message DNS.

        Seules les réponses A/AAAA (déjà filtrées par le parseur) portent une IP.
        Une requête (``answers`` vide) n'a aucun effet.
        """
        for record in message.answers:
            self._store(record.ip, record.name)

    def lookup(self, ip: str) -> str | None:
        """Renvoie le domaine ayant résolu ``ip``, ou ``None`` si inconnu."""
        domain = self._entries.get(ip)
        if domain is None:
            return None
        self._entries.move_to_end(ip)  # accès récent → repousse l'éviction LRU
        return domain

    def _store(self, ip: str, domain: str) -> None:
        self._entries[ip] = domain
        self._entries.move_to_end(ip)  # dernière résolution gagnante et « fraîche »
        if len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)  # évince l'entrée la plus ancienne

    def __len__(self) -> int:
        """Nombre d'entrées actuellement stockées."""
        return len(self._entries)
