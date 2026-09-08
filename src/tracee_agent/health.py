"""Compteurs de santé du pipeline de capture.

Pourquoi ce module existe : un agent de capture peut échouer **en silence**. Il
tourne, consomme des paquets, envoie des events — et n'identifie plus rien parce
que la carte réseau a changé de comportement, que le lien n'est pas celui qu'on
croit ou que ``snaplen`` est devenu trop court. Rien dans le flux d'events ne le
dit : ils continuent d'arriver, simplement vides de sens.

On instrumente donc les endroits où le pipeline *perd* de l'information, et on
publie périodiquement le résultat. La métrique qui compte est le **taux
d'identification** : la part d'events porteurs d'un ``service_hint``. Un taux nul
alors que des ClientHello défilent est un diagnostic à lui seul.

Les compteurs sont **cumulés depuis le démarrage**, comme ceux du ``heartbeat`` :
un cumul se lit sans se demander sur quelle fenêtre il porte, et suffit à révéler
une panne franche. Ils vivent dans l'unique thread de la boucle asyncio (comme le
reste du pipeline, cf. ``capture/sniffer.py``) : aucun verrou n'est nécessaire.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

# En dessous, un taux d'identification n'est pas représentatif : sur une poignée
# d'events, tomber à 0 % ne veut rien dire (aucune connexion TLS n'a pu s'ouvrir).
# On ne juge donc la santé de l'identification qu'au-delà de ce seuil.
_MIN_EVENTS_FOR_RATE = 20


@dataclass(slots=True)
class PipelineHealth:
    """Ce que le pipeline a vu, et ce qu'il en a perdu.

    Attributes:
        packets_decoded: Paquets IP décodés avec succès.
        frames_ignored: Trames écartées au décodage (non-IP, ou octets aberrants).
            Un ratio proche de 100 % trahit un lien qui n'est pas Ethernet.
        frames_truncated: Trames rendues à la taille exacte de ``snaplen`` — donc
            probablement écrêtées. Beaucoup de troncatures = ``snaplen`` trop court,
            et des ClientHello incomplets.
        headers_offloaded: Paquets dont l'en-tête IP annonçait une longueur nulle
            (segmentation déléguée à la carte). Attendu et sans gravité depuis
            qu'on le gère ; utile pour reconnaître la machine à distance.
        client_hellos: Débuts de ClientHello TLS observés.
        services_identified: SNI extraits par le réassembleur.
        dns_answers: Messages DNS porteurs d'au moins une résolution.
        events: Events produits au flush.
        events_identified: Events partis avec un ``service_hint``.
    """

    packets_decoded: int = 0
    frames_ignored: int = 0
    frames_truncated: int = 0
    headers_offloaded: int = 0
    client_hellos: int = 0
    services_identified: int = 0
    dns_answers: int = 0
    events: int = 0
    events_identified: int = 0

    def identification_rate(self) -> float | None:
        """Part d'events porteurs d'un ``service_hint``, en pourcentage.

        Returns:
            Le taux arrondi au dixième, ou ``None`` tant que l'échantillon est trop
            mince pour qu'il veuille dire quelque chose.
        """
        if self.events < _MIN_EVENTS_FOR_RATE:
            return None
        return round(100 * self.events_identified / self.events, 1)

    def report(self, *, dns_cache_size: int) -> dict[str, object]:
        """Instantané destiné au log, taux d'identification compris.

        Args:
            dns_cache_size: Nombre d'associations IP → domaine apprises. Détenu par
                l'identification, pas par ce compteur : on le reçoit au moment du
                rapport plutôt que d'en tenir un double qui pourrait diverger.
        """
        return {
            **asdict(self),
            "dns_cache": dns_cache_size,
            "identification_rate": self.identification_rate(),
        }
