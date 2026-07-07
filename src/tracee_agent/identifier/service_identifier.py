"""Identification de service d'un flux : choisit le meilleur nom à lui coller.

Deux sources d'identification, par ordre de précision décroissante :

1. **SNI** — le nom de domaine visé, lu en clair dans le ClientHello TLS
   (premier paquet d'une connexion HTTPS). Le plus précis quand il existe.
2. **Cache DNS observé** (``DnsCache``, #13) — le domaine qui a résolu l'IP de
   destination, appris en écoutant les réponses DNS. Filet pour le trafic sans
   SNI.

Règle déterministe : **SNI > DNS > rien**. Réf : ``docs/PROJECT.md`` §5.

Le SNI et le DNS n'ont pas la même granularité, d'où ce composant :

* le **SNI** est propre à un **flux** (le 5-tuple d'une connexion) et n'apparaît
  qu'**une fois**, sur le ClientHello ; le réassembleur le retourne puis l'oublie.
  Pour que le SNI étiquette *toute* la connexion (pas juste son premier paquet),
  on le **mémorise** ici dans un carnet ``flux → domaine``.
* le **DNS** est propre à une **IP** de destination et vit déjà dans le cache.

Le carnet SNI est **borné** (éviction LRU), comme le cache DNS et le réassembleur :
pas de timer ni de suivi de fermeture TCP (coûteux et hors périmètre d'un agent
léger) — les vieilles entrées tombent d'elles-mêmes quand de nouvelles arrivent.
La purge précise à l'émission de l'event viendra avec le transport (#18).

Comme le reste du pipeline, ce composant tourne dans l'unique thread de la boucle
asyncio (cf. ``capture/sniffer.py``) : aucun verrou nécessaire.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Literal

from tracee_agent.identifier.dns_cache import DnsCache
from tracee_agent.parser.dns import DnsMessage
from tracee_agent.parser.tls_reassembly import FlowKey

# Plafond du carnet flux → SNI. Une machine a rarement plus de quelques centaines
# de connexions récentes ; 2048 laisse de la marge tout en bornant la mémoire.
_DEFAULT_MAX_FLOWS = 2048


@dataclass(frozen=True, slots=True)
class ServiceHint:
    """Meilleur nom identifié pour un flux, avec sa source.

    Se sérialise en ``{"type": source, "value": value}`` dans le message
    ``event`` du protocole (fait plus tard, à l'émission — #18).

    Attributes:
        source: Source ayant fourni le nom (``"sni"`` ou ``"dns"``).
        value: Nom de domaine identifié.
    """

    source: Literal["sni", "dns"]
    value: str


class ServiceIdentifier:
    """Combine SNI et cache DNS observé pour étiqueter un flux (SNI > DNS).

    Args:
        max_flows: Nombre maximal de SNI mémorisés ; au-delà, le flux le moins
            récemment vu est évincé (> 0).
    """

    def __init__(self, *, max_flows: int = _DEFAULT_MAX_FLOWS) -> None:
        if max_flows <= 0:
            raise ValueError("max_flows doit être strictement positif.")
        self._dns_cache = DnsCache()
        self._sni_by_flow: OrderedDict[FlowKey, str] = OrderedDict()
        self._max_flows = max_flows

    def observe_dns(self, message: DnsMessage) -> None:
        """Alimente le cache DNS avec les résolutions d'un message DNS observé."""
        self._dns_cache.observe(message)

    def observe_sni(self, flow: FlowKey, domain: str) -> None:
        """Mémorise le SNI d'un flux (vu une fois, réutilisé pour toute la connexion)."""
        self._sni_by_flow[flow] = domain
        self._sni_by_flow.move_to_end(flow)  # flux récent → repousse l'éviction LRU
        if len(self._sni_by_flow) > self._max_flows:
            self._sni_by_flow.popitem(last=False)  # évince le flux le plus ancien

    def resolve(self, flow: FlowKey) -> ServiceHint | None:
        """Renvoie le meilleur nom pour ``flow`` selon la priorité SNI > DNS.

        Le SNI mémorisé pour ce flux l'emporte ; à défaut, on interroge le cache
        DNS sur l'IP de destination ; sinon aucune source n'identifie le flux.
        """
        sni = self._sni_by_flow.get(flow)
        if sni is not None:
            self._sni_by_flow.move_to_end(flow)  # accès récent → repousse l'éviction
            return ServiceHint(source="sni", value=sni)

        dest_ip = flow[2]  # FlowKey = (ip_src, port_src, ip_dst, port_dst)
        domain = self._dns_cache.lookup(dest_ip)
        if domain is not None:
            return ServiceHint(source="dns", value=domain)

        return None
