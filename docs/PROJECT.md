# Tracee Agent — Documentation

Documentation technique du composant agent de Tracee.

Pour le **contexte global du projet** (vision, architecture complète, décisions business), voir [tracee/docs/PROJECT.md](https://github.com/lucasmaiaux/tracee/blob/main/docs/PROJECT.md) dans le repo principal.

Pour le **protocole de communication** entre l'agent et le serveur, voir [tracee/docs/PROTOCOL.md](https://github.com/lucasmaiaux/tracee/blob/main/docs/PROTOCOL.md).

---

## Rôle de l'agent

L'agent Tracee est le composant client installé sur les machines à observer. Il :

1. Capture le trafic réseau sur les interfaces sélectionnées
2. Parse les paquets pour extraire les métadonnées utiles
3. Identifie localement les services contactés (SNI, DNS, reverse DNS, ASN)
4. Transmet les événements normalisés au serveur via WebSocket
5. Gère la reconnexion et le buffer local en cas de perte de connexion

L'agent fonctionne **en lecture seule** : aucune injection de trafic, aucune modification de paquet.

---

## Architecture interne

```
┌──────────────────────────────────────────┐
│  Tracee Agent                            │
│                                          │
│  ┌────────────┐    ┌────────────┐        │
│  │  Capture   │───►│  Parser    │        │
│  │  (Scapy)   │    │  (TLS, DNS,│        │
│  │            │    │   etc.)    │        │
│  └────────────┘    └─────┬──────┘        │
│                          │               │
│                          ▼               │
│                  ┌──────────────┐        │
│                  │  Identifier  │        │
│                  │  - SNI       │        │
│                  │  - DNS cache │        │
│                  │  - Reverse   │        │
│                  │  - ASN       │        │
│                  └──────┬───────┘        │
│                         │                │
│                         ▼                │
│                  ┌──────────────┐        │
│                  │  Transport   │        │
│                  │  (WebSocket) │        │
│                  └──────┬───────┘        │
└─────────────────────────┼────────────────┘
                          │
                          ▼
                  Serveur Tracee
```

### Modules

- **`capture/`** : interface avec Scapy pour la capture brute
- **`parser/`** : décodage des protocoles (Ethernet, IP, TCP, UDP, TLS handshake, DNS)
- **`identifier/`** : techniques d'identification de services
- **`transport/`** : client WebSocket avec reconnexion et buffer
- **`config/`** : chargement et validation de la configuration

---

## Techniques d'identification de services

L'agent applique les techniques dans cet ordre de précision décroissante :

1. **SNI TLS** : extraction du Server Name Indication dans le ClientHello (couverture ~90% HTTPS)
2. **Cache DNS observé** : mapping IP→domaine construit en observant les requêtes DNS
3. **Reverse DNS** : requête PTR pour les IPs sans match précédent
4. **ASN MaxMind** : base locale pour identifier l'organisation propriétaire de l'IP

Voir le PROJECT.md du repo serveur pour le détail des couvertures et limitations.

---

## Stack technique

| Composant | Technologie | Justification |
|-----------|-------------|---------------|
| Capture | Scapy | Standard Python pour capture/parsing |
| Async I/O | asyncio | Standard moderne pour async Python |
| WebSocket | websockets | Bibliothèque async maintenue |
| Configuration | PyYAML + Pydantic | Parsing YAML + validation typée |
| Géo / ASN | maxminddb | Lecture des bases MaxMind |
| Logging | structlog | Logs structurés, modernes |
| Tests | pytest + scapy | Tests unitaires sur PCAP de référence |
| Packaging | pyinstaller, fpm | Build multi-plateformes |

---

## Compatibilité de version

L'agent et le serveur sont versionnés indépendamment, avec un **protocole versionné** pour assurer la compatibilité.

| Version agent | Versions serveur compatibles | Notes |
|---------------|------------------------------|-------|
| 1.0.x         | 1.0.x                        | Version initiale |

Voir [PROTOCOL.md](https://github.com/lucasmaiaux/tracee/blob/main/docs/PROTOCOL.md) pour les détails du contrat.

---

## Plateformes supportées

L'agent est écrit en Python pur et fonctionne sur :

- **Linux** : Debian/Ubuntu, Fedora, Arch
- **macOS** : Intel et Apple Silicon
- **Windows** : 10 et 11

La capture nécessite des privilèges élevés sur toutes les plateformes (root sur Linux, admin sur Windows).

### Distribution

Les releases GitHub fournissent :

- **Linux** : paquets `.deb` (Debian/Ubuntu) et `.rpm` (Fedora/RHEL)
- **macOS** : paquet `.pkg`
- **Windows** : exécutable `.exe` (PyInstaller)
- **Python** : paquet pip pour installation depuis sources

---

## Sécurité

### Authentification

- Token machine-to-machine généré côté serveur
- Stocké dans le fichier de config local de l'agent
- Transmis via header `Authorization: Bearer` à l'ouverture de la WebSocket
- Connexion uniquement en WSS (TLS)

### Données capturées

L'agent ne stocke et ne transmet **que des métadonnées** :

- IPs source/destination, ports, protocole, tailles, timing
- SNI extrait des handshakes TLS (visible en clair par conception)
- Domaines observés dans les requêtes DNS en clair

L'agent ne capture **pas** :

- Contenu des communications HTTPS (chiffré)
- Contenu HTTP en clair (sauf en mode "raw capture" optionnel, désactivé par défaut)
- Mots de passe, cookies, tokens

### Mode raw capture (optionnel)

L'agent peut être configuré pour capturer aussi le contenu brut (PCAP) pour analyse approfondie. Ce mode :

- Est **désactivé par défaut**
- Doit être activé explicitement par l'utilisateur
- Stocke localement, ne transmet jamais le contenu au serveur sans demande explicite

---

## Considérations légales

L'utilisation de l'agent est légale uniquement sur :

- Votre propre réseau et vos propres appareils
- Un réseau pour lequel vous avez une autorisation explicite d'audit

L'utilisation à des fins de surveillance non consentie est interdite par la loi dans la plupart des juridictions.

---

## Roadmap

### v1.0 — Version initiale (Projet Libre 2026)

- Capture sur interfaces réseau via Scapy
- Parsing Ethernet, IP, TCP, UDP, TLS ClientHello, DNS
- Identification via SNI, DNS cache, reverse DNS, ASN
- Transport WebSocket avec reconnexion et buffer
- Configuration YAML
- Tests sur fixtures PCAP

### Évolutions possibles (post-projet école)

- Support de QUIC / HTTP/3
- Intégration optionnelle de nfstream pour DPI avancé
- Détection d'anomalies via patterns statistiques
- Interface web locale pour configuration sans toucher au YAML
- Plugin system pour ajouter des protocoles custom
