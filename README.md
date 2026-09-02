# Tracee Agent

> Agent de capture réseau pour Tracee.

Composant client de [Tracee](https://github.com/lucasmaiaux/tracee). À installer sur les machines dont vous souhaitez observer le trafic réseau. L'agent capture passivement le trafic des interfaces réseau sélectionnées, l'analyse localement, et transmet les événements au serveur Tracee via une connexion sécurisée.

**Le serveur (backend + frontend) est dans un repo séparé : [tracee](https://github.com/lucasmaiaux/tracee).**

## Architecture

```
┌────────────────────────────┐
│  Votre machine             │
│  ┌──────────────────────┐  │
│  │  tracee-agent        │  │
│  │  - Capture (Scapy)   │  │
│  │  - Parsing local     │  │
│  │  - Identification    │  │
│  │    (DNS, SNI, ASN)   │  │
│  └──────────┬───────────┘  │
└─────────────┼──────────────┘
              │
        WebSocket (WSS)
              │
              ▼
   ┌────────────────────┐
   │  Serveur Tracee    │
   │  Voir le repo:     │
   │  github.com/       │
   │  lucasmaiaux/      │
   │  tracee            │
   └────────────────────┘
```

## Prérequis

- **Python 3.12+**
- **Privilèges réseau** : la capture nécessite des droits élevés (root sur Linux, admin sur Windows, ou setuid)
- **Compte Tracee** sur le serveur, avec un agent enregistré (récupérez le token depuis le dashboard)

## Installation

### Depuis les sources

```bash
git clone https://github.com/lucasmaiaux/tracee-agent.git
cd tracee-agent
pip install -e .
```

### Configuration

Créez un fichier `config.yaml` dans le répertoire de l'agent :

```yaml
server:
  url: "wss://api.tracee.example.com/ws/agent"
  token: "votre-token-agent-ici"

capture:
  default_interface: "wlan0"
  snaplen: 512

logging:
  level: "INFO"
  file: null   # stderr ; pour écrire dans un fichier, donnez un chemin dont le
               # répertoire existe déjà (ex. /var/log/tracee-agent.log)
```

Le token est généré depuis le dashboard Tracee : Settings → Agents → Create Agent.

## Utilisation

### Lancement basique

```bash
# Linux/Mac (nécessite root pour la capture)
sudo tracee-agent --config config.yaml

# Windows (lancer un terminal en administrateur)
tracee-agent --config config.yaml
```

### Sélection d'interface

```bash
sudo tracee-agent --config config.yaml --interface eth0
```

### Mode verbose

```bash
sudo tracee-agent --config config.yaml --verbose
```

### Démarrage automatique (Linux, systemd)

Un fichier de service est fourni dans `packaging/systemd/tracee-agent.service`. Adapter le chemin et activer :

```bash
sudo cp packaging/systemd/tracee-agent.service /etc/systemd/system/
sudo systemctl enable tracee-agent
sudo systemctl start tracee-agent
```

## Sécurité et vie privée

L'agent fonctionne en **lecture seule** sur les interfaces réseau. Il n'injecte aucun trafic, ne modifie rien, ne stocke aucun contenu utilisateur.

Ce qu'il observe :
- Métadonnées des paquets (IPs, ports, tailles, timing)
- SNI dans les handshakes TLS (en clair par conception du protocole)
- Requêtes DNS en clair (le DNS chiffré DoH/DoT n'est pas observable)

Ce qu'il **n'observe pas** :
- Contenu des communications chiffrées (HTTPS)
- Mots de passe, cookies, tokens
- Contenus de pages web ou de messages

## Compatibilité

| Version agent | Version serveur compatible |
|---------------|----------------------------|
| 1.0.x         | 1.0.x                      |

Voir la matrice détaillée dans le repo serveur : [tracee/docs/PROTOCOL.md](https://github.com/lucasmaiaux/tracee/blob/main/docs/PROTOCOL.md).

## Légalité

La capture réseau est légale uniquement sur **votre propre réseau et vos propres appareils**. N'installez pas cet agent sur des machines ou réseaux que vous n'êtes pas autorisé à observer.

## Plateformes supportées

- Linux (Debian, Ubuntu, Fedora, Arch)
- macOS (Intel et Apple Silicon)
- Windows 10/11

## Développement

Voir [PROJECT.md](docs/PROJECT.md) pour le contexte technique et [PROTOCOL.md](https://github.com/lucasmaiaux/tracee/blob/main/docs/PROTOCOL.md) pour le protocole.

## Auteur

Lucas MAIAUX — [@lucasmaiaux](https://github.com/lucasmaiaux)

Projet réalisé dans le cadre du **Projet Libre 2026** — Campus Numérique in the Alps, formation Développeurs Avancés.

## Licence

MIT
