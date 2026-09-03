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

Pour **utiliser** l'agent :

- **Privilèges d'administration** : ouvrir un socket de capture est une opération privilégiée — root sous Linux, administrateur sous Windows. Sous Windows, l'exécutable demande l'élévation de lui-même au lancement ; sous Linux, voir `setcap` ci-dessous.
- **[Npcap](https://npcap.com/) sous Windows** : le pilote de capture. Sa licence interdit de l'embarquer dans l'exécutable, il s'installe donc séparément. Sans lui, la capture échoue quels que soient les privilèges.
- **Un token d'agent**, généré sur la page Agents du serveur Tracee. Il n'existe pas avant : c'est pourquoi l'agent embarque un écran de configuration.

Aucun Python n'est requis : l'exécutable est autonome.

Pour **développer** :

- **Python 3.12+** et [uv](https://docs.astral.sh/uv/)
- **`python3-tk`** sous Debian/Ubuntu (`sudo apt install python3-tk`) : Tkinter dépend d'un paquet système séparé. Prérequis de développement uniquement — PyInstaller embarque Tcl/Tk dans l'exécutable.

## Installation

### Exécutable autonome (recommandé)

Télécharger le binaire de sa plateforme depuis les [Releases](https://github.com/lucasmaiaux/tracee-agent/releases), puis le placer dans un **dossier accessible en écriture** — Bureau ou Téléchargements. L'agent y écrit sa configuration ; un dossier protégé comme `C:\Program Files` ne conviendrait pas.

```bash
# Linux
chmod +x tracee-agent-linux-x86_64
sudo ./tracee-agent-linux-x86_64
```

Sous Windows, **double-cliquer** sur `tracee-agent-windows-x86_64.exe` : l'exécutable réclame lui-même l'élévation, Windows demande confirmation, et c'est tout. Aucune console ne s'ouvre — c'est une application graphique.

Les deux commandes Linux ne se font qu'**une fois par fichier téléchargé**. `chmod` parce qu'un fichier attaché à une release perd son bit exécutable en chemin ; `setcap` parce que le noyau refuse un socket de capture à un processus ordinaire — c'est une protection du système, qu'aucune application ne peut contourner d'elle-même. Wireshark impose la même chose. Le seul autre chemin est de préfixer chaque lancement par `sudo`.

### Depuis les sources

```bash
git clone https://github.com/lucasmaiaux/tracee-agent.git
cd tracee-agent
uv sync
make gui          # écran de configuration
make build-exe    # construire l'exécutable de la plateforme courante
```

## Configuration

Lancé **sans argument**, l'agent ouvre son écran de configuration : coller le token, choisir l'interface, Démarrer. La configuration est enregistrée au premier démarrage et pré-remplie aux lancements suivants.

L'URL du serveur n'y est pas saisissable — l'agent ne parle qu'au serveur Tracee, et l'adresse par défaut est intégrée. Elle reste modifiable dans le YAML pour un autre déploiement.

### Où vit le `config.yaml`

| Mode d'exécution | Emplacement |
|---|---|
| Exécutable autonome | **à côté du binaire** |
| Sources (`uv run`, `make`) | répertoire de travail courant |

À côté de l'exécutable, et non dans `~/.config` : sous `sudo`, `HOME` devient `/root`, et un fichier rangé dans le `~` de l'utilisateur ne serait pas relu par l'agent lancé en privilégié. Le fichier est aussi visible et supprimable, pour repartir de zéro.

⚠️ Il contient le token d'agent en clair : ne pas le partager ni le committer (il est gitignoré).

### Journalisation

L'agent lancé par son écran de configuration est **silencieux** : rien dans le terminal d'où on l'a lancé, aucune console sous Windows, aucun fichier de journal. Les pannes sur lesquelles on peut agir — token refusé, capture impossible, privilèges manquants — sont annoncées dans la fenêtre ; le reste (paquets décodés, services identifiés) relève du développement.

Deux façons de retrouver la parole :

```bash
tracee-agent --verbose        # l'écran s'ouvre, et les logs reviennent dans le terminal
```

ou renseigner `logging.file` dans le `config.yaml`, avec un chemin dont le répertoire existe déjà.

### Deux profils

| Profil | Fichier | Usage |
|---|---|---|
| Normal | `config.yaml` | serveur Tracee |
| Mise au point | `config.local.yaml` | backend lancé en local |

La case **« Profil de mise au point »** bascule de l'un à l'autre. Ils sont séparés parce que leurs tokens diffèrent : un agent déclaré sur le backend local n'est pas celui du serveur distant.

Pour un usage en ligne de commande, partir de `config.example.yaml`.

## Utilisation

### Écran de configuration

```bash
sudo ./tracee-agent-linux-x86_64     # sans argument
tracee-agent --gui                   # explicitement
```

### Ligne de commande

Le chemin de développement et d'usage serveur. `--gui` est incompatible avec ces options.

```bash
tracee-agent --list-interfaces                                  # ne demande aucun privilège
sudo tracee-agent --config config.yaml
sudo tracee-agent --config config.yaml --interface eth0
sudo tracee-agent --config config.yaml --pick-interface         # choix dans une liste
sudo tracee-agent --config config.yaml --verbose                # logs DEBUG
```

### Capturer sans `sudo` sous Linux

`sudo` n'est pas la seule voie : la capability `cap_net_raw` autorise un utilisateur ordinaire à ouvrir un socket de capture.

```bash
sudo setcap cap_net_raw,cap_net_admin+ep ./tracee-agent-linux-x86_64
./tracee-agent-linux-x86_64          # plus besoin de sudo
```

C'est la manière recommandée pour l'écran de configuration sous Linux : selon la session graphique, `sudo` peut perdre l'accès au serveur d'affichage et empêcher la fenêtre de s'ouvrir. À poser sur l'exécutable autonome uniquement — jamais sur l'interpréteur Python d'un venv, qui rendrait privilégié n'importe quel script.

### Démarrage automatique (Linux, systemd)

Pas encore fourni. En attendant, un service se déclare à la main en pointant l'exécutable et son `--config`.

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

Distribuées et testées :

- Linux (Debian, Ubuntu, Fedora, Arch)
- Windows 10/11 — [Npcap](https://npcap.com/) requis

macOS n'est pas une cible : aucun exécutable n'est publié et rien n'y est vérifié. Le code n'a pourtant rien de spécifique aux deux autres systèmes ; une installation depuis les sources a des chances de fonctionner, sans garantie.

## Développement

Voir [PROJECT.md](docs/PROJECT.md) pour le contexte technique et [PROTOCOL.md](https://github.com/lucasmaiaux/tracee/blob/main/docs/PROTOCOL.md) pour le protocole.

## Auteur

Lucas MAIAUX — [@lucasmaiaux](https://github.com/lucasmaiaux)

Projet réalisé dans le cadre du **Projet Libre 2026** — Campus Numérique in the Alps, formation Développeurs Avancés.

## Licence

MIT
