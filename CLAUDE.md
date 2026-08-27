# Tracee Agent — Instructions pour Claude Code

## Contexte du projet

Ce repo contient l'**agent de capture** de Tracee. C'est le composant client installé sur les machines des utilisateurs pour capturer et analyser leur trafic réseau, puis l'envoyer au serveur.

Le serveur (backend + frontend) est dans un repo séparé : `tracee` (probablement dans `../tracee/` en local).

**Document de référence pour le protocole de communication** : voir `../tracee/docs/PROTOCOL.md`. Le contrat agent ↔ serveur y est défini, toute modification doit y être documentée.

Stack : Python 3.12+, Scapy, websockets, asyncio.

## Structure du repo

```
tracee-agent/
├── src/
│   ├── capture/        # Capture Scapy par interface
│   ├── parser/         # Parsing protocoles (Ethernet, IP, TCP, UDP, TLS, DNS)
│   ├── identifier/     # Identification de services (SNI, DNS cache, reverse DNS, ASN)
│   ├── transport/      # Client WebSocket vers le serveur
│   ├── config/         # Chargement et validation de la config
│   └── main.py
├── tests/
│   └── fixtures/       # Captures PCAP de test
├── docs/
├── packaging/          # Scripts de build pour distribution (deb, rpm, exe, pkg)
└── .github/workflows/
```

## Conventions de code

### Python

- Python 3.12+ avec type hints stricts partout
- Lint + formatage : Ruff (`ruff check` + `ruff format`, compatible Black ; remplace aussi isort)
- Docstrings format Google
- Async/await pour le réseau et le WebSocket
- Pas de print, utiliser logging
- Variables nommées en clair, pas d'abréviations cryptiques

### Git

Convention de commits : **référence à l'issue en préfixe, style CPython** (pas de préfixe de type `feat:`/`fix:`).

Format du titre (commit ET titre de PR) :

```
gh-<numéro_issue>: <description courte>
```

Exemples :

```
gh-8: implement TLS SNI parser
gh-13: handle reconnection backoff
gh-9: add SNI parser tests with PCAP fixtures
gh-27: pin scapy to 2.5.x
```

Workflow Git (squash) :

- Une fonctionnalité = une branche = une PR = **un commit squashé** sur `main`.
- Nom de branche : `<numéro_issue>-<description-kebab>`, **sans préfixe de type** (ex: `8-sni-parser`, `13-reconnection`).
- Les commits de travail sur la branche n'ont pas d'importance (jetés au squash) : seuls le **titre + la description de la PR** deviennent le message final.
- `Closes #N` (ou `Fixes #N`) dans la **description de la PR** → ferme l'issue automatiquement. ⚠️ Le préfixe `gh-N:` ne ferme rien tout seul.
- **Squash and merge** : GitHub ajoute automatiquement `(#numéro_PR)` à la fin du titre → commit final `gh-8: implement TLS SNI parser (#42)`. Le `(#N)` final est donc le n° de **PR**, pas de l'issue.
- Réglage repo (une fois) : `Settings → Pull Requests → Default commit message = « Pull request title and description »` + auto-delete des branches.

### Versioning

L'agent suit **semver** strict :
- `MAJOR.MINOR.PATCH`
- Breaking change protocole → MAJOR
- Nouvelle feature compatible → MINOR
- Bugfix → PATCH

Les versions sont taggées sur Git (`v1.0.0`) et releasées sur GitHub. Le choix du segment à incrémenter est **manuel** (décidé au moment de la release, pas dérivé automatiquement des messages de commit — on n'utilise pas de préfixe de type).

### Tests

- Pytest avec fixtures PCAP pour valider le parsing
- Couverture prioritaire :
  - Parser TLS (extraction SNI)
  - Parser DNS (cache observationnel)
  - Reconnexion WebSocket
  - Authentification au serveur

## Commandes courantes

```bash
make dev          # Lancer l'agent en mode dev avec capture sur loopback ou interface configurée
make test         # Tests pytest
make lint         # Ruff check + format --check (ne modifie rien)
make format       # Ruff format + check --fix (corrige en place)
make build-deb    # Construire le paquet .deb
make build-exe    # Construire l'exécutable Windows
make release      # Release multi-plateformes (utilisé en CI)
```

## Protocole de communication avec le serveur

**Lecture indispensable** : `../tracee/docs/PROTOCOL.md`

Tout changement dans le format des messages envoyés/reçus doit :
1. Être documenté dans PROTOCOL.md du repo serveur
2. Respecter le versioning sémantique du protocole
3. Être discuté avec moi avant implémentation

## Préférences de travail

### Communication

- Réponds-moi toujours en français
- Sois honnête, pas flatteur
- Challenge mes choix si tu vois mieux, justifie tes recommandations
- Va à l'essentiel, évite le blabla
- Si tu as un doute sur ce que je veux, demande plutôt que de supposer

### Code

- Préférer la simplicité à l'astuce
- Pas de commentaires qui paraphrasent le code, seulement ceux qui expliquent le pourquoi
- Réutiliser le code existant avant d'en créer
- Si une fonction dépasse 50 lignes, probablement à découper

### Workflow

- Avant de coder un truc complexe (notamment parser), m'expliquer l'approche
- Toujours créer un test pour une nouvelle fonction de parsing
- Si une modif touche plusieurs fichiers, lister les changements avant

### Apprentissage (important pour ce repo)

Mon objectif principal sur ce repo : **maîtriser en profondeur le parsing réseau**. Donc :

- Explique-moi le **pourquoi** technique de chaque étape de parsing, pas juste le comment
- Quand on parse TLS, DNS, ou autre protocole, fais-moi comprendre la structure binaire
- Cite les RFC pertinentes si utile (RFC 1035 DNS, RFC 8446 TLS 1.3, etc.)
- Pas peur d'aller dans le détail technique
- **Scapy est l'outil de base assumé** : on l'utilise pour la capture brute ET pour disséquer tout protocole qu'il gère bien, applicatif compris (ex : DNS via `scapy.layers.dns`). L'objectif d'apprentissage est de **maîtriser Scapy**, pas de réécrire des décodeurs qui existent déjà.
- **Parsing à la main uniquement quand Scapy est faible ou absent** : ex. le SNI dans un ClientHello TLS souvent tronqué (snaplen) et réassemblé sur plusieurs segments — cas que Scapy ne gère pas, d'où `parser/tls.py` écrit à la main.
- **Pas de lib DPI/résolution « clé en main »** (nDPI, nfstream, dnspython…) : ni pour le parsing, ni pour l'identification. Scapy reste la frontière.
- Comprendre ce que Scapy fait « sous le capot » (structure binaire, RFC) même quand on le laisse décoder : on doit savoir l'expliquer.

### Contexte personnel

#### Stack que je maîtrise déjà

- Java Spring, C#.NET
- Docker
- PostgreSQL en usage classique
- GitLab CI/CD complet

#### Stack en apprentissage sur ce projet

- Python (Scapy, async, websockets)
- Parsing réseau bas niveau
- GitHub Actions
- Packaging multi-plateformes (deb, rpm, exe, pkg)

#### Expérience GitLab → GitHub Actions

J'ai déjà fait une CI/CD complète sur GitLab. Je découvre GitHub Actions.

Quand on travaillera sur la CI/CD :
- Pars du principe que je connais les concepts CI/CD
- Concentre-toi sur les spécificités GitHub Actions et les différences avec GitLab CI
- Fais des **parallèles explicites** entre les deux syntaxes
- Pour le build multi-plateformes, signale les pièges (différences Linux/Mac/Windows runners)

## Ne pas faire

- Ne pas implémenter du DPI sophistiqué (nDPI, nfstream) : non, l'objectif est l'apprentissage du parsing
- Ne pas modifier le repo `tracee` (serveur) depuis ici, il a son propre cycle de vie
- Ne pas ajouter de dépendance externe sans me demander
- Ne pas committer à ma place, je gère mes commits moi-même
- Ne pas inclure de token ou de secret dans le code ou les fichiers commités
