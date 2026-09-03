"""Ce que l'écran de paramètres manipule, indépendamment des widgets.

Séparé de la fenêtre pour deux raisons : ce sont les règles qui méritent des tests
(Tkinter n'est pas testable en CI sans serveur X), et parce que le module doit rester
importable sur une machine dépourvue de ``python3-tk``.

L'écran expose **le strict nécessaire** : le token, qui n'existe qu'au moment de la
démo, et l'interface à écouter, qui dépend de la machine. Tout le reste — URL du
serveur, ``snaplen``, journalisation — vient du profil existant ou des valeurs par
défaut, et se règle dans le YAML pour qui en a besoin.

Le pré-remplissage est **délibérément tolérant** : un profil absent, illisible ou
syntaxiquement cassé rend des champs vides, jamais une exception. L'écran de paramètres
est précisément l'outil qui sert à réparer une configuration — il doit s'ouvrir surtout
quand elle est en mauvais état.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from tracee_agent.config.loader import ConfigError, load_config
from tracee_agent.config.paths import config_path
from tracee_agent.config.schema import AgentConfig
from tracee_agent.config.writer import write_config

# Serveur visé quand aucun profil n'existe encore — le cas du binaire fraîchement posé
# sur une machine vierge. L'agent ne parle qu'au serveur Tracee : il n'y a rien à
# choisir, et l'écran n'a donc pas à demander cette adresse. Un `config.yaml` présent
# la surcharge, ce qui laisse la porte ouverte à un autre déploiement.
DEFAULT_SERVER_URL = "wss://tracee.lucas-maiaux.fr/ws/agent"

# Pendant du profil de mise au point : le backend lancé en local (voir `make local-dev`).
DEFAULT_DEBUG_SERVER_URL = "ws://localhost:8000/ws/agent"


class SettingsError(Exception):
    """Saisie invalide, avec un message destiné à l'utilisateur."""


@dataclass(frozen=True)
class Settings:
    """Les deux champs de l'écran, tels qu'ils sont saisis puis persistés."""

    token: str = ""
    interface: str | None = None


def load_settings(*, debug: bool = False) -> Settings:
    """Relit le profil demandé pour pré-remplir l'écran, sans jamais échouer.

    Args:
        debug: Vise le profil de mise au point plutôt que le profil normal.

    Returns:
        Les valeurs trouvées, ou des champs vides si le fichier est absent ou illisible.
    """
    try:
        config = load_config(str(config_path(debug=debug)))
    except ConfigError:
        # Fichier absent au premier lancement, ou YAML cassé par une édition manuelle :
        # dans les deux cas l'écran s'ouvre vide et laisse l'utilisateur repartir.
        return Settings()
    return Settings(token=config.server.token, interface=config.capture.default_interface)


def server_url(*, debug: bool = False) -> str:
    """URL du serveur du profil, affichée en lecture seule par l'écran."""
    return _profile(debug=debug).server.url


def build_config(settings: Settings, *, debug: bool = False) -> AgentConfig:
    """Valide la saisie et en fait une configuration complète.

    Les réglages absents de l'écran (URL, ``snaplen``, journalisation) viennent du profil
    existant quand il est lisible, et des valeurs par défaut sinon : ce que l'utilisateur
    a réglé à la main dans le YAML n'est pas écrasé par un passage dans l'écran.

    Args:
        settings: Valeurs saisies.
        debug: Profil visé, dont sont repris les réglages non exposés par l'écran.

    Raises:
        SettingsError: Un champ obligatoire est vide, ou l'ensemble est refusé par le
            schéma.
    """
    token = settings.token.strip()
    interface = (settings.interface or "").strip()

    if not token:
        raise SettingsError("Le token d'agent est obligatoire.")
    if not interface:
        raise SettingsError("Choisir une interface réseau à écouter.")

    profile = _profile(debug=debug)
    url = profile.server.url.strip()
    if not url.startswith(("ws://", "wss://")):
        # L'URL ne venant pas de l'écran, une valeur aberrante ne peut venir que d'une
        # édition manuelle du YAML. Sans ce garde-fou, l'échec n'apparaîtrait qu'au
        # handshake, sous une forme bien moins parlante.
        raise SettingsError(
            f"L'URL du serveur est invalide : {url!r}.\n"
            f"Elle doit commencer par wss:// (ou ws:// en local) et se corrige dans "
            f"{config_path(debug=debug).name}."
        )

    capture = profile.capture.model_copy(update={"default_interface": interface})
    try:
        return AgentConfig(
            server={"url": url, "token": token},
            capture=capture,
            logging=profile.logging,
        )
    except ValidationError as exc:
        raise SettingsError(f"Configuration invalide :\n{exc}") from exc


def save_config(config: AgentConfig, *, debug: bool = False) -> Path:
    """Persiste la configuration dans le profil demandé et renvoie le fichier écrit.

    Raises:
        ConfigWriteError: Dossier absent, droits insuffisants, disque plein.
    """
    path = config_path(debug=debug)
    write_config(config, path)
    return path


def _profile(*, debug: bool) -> AgentConfig:
    """Profil existant, ou une configuration par défaut s'il est absent ou illisible."""
    try:
        return load_config(str(config_path(debug=debug)))
    except ConfigError:
        url = DEFAULT_DEBUG_SERVER_URL if debug else DEFAULT_SERVER_URL
        return AgentConfig(server={"url": url, "token": ""})
