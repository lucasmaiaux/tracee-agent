"""Point d'entrée CLI de l'agent Tracee."""

import argparse
import asyncio
import os
import sys

import structlog

from tracee_agent.capture.interfaces import (
    InterfaceSelectionError,
    format_interfaces,
    list_interfaces,
    prompt_interface,
)
from tracee_agent.capture.sniffer import CaptureError
from tracee_agent.config.loader import ConfigError, load_config
from tracee_agent.config.paths import app_dir
from tracee_agent.logging import configure_logging
from tracee_agent.runtime import run_agent
from tracee_agent.transport.client import ConnectionRejected

logger = structlog.get_logger("tracee_agent")


def ensure_output_streams() -> None:
    """Garantit des flux de sortie utilisables avant toute écriture.

    Un exécutable construit sans console démarre sous Windows avec ``sys.stdout`` et
    ``sys.stderr`` à ``None``. Le moindre ``print`` — celui de ``--list-interfaces``,
    ou le message d'usage d'argparse — lèverait alors une exception, sans console pour
    l'afficher. On substitue un puits une fois pour toutes, plutôt que de tester la
    présence d'une sortie à chaque écriture.
    """
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))  # noqa: SIM115


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tracee-agent",
        description="Agent de capture réseau pour Tracee",
    )
    parser.add_argument("--config", help="Chemin du fichier config.yaml")
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Lister les interfaces réseau capturables et quitter",
    )
    # Les deux façons de désigner l'interface s'excluent : l'une la nomme, l'autre
    # la fait choisir. argparse rejette la combinaison avec un message clair.
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--interface", help="Interface à capturer (surcharge la config)")
    selection.add_argument(
        "--pick-interface",
        action="store_true",
        help="Choisir l'interface dans la liste, interactivement (surcharge la config)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Ouvrir l'écran de paramètres (par défaut si aucun argument n'est fourni)",
    )
    parser.add_argument("--verbose", action="store_true", help="Logs détaillés (DEBUG)")
    args = parser.parse_args()

    # L'écran travaille sur ses propres profils et choisit lui-même l'interface : lui
    # passer ces options laisserait croire qu'elles sont prises en compte.
    conflicting = [
        name
        for name, given in (
            ("--config", args.config),
            ("--interface", args.interface),
            ("--pick-interface", args.pick_interface),
            ("--list-interfaces", args.list_interfaces),
        )
        if given
    ]
    if args.gui and conflicting:
        parser.error(f"--gui est incompatible avec {', '.join(conflicting)}")

    # Aucune option de fond — le double-clic sur l'exécutable, ou un lancement à main
    # nue : on ouvre l'écran de paramètres. Le critère porte sur ces options-là et non
    # sur l'absence totale d'arguments, car `--verbose` ne désigne pas un mode ; il
    # module celui qu'on a choisi, et doit pouvoir rendre l'écran bavard.
    if not conflicting:
        args.gui = True

    return args


def _open_settings_window(*, verbose: bool) -> None:
    """Ouvre l'écran de paramètres, en signalant proprement un Tkinter absent.

    L'import est fait ici et non en tête de module : Tkinter dépend du paquet système
    ``python3-tk``, absent d'un serveur typique. Un import global rendrait la ligne de
    commande — le mode d'usage serveur — inutilisable sur ces machines.
    """
    try:
        from tracee_agent.gui.window import run
    except ImportError:
        logger.error(
            "interface_indisponible",
            indice="Tkinter manquant : installer python3-tk, ou lancer avec --config",
        )
        raise SystemExit(2) from None

    # L'écran de paramètres ne bavarde pas dans le terminal d'où on l'a lancé : il
    # annonce lui-même ce que l'utilisateur peut corriger. `--verbose` lève le silence.
    configure_logging("DEBUG" if verbose else "INFO", quiet=not verbose)

    # Première question au diagnostic : où l'agent lit-il et écrit-il sa configuration ?
    # La réponse dépend du mode d'exécution, jamais du répertoire courant.
    logger.info("ecran_parametres", dossier_de_configuration=str(app_dir()))
    run(verbose=verbose)


def main() -> None:
    ensure_output_streams()  # avant argparse, qui écrit sur stdout et stderr
    args = parse_args()
    # Bootstrap : on ne connaît pas encore la config, on part d'un niveau par défaut
    # pour pouvoir déjà rapporter une éventuelle erreur de chargement.
    configure_logging("DEBUG" if args.verbose else "INFO")

    if args.list_interfaces:
        # Produit de la commande → stdout (comme --help), pas un log de diagnostic.
        print(format_interfaces(list_interfaces()))
        return

    if args.gui:
        _open_settings_window(verbose=args.verbose)
        return

    if args.config is None:
        logger.error("config_requise", indice="fournir --config ou utiliser --list-interfaces")
        raise SystemExit(2)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        logger.error("configuration_invalide", erreur=str(exc))
        raise SystemExit(2) from None

    # Reconfigure selon la config (--verbose garde la priorité sur le niveau du fichier).
    level = "DEBUG" if args.verbose else config.logging.level
    configure_logging(level, config.logging.file)

    if args.pick_interface:
        try:
            interface = prompt_interface(list_interfaces())
        except InterfaceSelectionError as exc:
            logger.error("selection_interface_impossible", erreur=str(exc))
            raise SystemExit(2) from None
    else:
        interface = args.interface or config.capture.default_interface

    logger.info("agent_demarre", interface=interface, serveur=config.server.url)

    try:
        asyncio.run(run_agent(config, interface))
    except CaptureError as exc:
        logger.error("capture_impossible", erreur=str(exc))
        raise SystemExit(1) from None
    except ConnectionRejected as exc:
        # Motif déjà journalisé par le transport ; on ne relaie que le verdict.
        logger.error("agent_refuse", erreur=str(exc))
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        logger.info("agent_arrete")


if __name__ == "__main__":
    main()
