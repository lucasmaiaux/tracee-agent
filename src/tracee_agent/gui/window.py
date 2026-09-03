"""Écran de paramètres de l'agent (Tkinter).

Sa raison d'être tient en une phrase : le token est généré à chaud sur la page Agents
du serveur, il n'existe donc pas au moment de l'installation et doit être saisi quelque
part. Le reste de la configuration vit dans le YAML.

Ce module importe Tkinter en tête, ce que le reste de l'agent ne fait jamais : il n'est
lui-même importé qu'au moment d'ouvrir la fenêtre, pour que la ligne de commande reste
utilisable sur une machine sans ``python3-tk`` (un serveur, typiquement).

Les widgets ne sont manipulés que depuis le thread principal ; l'agent tourne ailleurs
et n'est observé qu'à travers ``AgentRunner``, interrogé par un ``after()`` périodique.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

import structlog

from tracee_agent.capture.interfaces import InterfaceInfo, list_interfaces
from tracee_agent.capture.privileges import privilege_warning
from tracee_agent.config.writer import ConfigWriteError
from tracee_agent.gui.runner import AgentRunner
from tracee_agent.gui.settings import (
    Settings,
    SettingsError,
    build_config,
    load_settings,
    save_config,
    server_url,
)
from tracee_agent.logging import configure_logging

logger = structlog.get_logger("tracee_agent.gui")

_TITLE = "Tracee — Agent de capture"

# Cadence d'observation du runner : assez courte pour que la reprise de la main après
# un arrêt paraisse immédiate, assez longue pour rester sans effet sur la charge.
_POLL_INTERVAL_MS = 500

# Délai laissé à l'agent pour libérer l'interface quand on ferme la fenêtre.
_SHUTDOWN_TIMEOUT_SECONDS = 3.0

_WARNING_COLOR = "#b00020"


class SettingsWindow:
    """Saisie du token, choix de l'interface, démarrage et arrêt de la capture."""

    def __init__(self, root: tk.Tk, *, verbose: bool = False) -> None:
        self._root = root
        self._runner = AgentRunner()
        self._verbose = verbose
        self._interfaces: list[InterfaceInfo] = []

        self._server = tk.StringVar()
        self._token = tk.StringVar()
        self._interface = tk.StringVar()
        self._debug = tk.BooleanVar(value=False)
        self._show_token = tk.BooleanVar(value=False)
        self._status = tk.StringVar(value="Agent à l'arrêt.")

        self._build()
        self._refresh_interfaces()
        self._load_profile()

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(_POLL_INTERVAL_MS, self._poll)

    # --- Construction ---------------------------------------------------------------

    def _build(self) -> None:
        self._root.title(_TITLE)
        self._root.resizable(False, False)

        frame = ttk.Frame(self._root, padding=16)
        frame.grid(sticky="nsew")
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Serveur").grid(row=0, column=0, sticky="w", pady=4)
        # Lecture seule : l'agent ne parle qu'au serveur Tracee. Affiché quand même,
        # pour qu'on voie où part le trafic sans ouvrir le YAML.
        ttk.Label(frame, textvariable=self._server, foreground="#555").grid(
            row=0, column=1, columnspan=2, sticky="w", pady=4
        )

        ttk.Label(frame, text="Token d'agent").grid(row=1, column=0, sticky="w", pady=4)
        self._token_entry = ttk.Entry(frame, textvariable=self._token, show="•", width=44)
        self._token_entry.grid(row=1, column=1, sticky="ew", pady=4)
        self._show_token_box = ttk.Checkbutton(
            frame,
            text="Afficher",
            variable=self._show_token,
            command=self._on_toggle_token_visibility,
        )
        self._show_token_box.grid(row=1, column=2, sticky="w", padx=(8, 0))

        ttk.Label(frame, text="Interface").grid(row=2, column=0, sticky="w", pady=4)
        self._interface_box = ttk.Combobox(
            frame, textvariable=self._interface, state="readonly", width=42
        )
        self._interface_box.grid(row=2, column=1, sticky="ew", pady=4)
        self._refresh_button = ttk.Button(frame, text="Actualiser", command=self._on_refresh)
        self._refresh_button.grid(row=2, column=2, sticky="w", padx=(8, 0))

        self._debug_box = ttk.Checkbutton(
            frame,
            text="Profil de mise au point (backend local)",
            variable=self._debug,
            command=self._load_profile,
        )
        self._debug_box.grid(row=3, column=1, columnspan=2, sticky="w", pady=(8, 4))

        warning = privilege_warning()
        if warning is not None:
            # Avertissement et non blocage : sous Linux, `setcap` permet de capturer
            # sans être root, et le seul juge fiable reste l'ouverture du socket.
            ttk.Label(
                frame, text=warning, foreground=_WARNING_COLOR, justify="left", wraplength=440
            ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 4))

        self._action_button = ttk.Button(frame, text="Démarrer", command=self._on_action)
        self._action_button.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(12, 4))

        ttk.Label(frame, textvariable=self._status, justify="left", wraplength=440).grid(
            row=6, column=0, columnspan=3, sticky="w"
        )

    # --- Chargement et rafraîchissement ---------------------------------------------

    def _load_profile(self) -> None:
        """Recharge les champs depuis le profil courant (normal ou mise au point)."""
        debug = self._debug.get()
        settings = load_settings(debug=debug)
        self._server.set(server_url(debug=debug))
        self._token.set(settings.token)
        self._select_interface(settings.interface)

    def _refresh_interfaces(self) -> None:
        self._interfaces = list_interfaces()
        self._interface_box.configure(values=[self._label(info) for info in self._interfaces])

    def _label(self, info: InterfaceInfo) -> str:
        addresses = ", ".join(info.ipv4 + info.ipv6) or "aucune adresse"
        # Les adresses sont là pour reconnaître la bonne carte : sous Windows, les noms
        # d'interface se ressemblent tous.
        return f"{info.name} — {addresses}"

    def _select_interface(self, name: str | None) -> None:
        match = next((info for info in self._interfaces if info.name == name), None)
        self._interface.set(self._label(match) if match is not None else "")

    def _selected_interface(self) -> str | None:
        """Nom Scapy de l'interface choisie, extrait de son libellé."""
        label = self._interface.get()
        return next(
            (info.name for info in self._interfaces if self._label(info) == label),
            None,
        )

    # --- Actions --------------------------------------------------------------------

    def _on_toggle_token_visibility(self) -> None:
        self._token_entry.configure(show="" if self._show_token.get() else "•")

    def _on_refresh(self) -> None:
        previous = self._selected_interface()
        self._refresh_interfaces()
        self._select_interface(previous)

    def _on_action(self) -> None:
        if self._runner.is_running():
            self._stop()
        else:
            self._start()

    def _start(self) -> None:
        debug = self._debug.get()
        settings = Settings(token=self._token.get(), interface=self._selected_interface())
        try:
            config = build_config(settings, debug=debug)
            save_config(config, debug=debug)
        except (SettingsError, ConfigWriteError) as exc:
            messagebox.showerror(_TITLE, str(exc), parent=self._root)
            return

        # Même règle qu'en ligne de commande : le profil fixe le niveau et la
        # destination des logs, `--verbose` garde la priorité.
        configure_logging("DEBUG" if self._verbose else config.logging.level, config.logging.file)

        interface = config.capture.default_interface
        assert interface is not None  # garanti par build_config
        self._runner.start(config, interface)
        self._set_running(True)
        self._status.set(f"Capture en cours sur {interface}.")

    def _stop(self) -> None:
        # Sans attente : le clic ne doit pas figer la fenêtre. L'arrêt effectif est
        # constaté par `_poll`, qui rendra la main aux champs.
        self._runner.stop()
        self._status.set("Arrêt en cours…")
        self._action_button.state(["disabled"])

    def _poll(self) -> None:
        """Surveille le runner : l'agent peut s'arrêter seul (token rejeté, capture morte)."""
        if not self._runner.is_running() and self._action_button["text"] != "Démarrer":
            self._set_running(False)
            error = self._runner.take_error()
            if error is None:
                self._status.set("Agent à l'arrêt.")
            else:
                self._status.set(error)
                messagebox.showerror(_TITLE, error, parent=self._root)
        self._root.after(_POLL_INTERVAL_MS, self._poll)

    def _set_running(self, running: bool) -> None:
        """Bascule l'écran entre saisie et capture : on ne modifie pas un agent qui tourne."""
        state = ["disabled"] if running else ["!disabled"]
        for widget in (
            self._token_entry,
            self._interface_box,
            self._refresh_button,
            self._debug_box,
            self._show_token_box,
        ):
            widget.state(state)
        # La combobox reste en lecture seule hors capture : son état n'est pas booléen.
        if not running:
            self._interface_box.state(["readonly"])
        self._action_button.state(["!disabled"])
        self._action_button.configure(text="Arrêter" if running else "Démarrer")

    def _on_close(self) -> None:
        # On attend ici, contrairement au bouton : la fenêtre disparaît, et l'interface
        # réseau doit être rendue avant que le process ne s'achève.
        self._runner.stop(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        self._root.destroy()


def run(*, verbose: bool = False) -> None:
    """Ouvre l'écran de paramètres et rend la main à sa fermeture."""
    root = tk.Tk()
    SettingsWindow(root, verbose=verbose)
    root.mainloop()
