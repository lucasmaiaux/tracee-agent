"""Pilotage de l'agent depuis l'écran de paramètres : une boucle asyncio dans un thread.

Tkinter et asyncio ont chacun leur boucle d'événements, et ni ``mainloop()`` ni
``asyncio.run()`` ne rendent jamais la main : elles ne peuvent donc pas s'imbriquer, il
en faut une par thread. Tkinter garde le thread principal — Tcl n'accepte pas d'être
piloté d'ailleurs — et l'agent part dans un thread de travail.

Le franchissement de frontière reprend la règle déjà appliquée par ``PacketCapture``,
dans l'autre sens : ``loop.call_soon_threadsafe`` est la seule primitive asyncio qu'un
thread étranger a le droit d'appeler. Rien d'autre ne traverse — l'écran se contente de
lire ``is_running`` et ``take_error`` au rythme d'un ``after()``.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading

import structlog

from tracee_agent.capture.sniffer import CaptureError
from tracee_agent.config.schema import AgentConfig
from tracee_agent.runtime import run_agent
from tracee_agent.transport.client import ConnectionRejected

logger = structlog.get_logger("tracee_agent.gui")

# Délai laissé au thread pour installer sa boucle avant que `start` rende la main.
# Sans cette poignée de main, un « Arrêter » cliqué dans la foulée n'aurait aucune
# boucle où poster son annulation, et l'agent continuerait de tourner.
_STARTUP_TIMEOUT_SECONDS = 5.0


class AgentRunner:
    """Fait tourner l'agent dans un thread de travail, démarrable et arrêtable à volonté.

    L'agent peut aussi s'arrêter **de lui-même** — token rejeté, version de protocole
    incompatible, interface disparue. L'écran s'en aperçoit en observant ``is_running``
    et récupère le motif par ``take_error``.
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task[None] | None = None
        # Écrit par le thread de travail, lu par le thread Tk : une affectation
        # d'attribut est atomique sous le GIL et il n'y a qu'un écrivain, donc pas de
        # verrou à poser ici.
        self._error: str | None = None
        self._ready = threading.Event()

    def is_running(self) -> bool:
        """Indique si l'agent tourne encore."""
        return self._thread is not None and self._thread.is_alive()

    def start(self, config: AgentConfig, interface: str) -> None:
        """Démarre l'agent et rend la main dès que sa boucle est prête.

        Args:
            config: Configuration validée (serveur, token, capture).
            interface: Interface à écouter.

        Raises:
            RuntimeError: Un agent tourne déjà.
        """
        if self.is_running():
            raise RuntimeError("L'agent tourne déjà.")

        self._error = None
        self._ready.clear()
        self._thread = threading.Thread(
            target=self._serve,
            args=(config, interface),
            name="tracee-agent",
            # Filet de sécurité : une fenêtre fermée brutalement ne doit pas laisser
            # le process en vie sur un thread orphelin.
            daemon=True,
        )
        self._thread.start()
        self._ready.wait(_STARTUP_TIMEOUT_SECONDS)

    def stop(self, timeout: float | None = None) -> None:
        """Demande l'arrêt de l'agent (sans effet s'il ne tourne pas).

        Args:
            timeout: Secondes d'attente de la fin effective du thread. ``None`` rend la
                main aussitôt — ce qu'il faut depuis un clic, pour ne pas figer l'écran ;
                l'arrêt réel est constaté ensuite par ``is_running``. À la fermeture de
                la fenêtre en revanche, on attend, le temps que l'interface réseau soit
                libérée.
        """
        loop, task = self._loop, self._task
        if loop is not None and task is not None:
            # Boucle déjà fermée : l'agent s'était arrêté entre-temps, rien à annuler.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(task.cancel)
        if timeout is not None and self._thread is not None:
            self._thread.join(timeout)

    def take_error(self) -> str | None:
        """Renvoie le motif du dernier arrêt subi, puis l'oublie.

        Consommé une seule fois : l'écran interroge le runner à chaque ``after()`` et
        ne doit pas réafficher la même erreur en boucle.
        """
        error, self._error = self._error, None
        return error

    def _serve(self, config: AgentConfig, interface: str) -> None:
        """Corps du thread de travail : sa propre boucle asyncio, du début à la fin."""
        try:
            asyncio.run(self._supervise(config, interface))
        except asyncio.CancelledError:
            # Annulation arrivée avant que la coroutine ne démarre : la tâche est
            # marquée annulée et `asyncio.run` relève l'exception. Elle hérite de
            # BaseException, donc le `except Exception` ci-dessous ne la verrait pas.
            logger.info("agent_arrete")
        except (CaptureError, ConnectionRejected) as exc:
            # Les deux pannes que l'utilisateur peut corriger lui-même : mauvaise
            # interface ou privilèges manquants d'un côté, token périmé de l'autre.
            self._error = str(exc)
        except Exception as exc:  # noqa: BLE001 — l'écran doit voir *toute* panne
            logger.exception("agent_arret_inattendu")
            self._error = f"Arrêt inattendu de l'agent : {exc}"
        finally:
            self._loop = None
            self._task = None
            self._ready.set()  # débloque un `start` qui attendrait encore

    async def _supervise(self, config: AgentConfig, interface: str) -> None:
        """Expose la boucle et la tâche au thread Tk, puis fait tourner l'agent."""
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.current_task()
        self._ready.set()
        try:
            await run_agent(config, interface)
        except asyncio.CancelledError:
            # Arrêt demandé : `run_agent` a déjà libéré l'interface dans son `finally`.
            logger.info("agent_arrete")
