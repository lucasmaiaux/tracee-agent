"""Pilotage de l'agent dans un thread de travail (pont écran Tk ↔ boucle asyncio).

`run_agent` est remplacé par une coroutine factice : ce qui est éprouvé ici, c'est la
plomberie — démarrage, annulation à travers la frontière de thread, remontée d'erreur —
et non la capture elle-même.
"""

import asyncio
import threading
import time

import pytest

from tracee_agent.capture.sniffer import CaptureError
from tracee_agent.config.schema import AgentConfig
from tracee_agent.gui import runner as gui_runner
from tracee_agent.gui.runner import AgentRunner
from tracee_agent.transport.client import ConnectionRejected

_TIMEOUT_SECONDS = 3.0

CONFIG = AgentConfig.model_validate(
    {"server": {"url": "ws://localhost:8000/ws/agent", "token": "trc_agt_test"}}
)


@pytest.fixture
def runner():
    agent_runner = AgentRunner()
    yield agent_runner
    agent_runner.stop(timeout=_TIMEOUT_SECONDS)  # aucun thread ne survit à un test


def wait_until_stopped(runner: AgentRunner) -> None:
    """Attend l'arrêt effectif, comme l'écran le constate via son `after()`."""
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    while runner.is_running() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not runner.is_running()


def test_agent_runs_until_it_is_stopped(runner, monkeypatch):
    started = threading.Event()

    async def never_ends(_config, _interface):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(gui_runner, "run_agent", never_ends)

    runner.start(CONFIG, "lo")

    assert started.wait(_TIMEOUT_SECONDS)
    assert runner.is_running() is True


def test_stopping_cancels_the_coroutine_across_the_thread_boundary(runner, monkeypatch):
    """Cœur du pont Tk → asyncio : le clic « Arrêter » atteint bien la coroutine."""
    started = threading.Event()
    cancelled = threading.Event()

    async def never_ends(_config, _interface):
        try:
            started.set()
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(gui_runner, "run_agent", never_ends)
    runner.start(CONFIG, "lo")
    assert started.wait(_TIMEOUT_SECONDS)

    runner.stop(timeout=_TIMEOUT_SECONDS)

    assert cancelled.is_set()
    assert runner.is_running() is False
    assert runner.take_error() is None  # un arrêt demandé n'est pas une panne


def test_capture_failure_is_reported_to_the_screen(runner, monkeypatch):
    async def refuse(_config, _interface):
        raise CaptureError("Impossible de capturer sur 'lo'.")

    monkeypatch.setattr(gui_runner, "run_agent", refuse)
    monkeypatch.setattr(gui_runner, "privilege_warning", lambda: None)

    runner.start(CONFIG, "lo")
    wait_until_stopped(runner)

    assert runner.take_error() == "Impossible de capturer sur 'lo'."


def test_capture_failure_names_the_missing_privilege(runner, monkeypatch):
    """Le conseil accompagne l'échec au lieu d'occuper la fenêtre en permanence."""

    async def refuse(_config, _interface):
        raise CaptureError("Impossible de capturer sur 'lo'.")

    monkeypatch.setattr(gui_runner, "run_agent", refuse)
    monkeypatch.setattr(gui_runner, "privilege_warning", lambda: "Relancer avec sudo.")

    runner.start(CONFIG, "lo")
    wait_until_stopped(runner)

    error = runner.take_error()
    assert "Impossible de capturer sur 'lo'." in error
    assert "Relancer avec sudo." in error


def test_a_rejected_token_carries_no_privilege_advice(runner, monkeypatch):
    """Un token refusé n'a rien à voir avec les privilèges : pas de conseil hors sujet."""

    async def reject(_config, _interface):
        raise ConnectionRejected("Token d'agent refusé par le serveur.")

    monkeypatch.setattr(gui_runner, "run_agent", reject)
    monkeypatch.setattr(gui_runner, "privilege_warning", lambda: "Relancer avec sudo.")

    runner.start(CONFIG, "lo")
    wait_until_stopped(runner)

    assert runner.take_error() == "Token d'agent refusé par le serveur."


def test_a_rejected_token_is_named_rather_than_a_silent_stop(runner, monkeypatch):
    """Incident le plus probable en démonstration : il ne doit pas passer pour un arrêt normal."""

    async def reject(_config, _interface):
        raise ConnectionRejected("Token d'agent refusé par le serveur.")

    monkeypatch.setattr(gui_runner, "run_agent", reject)

    runner.start(CONFIG, "lo")
    wait_until_stopped(runner)

    assert runner.take_error() == "Token d'agent refusé par le serveur."


def test_unexpected_failure_is_reported_rather_than_swallowed(runner, monkeypatch):
    async def crash(_config, _interface):
        raise ValueError("boum")

    monkeypatch.setattr(gui_runner, "run_agent", crash)

    runner.start(CONFIG, "lo")
    wait_until_stopped(runner)

    assert "boum" in runner.take_error()


def test_an_error_is_delivered_once(runner, monkeypatch):
    """L'écran interroge le runner à chaque tick : pas de message répété en boucle."""

    async def refuse(_config, _interface):
        raise CaptureError("Impossible de capturer sur 'lo'.")

    monkeypatch.setattr(gui_runner, "run_agent", refuse)
    runner.start(CONFIG, "lo")
    wait_until_stopped(runner)

    assert runner.take_error() is not None
    assert runner.take_error() is None


def test_starting_twice_is_refused(runner, monkeypatch):
    async def never_ends(_config, _interface):
        await asyncio.Event().wait()

    monkeypatch.setattr(gui_runner, "run_agent", never_ends)
    runner.start(CONFIG, "lo")

    with pytest.raises(RuntimeError, match="tourne déjà"):
        runner.start(CONFIG, "lo")


def test_restarting_after_a_failure_clears_the_previous_error(runner, monkeypatch):
    async def refuse(_config, _interface):
        raise CaptureError("Impossible de capturer sur 'lo'.")

    monkeypatch.setattr(gui_runner, "run_agent", refuse)
    runner.start(CONFIG, "lo")
    wait_until_stopped(runner)

    started = threading.Event()

    async def never_ends(_config, _interface):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(gui_runner, "run_agent", never_ends)
    runner.start(CONFIG, "eno1")

    assert started.wait(_TIMEOUT_SECONDS)
    assert runner.take_error() is None


def test_stopping_an_idle_runner_is_harmless(runner):
    runner.stop(timeout=_TIMEOUT_SECONDS)

    assert runner.is_running() is False
    assert runner.take_error() is None
