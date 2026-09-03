"""Détection des privilèges de capture, sur les deux plateformes visées."""

import ctypes
import os
import sys
import types

import pytest

from tracee_agent.capture import privileges


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch):
    """Simule Windows et la réponse de `IsUserAnAdmin` (0 = non, 1 = oui).

    `ctypes.windll` n'existe pas hors Windows : on l'injecte pour pouvoir couvrir
    cette branche depuis la CI Linux comme depuis un poste de dev.
    """

    def _simulate(is_admin: int) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        shell32 = types.SimpleNamespace(IsUserAnAdmin=lambda: is_admin)
        monkeypatch.setattr(ctypes, "windll", types.SimpleNamespace(shell32=shell32), raising=False)

    return _simulate


@pytest.fixture
def posix(monkeypatch: pytest.MonkeyPatch):
    """Simule un POSIX dont l'utilisateur effectif a l'uid donné (0 = root)."""

    def _simulate(euid: int) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(os, "geteuid", lambda: euid)

    return _simulate


def test_root_is_privileged(posix):
    posix(0)

    assert privileges.is_privileged() is True
    assert privileges.privilege_warning() is None


def test_ordinary_user_is_not_privileged(posix):
    posix(1000)

    assert privileges.is_privileged() is False


def test_administrator_is_privileged(windows):
    windows(1)

    assert privileges.is_privileged() is True
    assert privileges.privilege_warning() is None


def test_standard_windows_user_is_not_privileged(windows):
    windows(0)

    assert privileges.is_privileged() is False


def test_unreachable_shell_api_is_treated_as_unprivileged(monkeypatch):
    """Un `windll` indisponible ne doit pas remonter en exception jusqu'à l'écran."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delattr(ctypes, "windll", raising=False)

    assert privileges.is_privileged() is False


def test_warning_names_the_gesture_expected_on_each_platform(posix, windows):
    posix(1000)
    assert "sudo" in privileges.privilege_warning()

    windows(0)
    assert "administrateur" in privileges.privilege_warning()
