"""Résolution de l'emplacement du config.yaml selon le mode d'exécution."""

import sys

import pytest

from tracee_agent.config import paths


@pytest.fixture
def frozen(monkeypatch: pytest.MonkeyPatch):
    """Simule un exécutable PyInstaller dont le binaire est à l'emplacement donné."""

    def _freeze(binary) -> None:
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", str(binary))

    return _freeze


def test_app_dir_falls_back_to_cwd_in_development(monkeypatch, tmp_path):
    # Hors PyInstaller, sys.executable désigne le python du venv : sans intérêt.
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.chdir(tmp_path)

    assert paths.app_dir() == tmp_path.resolve()


def test_app_dir_is_the_binary_folder_when_frozen(frozen, tmp_path):
    frozen(tmp_path / "tracee-agent")

    assert paths.app_dir() == tmp_path.resolve()


def test_config_sits_next_to_the_binary(frozen, tmp_path):
    frozen(tmp_path / "tracee-agent.exe")

    assert paths.config_path() == tmp_path.resolve() / "config.yaml"


def test_debug_profile_is_a_separate_file(frozen, tmp_path):
    # Profils séparés : le token du backend local n'est pas celui du serveur distant.
    frozen(tmp_path / "tracee-agent")

    assert paths.config_path(debug=True) == tmp_path.resolve() / "config.local.yaml"
    assert paths.config_path(debug=True) != paths.config_path()


def test_config_never_lands_in_the_extraction_folder(frozen, monkeypatch, tmp_path):
    """Régression : `_MEIPASS` est détruit à la fermeture, rien d'utilisateur n'y va.

    C'est le piège classique de PyInstaller : un chemin déduit de ``__file__`` tombe
    dans ce dossier temporaire, et la configuration saisie par l'utilisateur disparaît
    au redémarrage suivant.
    """
    extraction = tmp_path / "_MEI42"
    monkeypatch.setattr(sys, "_MEIPASS", str(extraction), raising=False)
    frozen(tmp_path / "dist" / "tracee-agent")

    assert paths.config_path().parent != extraction
    assert paths.config_path().parent == (tmp_path / "dist").resolve()
