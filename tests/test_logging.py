"""Tests de l'assainissement des logs (neutralisation des octets de contrôle)."""

import sys

import structlog

from tracee_agent.logging import _escape_control_chars, configure_logging


def test_echappe_un_esc_dans_une_valeur_reseau():
    # Un faux SNI contenant un ESC ne doit jamais partir brut vers le terminal.
    event = _escape_control_chars(None, "info", {"event": "sni_detecte", "domaine": "evil\x1b[2Jx"})
    assert event["domaine"] == "evil\\x1b[2Jx"  # ESC échappé, le reste intact
    assert event["event"] == "sni_detecte"  # message sûr, inchangé


def test_preserve_sauts_de_ligne_tabulations_et_accents():
    # Les tracebacks (\n, \t) et le texte accentué restent lisibles.
    event = _escape_control_chars(None, "error", {"exception": "Erreur:\n\tdétail\n"})
    assert event["exception"] == "Erreur:\n\tdétail\n"


def test_valeurs_non_str_inchangees():
    event = _escape_control_chars(None, "debug", {"taille": 52, "payload": 0})
    assert event == {"taille": 52, "payload": 0}


def test_journalisation_sans_sortie_standard(monkeypatch, capsys):
    """Exécutable construit sans console : `sys.stderr` vaut None sous Windows.

    Écrire sur None lèverait au premier message journalisé — et il n'y aurait
    justement aucune console pour afficher l'erreur. On journalise dans le vide.
    """
    monkeypatch.setattr(sys, "stderr", None)

    configure_logging("INFO")
    structlog.get_logger("test").info("agent_demarre", interface="eno1")

    assert capsys.readouterr().out == ""
