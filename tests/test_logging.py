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
    structlog.get_logger("sans_sortie").info("agent_demarre", interface="eno1")

    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert sortie.err == ""


def test_ecran_de_parametres_ne_remplit_pas_le_terminal(capsys):
    """Lancé depuis un terminal, l'écran de paramètres n'y déverse rien."""
    configure_logging("INFO", quiet=True)
    structlog.get_logger("silencieux").info("service_identifie", service="netflix.com")

    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert sortie.err == ""


def test_le_silence_cede_devant_un_fichier_de_destination(tmp_path):
    """`logging.file` reste prioritaire : demander un fichier, c'est vouloir la trace."""
    journal = tmp_path / "tracee-agent.log"

    configure_logging("INFO", str(journal), quiet=True)
    structlog.get_logger("vers_fichier").info("capture_demarree", source="eno1")

    assert "capture_demarree" in journal.read_text(encoding="utf-8")
