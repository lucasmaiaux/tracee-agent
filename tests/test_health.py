"""Tests des compteurs de santé du pipeline."""

from tracee_agent.health import PipelineHealth


def test_compteurs_partent_a_zero():
    health = PipelineHealth()

    report = health.report(dns_cache_size=0)

    assert report["packets_decoded"] == 0
    assert report["events"] == 0
    assert report["identification_rate"] is None  # rien à juger sur zéro event


def test_taux_indisponible_tant_que_l_echantillon_est_mince():
    # Un seul event sans hint ne prouve rien : au démarrage d'une capture, aucune
    # connexion TLS n'a encore pu s'ouvrir. Annoncer « 0 % » serait un faux signal.
    health = PipelineHealth(events=5, events_identified=0)

    assert health.identification_rate() is None


def test_taux_calcule_au_dela_du_seuil():
    health = PipelineHealth(events=200, events_identified=50)

    assert health.identification_rate() == 25.0


def test_taux_nul_est_rapporte_quand_l_echantillon_suffit():
    # Le cas qui doit sauter aux yeux : du trafic, des events, et rien d'identifié.
    health = PipelineHealth(events=300, events_identified=0, client_hellos=74)

    report = health.report(dns_cache_size=0)

    assert report["identification_rate"] == 0.0
    assert report["client_hellos"] == 74


def test_le_rapport_joint_la_taille_du_cache_dns():
    # Détenue par l'identification, pas par le compteur : on vérifie qu'elle transite.
    health = PipelineHealth()

    assert health.report(dns_cache_size=42)["dns_cache"] == 42
