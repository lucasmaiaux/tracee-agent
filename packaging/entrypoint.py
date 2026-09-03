"""Point d'entrée du binaire PyInstaller.

Un script distinct du package plutôt que ``main.py`` directement : PyInstaller
exécuterait sinon ce module sous le nom ``__main__`` **et** l'importerait sous le nom
``tracee_agent.main``, dupliquant tout état de niveau module (le logger, notamment).
"""

from tracee_agent.main import main

main()
