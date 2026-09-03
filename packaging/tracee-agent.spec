# -*- mode: python ; coding: utf-8 -*-
"""Recette de construction de l'exécutable autonome.

Lancée depuis la racine du repo : ``pyinstaller packaging/tracee-agent.spec`` (cible
``make build-exe``). PyInstaller **ne sait pas compiler d'une plateforme vers une
autre** : le binaire Windows exige un runner Windows, le binaire Linux un runner
Linux — d'où la matrice du workflow de release.

``SPECPATH`` est injecté par PyInstaller et vaut le dossier de ce fichier.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 — injecté par PyInstaller

# Tkinter est une liaison vers Tcl/Tk, livrée par un paquet système séparé
# (`python3-tk` sous Debian/Ubuntu) absent des machines de construction par défaut.
# Sans lui, PyInstaller ne signale rien et produit un exécutable **sans interface
# graphique** : un échec ici vaut mieux qu'une release inutilisable.
try:
    import tkinter  # noqa: F401
except ImportError as exc:
    raise SystemExit(
        "Tkinter introuvable : l'exécutable serait construit sans écran de "
        "configuration.\nLinux : sudo apt install python3-tk"
    ) from exc

# Scapy charge ses couches par import dynamique (`conf.load_layers`) : l'analyse
# statique de PyInstaller ne les voit pas, et le binaire perdrait les dissecteurs.
# Tkinter y est déclaré explicitement : il n'est importé qu'à l'intérieur d'une
# fonction, pour que la ligne de commande reste utilisable sans lui.
hidden_imports = collect_submodules("scapy") + [
    "tkinter",
    "tkinter.ttk",
    "tkinter.messagebox",
]

analysis = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "entrypoint.py")],
    pathex=[str(ROOT / "src")],
    hiddenimports=hidden_imports,
    excludes=["pytest", "_pytest", "ruff"],
)

pyz = PYZ(analysis.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="tracee-agent",
    debug=False,
    strip=False,
    # UPX économise quelques Mo au prix de faux positifs antivirus sous Windows et
    # d'un démarrage plus lent : sans intérêt ici.
    upx=False,
    # Console conservée : sans elle, un échec survenu avant l'ouverture de la fenêtre
    # (Npcap absent, bibliothèque manquante) ne laisserait aucune trace visible.
    console=True,
    # Windows uniquement (ignoré ailleurs) : embarque un manifeste qui réclame
    # l'élévation dès le lancement. Un double-clic suffit alors — Windows pose la
    # question à l'utilisateur — au lieu d'exiger un « Exécuter en tant
    # qu'administrateur » que rien ne rappelle à qui vient de télécharger le fichier.
    uac_admin=True,
)
