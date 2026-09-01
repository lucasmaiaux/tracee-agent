.PHONY: sync interfaces dev dev-all local-dev local-dev-all lint format test

# Config utilisée par dev/dev-all. Surchargeable : make dev-all CONFIG=config.local.yaml
CONFIG ?= config.yaml

# Interface à capturer. Si vide, l'agent la fait choisir dans une liste numérotée
# (--pick-interface). Le prompt est côté agent et non ici : `read` est un builtin
# POSIX, absent de cmd.exe, où make retombe faute de sh.exe dans le PATH.
IFACE ?=

# Options passées à l'agent. dev-all y injecte --verbose.
OPTS ?=

# --- Portabilité POSIX ↔ Windows --------------------------------------------
# GNU Make hérite de OS=Windows_NT, défini par Windows lui-même : test standard,
# et sans sous-processus (contrairement à `uname`, absent hors Git Bash).
#   - venv : CPython pose ses exécutables dans bin/ sur POSIX, Scripts/ sur Windows.
#   - privilèges : la capture demande root. `sudo` sur POSIX ; sur Windows il faut
#     un terminal déjà lancé en administrateur, d'où un préfixe vide.
ifeq ($(OS),Windows_NT)
    VENV_BIN := .venv/Scripts
    EXE      := .exe
    SUDO     :=
else
    VENV_BIN := .venv/bin
    EXE      :=
    SUDO     := sudo
endif

AGENT  := $(VENV_BIN)/tracee-agent$(EXE)
PYTHON := $(VENV_BIN)/python$(EXE)

sync:             ## Créer/actualiser le venv depuis uv.lock (idempotent)
	@uv sync

interfaces: sync  ## Lister les interfaces réseau capturables
	@$(AGENT) --list-interfaces

dev: sync         ## Capturer en INFO : affiche les domaines SNI détectés (root/admin)
	$(SUDO) $(AGENT) --config $(CONFIG) $(if $(IFACE),--interface "$(IFACE)",--pick-interface) $(OPTS)

dev-all:          ## Capturer en DEBUG : tout le trafic décodé, paquet par paquet (root/admin)
	@$(MAKE) dev OPTS=--verbose

local-dev:        ## Comme dev, mais sur config.local.yaml (test local, backend dev)
	@$(MAKE) dev CONFIG=config.local.yaml

local-dev-all:    ## Comme dev-all, mais sur config.local.yaml (test local, backend dev)
	@$(MAKE) dev-all CONFIG=config.local.yaml

lint:             ## Vérifier le code sans le modifier (CI)
	uv run ruff check .
	uv run ruff format --check .

format:           ## Formater + corriger automatiquement
	uv run ruff format .
	uv run ruff check --fix .

test:             ## Lancer les tests
	uv run pytest

trace1: sync
	$(SUDO) $(PYTHON) scripts_temp/explore_capture.py

trace2: sync
	$(SUDO) $(PYTHON) scripts_temp/explore_capture2.py

trace3: sync
	$(SUDO) $(PYTHON) scripts_temp/explore_sni.py
