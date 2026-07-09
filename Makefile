.PHONY: dev dev-all local-dev local-dev-all lint format test

# Config utilisée par dev/dev-all. Surchargeable : make dev-all CONFIG=config.local.yaml
CONFIG ?= config.yaml

dev:              ## Capturer en INFO : affiche les domaines SNI détectés (sudo)
	@.venv/bin/tracee-agent --list-interfaces
	@printf "Interface à capturer : " && read iface && \
		sudo .venv/bin/tracee-agent --config $(CONFIG) --interface $$iface

dev-all:      ## Capturer en DEBUG : tout le trafic décodé, paquet par paquet (sudo)
	@.venv/bin/tracee-agent --list-interfaces
	@printf "Interface à capturer : " && read iface && \
		sudo .venv/bin/tracee-agent --config $(CONFIG) --interface $$iface --verbose

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

trace1:
	sudo .venv/bin/python scripts_temp/explore_capture.py

trace2:
	sudo .venv/bin/python scripts_temp/explore_capture2.py

trace3:
	sudo .venv/bin/python scripts_temp/explore_sni.py