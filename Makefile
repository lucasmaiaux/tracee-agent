.PHONY: dev dev-all lint format test

dev:              ## Capturer en INFO : affiche les domaines SNI détectés (sudo)
	@.venv/bin/tracee-agent --list-interfaces
	@printf "Interface à capturer : " && read iface && \
		sudo .venv/bin/tracee-agent --config config.yaml --interface $$iface

dev-all:      ## Capturer en DEBUG : tout le trafic décodé, paquet par paquet (sudo)
	@.venv/bin/tracee-agent --list-interfaces
	@printf "Interface à capturer : " && read iface && \
		sudo .venv/bin/tracee-agent --config config.yaml --interface $$iface --verbose

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