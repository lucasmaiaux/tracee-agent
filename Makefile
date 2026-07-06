.PHONY: dev lint format test

dev:              ## Lancer l'agent en dev (config.yaml local)
	uv run tracee-agent --config config.yaml

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