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
