# AgentSOC — common tasks. Use `make help` for the list.
.DEFAULT_GOAL := help
PY ?= python

.PHONY: help install test demo live-attack serve docker-build docker-run clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package with dev extras
	pip install -e ".[dev]"

test:  ## Run the test suite (offline; live tests skip without a key)
	pytest -q

demo:  ## Run the offline attack/defence demo (fixtures)
	$(PY) demo/run_demo.py

live-attack:  ## Run the live stage-1 attack (needs ANTHROPIC_API_KEY)
	$(PY) -m demo.live_attack

serve:  ## Start the API + dashboard on http://127.0.0.1:8000
	uvicorn api.main:app --reload

docker-build:  ## Build the Docker image
	docker build -t agentsoc .

docker-run:  ## Run the container on port 8000
	docker run --rm -p 8000:8000 agentsoc

clean:  ## Remove caches and the local database
	rm -rf .pytest_cache **/__pycache__ data/*.db* sandbox/outbox.jsonl
