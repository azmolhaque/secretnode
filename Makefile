# SecretNode — developer & operator shortcuts
.PHONY: help setup test lint bench run docker clean

# Use this project's venv when it exists, whatever venv the shell happens to
# have activated. `make bench` and `python -m ops.ledger` both failed with
# ModuleNotFoundError for an operator whose active venv belonged to a different
# project — the interpreter a target runs on should not depend on which
# directory someone last ran `activate` in.
VENV := $(CURDIR)/.venv
PY   := $(shell [ -x "$(CURDIR)/.venv/bin/python" ] && echo "$(CURDIR)/.venv/bin/python" || echo python3)

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

setup: ## Create a venv and install dependencies
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt ruff
	@echo "Now: cp .env.example .env  &&  set SECRETNODE_API_KEY (openssl rand -hex 24)"

test: ## Run the full test suite
	$(PY) -m pytest

lint: ## Run the ruff correctness lint
	$(PY) -m ruff check backend/

auth-list: ## Show every recorded scanning authorization
	cd backend && $(PY) -m ops.ledger list

auth-check: ## Would TARGET be allowed? e.g. make auth-check TARGET=acme.com
	cd backend && $(PY) -m ops.ledger check $(TARGET) $(ARGS)

auth-decisions: ## Audit trail of allow/deny decisions
	cd backend && $(PY) -m ops.ledger decisions

bench: ## Measure detection-layer precision/recall on the labelled corpus (R2)
	cd backend && SECRETNODE_API_KEY=bench $(PY) -m bench.run_bench

bench-external: ## External-validity recall vs. gitleaks' corpus (needs network)
	cd backend && SECRETNODE_API_KEY=bench $(PY) -m bench.external

bench-full: ## Ground-truth benchmark across every detector (offline)
	cd backend && SECRETNODE_API_KEY=bench $(PY) -m bench.benchmark

bench-http: ## Ground-truth benchmark end-to-end, discovery in scope (local lab)
	cd backend && SECRETNODE_API_KEY=bench ALLOW_PRIVATE_TARGETS=true \
		$(PY) -m bench.benchmark --http

run: ## Start the server (requires .env with SECRETNODE_API_KEY)
	# `python -m uvicorn` uses the same interpreter that runs the CLI, so it works
	# even when the `uvicorn` console script isn't on PATH; --loop auto uses uvloop
	# when available and falls back to asyncio otherwise (no hard uvloop dependency).
	cd backend && $(PY) -m uvicorn main:app --host 0.0.0.0 --port 8000 --loop auto

docker: ## Build and run via docker compose
	docker compose up --build

clean: ## Remove caches and local build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache backend/.pytest_cache
