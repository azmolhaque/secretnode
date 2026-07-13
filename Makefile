# SecretNode — developer & operator shortcuts
.PHONY: help setup test lint run docker clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

setup: ## Create a venv and install dependencies
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt ruff
	@echo "Now: cp .env.example .env  &&  set SECRETNODE_API_KEY (openssl rand -hex 24)"

test: ## Run the full test suite
	pytest

lint: ## Run the ruff correctness lint
	ruff check backend/

run: ## Start the server (requires .env with SECRETNODE_API_KEY)
	cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 --loop uvloop

docker: ## Build and run via docker compose
	docker compose up --build

clean: ## Remove caches and local build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache backend/.pytest_cache
