.PHONY: help install lint mypy ruff pylint test format clean

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@egrep '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies
	poetry install

lint: ruff mypy pylint  ## Run all linters

mypy:  ## Run mypy type checker
	poetry run mypy app/

ruff:  ## Run ruff linter
	poetry run ruff check app/ tests/

pylint:  ## Run pylint linter
	poetry run pylint app/ tests/

test:  ## Run tests
	poetry run pytest tests/ -v

format:  ## Format code with ruff
	poetry run ruff format app/ tests/

clean:  ## Clean up cache and temporary files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
