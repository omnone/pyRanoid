.PHONY: help test test-unit test-integration test-cov test-cov-html clean install lint format build run run-cli run-gui

help:
	@echo "pyRanoid Commands"
	@echo "================="
	@echo ""
	@echo "Build & Install:"
	@echo "  make install           - Install dependencies with uv"
	@echo "  make build             - Build distribution packages"
	@echo ""
	@echo "Run:"
	@echo "  make run               - Run CLI (alias for run-cli)"
	@echo "  make run-cli           - Run pyRanoid CLI"
	@echo "  make run-gui           - Run pyRanoid GUI"
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests (unit + integration)"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-integration  - Run integration tests only"
	@echo "  make test-cov          - Run all tests with coverage report"
	@echo "  make test-cov-html     - Run tests with HTML coverage report"
	@echo ""
	@echo "Development:"
	@echo "  make lint              - Run linter checks"
	@echo "  make format            - Format code with black/ruff"
	@echo ""

test:
	@echo "Running all tests..."
	uv run pytest -v

test-unit:
	@echo "Running unit tests..."
	uv run pytest src/tests/unit -v

test-integration:
	@echo "Running integration tests..."
	uv run pytest src/tests/integration -v

test-cov:
	@echo "Running tests with coverage..."
	uv run pytest --cov=src/pyRanoid --cov-report=term-missing

test-cov-html:
	@echo "Running tests with HTML coverage report..."
	uv run pytest --cov=src/pyRanoid --cov-report=html --cov-report=term
	@echo ""
	@echo "Coverage report generated in htmlcov/index.html"

install:
	@echo "Installing dependencies and package..."
	uv sync --all-extras
	uv pip install -e .

build:
	@echo "Building distribution packages..."
	uv build
	@echo ""
	@echo "Build complete! Packages created in dist/"

run: run-cli

run-cli:
	@echo "Starting pyRanoid CLI..."
	@echo ""
	uv run python main.py

run-gui:
	@echo "Starting pyRanoid GUI..."
	@echo ""
	uv run python -m pyRanoid.gui

lint:
	@echo "Running linter..."
	@if command -v ruff >/dev/null 2>&1; then \
		uv run ruff check src/; \
	else \
		echo "Ruff not installed. Install with: uv add --dev ruff"; \
	fi

format:
	@echo "Formatting code..."
	@if command -v ruff >/dev/null 2>&1; then \
		uv run ruff format src/; \
	else \
		echo "Ruff not installed. Install with: uv add --dev ruff"; \
	fi


