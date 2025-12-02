# Cybersecurity Toolkit - Makefile
# Provides common development and deployment tasks

SHELL := /bin/bash
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

# Scripts from the mapping library
MAPPER_SCRIPTS = mapear_estrutura.sh libmapear.sh
# Main cybersecurity toolkit scripts
CYBERSEC_SCRIPTS = cybersec_toolkit.py cybersecurity_suite.py

.PHONY: help install test test-unit lint format security-check docker-build docker-run clean run run-interactive run-scan install-scripts uninstall-scripts test-scripts example

# Default target
help:
	@echo "Cybersecurity Toolkit - Development Commands"
	@echo "============================================="
	@echo "install          : Install Python dependencies"
	@echo "install-scripts  : Install shell scripts to system"
	@echo "test             : Run all tests"
	@echo "test-unit        : Run unit tests only"
	@echo "test-scripts     : Run tests for shell scripts"
	@echo "lint             : Run code quality checks"
	@echo "format           : Format code with black and isort"
	@echo "security-check   : Run security scans"
	@echo "docker-build     : Build Docker image"
	@echo "docker-run       : Run the toolkit in Docker"
	@echo "clean            : Remove generated files"
	@echo "run              : Run the cybersecurity toolkit"
	@echo "run-interactive  : Run in interactive mode"
	@echo "run-scan         : Run comprehensive security scan"
	@echo "example          : Run example of the mapping library"
	@echo ""
	@echo "Additional commands for mapping library:"
	@echo "  install-scripts  - Install mapping scripts to system"
	@echo "  uninstall-scripts - Remove mapping scripts from system"
	@echo "  test-scripts     - Test the mapping functionality"
	@echo "  example          - Run example of mapping library"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX     - Installation prefix (default: /usr/local)"
	@echo "  BINDIR     - Binary directory (default: PREFIX/bin)"

# Install Python dependencies
install:
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install -e .[dev]

# Install shell scripts to system
install-scripts:
	@echo "Installing mapping scripts to system..."
	@for script in $(MAPPER_SCRIPTS); do \
		if [ -f "$$script" ]; then \
			install -m 755 "$$script" "$(BINDIR)/$$script"; \
			echo "Installed: $(BINDIR)/$$script"; \
		else \
			echo "File not found: $$script"; \
		fi \
	done
	@echo "Installation completed!"

# Uninstall shell scripts from system
uninstall-scripts:
	@echo "Removing mapping scripts from system..."
	@for script in $(MAPPER_SCRIPTS); do \
		if [ -f "$(BINDIR)/$$script" ]; then \
			rm -f "$(BINDIR)/$$script"; \
			echo "Removed: $(BINDIR)/$$script"; \
		fi \
	done
	@echo "Removal completed!"

# Run all tests
test: test-scripts
	pytest tests/ -v --cov=cybersec --cov=cybersecurity_suite --cov-report=html

# Run unit tests only
test-unit:
	pytest tests/unit/ -v

# Run tests for shell scripts
test-scripts:
	@echo "Running basic tests for mapping scripts..."
	@echo "1. Testing help..."
	@./mapear_estrutura.sh --help > /dev/null
	@echo "✓ Help working"
	@echo "2. Testing basic mapping..."
	@./mapear_estrutura.sh -f plain . 2>/dev/null | head -n 5
	@echo "✓ Basic mapping working"
	@echo "3. Testing security mode..."
	@./mapear_estrutura.sh --security -f plain . 2>/dev/null | head -n 5
	@echo "✓ Security mode working"
	@echo "All basic tests passed!"

# Run code quality checks
lint:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=88 --statistics
	mypy .

# Format code
format:
	black .
	isort .

# Run security scans
security-check:
	bandit -r . -c pyproject.toml
	trivy fs .

# Build Docker image
docker-build:
	docker build -t cybersec-toolkit .

# Run the toolkit in Docker
docker-run:
	docker run --rm -it \
		-v /var/log:/var/log:ro \
		-v /var/run/docker.sock:/var/run/docker.sock:ro \
		-v $(PWD):/app:ro \
		cybersec-toolkit

# Run the cybersecurity toolkit
run:
	python cybersec_toolkit.py

# Run in interactive mode
run-interactive:
	python cybersec_toolkit.py -i

# Run comprehensive security scan
run-scan:
	python cybersec_toolkit.py --scan

# Run example of mapping library
example:
	@echo "Running example of the mapping library..."
	@./exemplo_uso_biblioteca.sh

# Clean generated files
clean:
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete
	find . -type f -name ".coverage.*" -delete