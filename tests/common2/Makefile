# Makefile for tests/common2 unit tests

# Configuration
PYTHON := python3
MIN_COVERAGE := 80
COVERAGE_SOURCES := $(filter-out check_coverage.py test_%.py,$(wildcard *.py))
COVERAGE_TARGETS := $(patsubst %.py,%,$(COVERAGE_SOURCES))

.PHONY: help test test-verbose test-coverage test-coverage-enforced coverage-report coverage-check coverage-enforce clean list-modules set-min-coverage test-bgp

help:  ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

test:  ## Run unit tests
	@echo "Running unit tests..."
	python3 -m pytest -m unit_test --tb=short -W ignore::pytest.PytestUnknownMarkWarning

test-verbose:  ## Run unit tests (verbose)
	@echo "Running unit tests (verbose)..."
	python3 -m pytest -m unit_test --tb=short -v -W ignore::pytest.PytestUnknownMarkWarning

test-coverage:  ## Run unit tests with coverage report (requires pytest-cov: pip install pytest-cov)
	@echo "Running unit tests with coverage..."
	@if python3 -c "import pytest_cov" 2>/dev/null; then \
		if [ -n "$(COVERAGE_SOURCES)" ]; then \
			$(PYTHON) -m pytest -m unit_test \
				$(addprefix --cov=,$(COVERAGE_TARGETS)) \
				--cov-report=term-missing \
				--cov-report=html:htmlcov \
				--tb=short \
				-W ignore::pytest.PytestUnknownMarkWarning; \
		else \
			echo "No Python modules found to test coverage for"; \
			$(PYTHON) -m pytest -m unit_test --tb=short -W ignore::pytest.PytestUnknownMarkWarning; \
		fi \
	else \
		echo "ERROR: pytest-cov not installed. Install with: pip install pytest-cov"; \
		exit 1; \
	fi

test-coverage-enforced:  ## Run unit tests with coverage and enforce minimum threshold
	@echo "Running unit tests with coverage enforcement (minimum $(MIN_COVERAGE)%)..."
	@if python3 -c "import pytest_cov" 2>/dev/null; then \
		if [ -n "$(COVERAGE_SOURCES)" ]; then \
			$(PYTHON) -m pytest -m unit_test \
				$(addprefix --cov=,$(COVERAGE_TARGETS)) \
				--cov-report=term-missing \
				--cov-report=html:htmlcov \
				--cov-fail-under=$(MIN_COVERAGE) \
				--tb=short \
				-W ignore::pytest.PytestUnknownMarkWarning; \
		else \
			echo "No Python modules found to test coverage for"; \
			$(PYTHON) -m pytest -m unit_test --tb=short -W ignore::pytest.PytestUnknownMarkWarning; \
		fi \
	else \
		echo "ERROR: pytest-cov not installed. Install with: pip install pytest-cov"; \
		exit 1; \
	fi

coverage-report:  ## Generate coverage report without running tests (requires existing .coverage file)
	@echo "Generating coverage report..."
	@if python3 -c "import coverage" 2>/dev/null; then \
		if [ -f .coverage ]; then \
			$(PYTHON) -m coverage report --show-missing; \
			$(PYTHON) -m coverage html -d htmlcov; \
			echo "HTML coverage report generated in htmlcov/"; \
		else \
			echo "No .coverage file found. Run 'make test-coverage' first."; \
		fi \
	else \
		echo "ERROR: coverage not installed. Install with: pip install coverage"; \
	fi

coverage-check:  ## Check coverage for each module individually
	@echo "Checking coverage for individual modules..."
	@$(PYTHON) check_coverage.py --min-coverage $(MIN_COVERAGE)

coverage-enforce:  ## Enforce coverage requirements (fails if any module below threshold)
	@echo "Enforcing coverage requirements (minimum $(MIN_COVERAGE)%)..."
	@$(PYTHON) check_coverage.py --min-coverage $(MIN_COVERAGE) || (echo "Coverage enforcement failed!" && exit 1)

test-bgp:  ## Run only BGP route control tests
	@echo "Running BGP route control unit tests..."
	@python3 -m pytest unit_tests/test_bgp_route_helper.py -m unit_test -v -W ignore::pytest.PytestUnknownMarkWarning

clean:  ## Clean up test artifacts
	@echo "Cleaning up test artifacts..."
	@find . -name "*.pyc" -delete
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache
	@rm -rf htmlcov
	@rm -f .coverage

list-modules:  ## List all Python modules that will be tested for coverage
	@echo "Python modules found for coverage testing:"
	@if [ -n "$(COVERAGE_SOURCES)" ]; then \
		for module in $(COVERAGE_SOURCES); do \
			echo "  - $$module"; \
		done \
	else \
		echo "  No Python modules found"; \
	fi

set-min-coverage:  ## Set minimum coverage threshold (usage: make set-min-coverage MIN_COVERAGE=85)
	@echo "Current minimum coverage threshold: $(MIN_COVERAGE)%"
	@echo "To change it, run: make <target> MIN_COVERAGE=<percentage>"
