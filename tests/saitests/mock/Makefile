# Makefile for tests/saitests/mock — MMU probe UT/IT
#
# Targets:
#   make ut        — run unit tests (mock/ut/)
#   make it        — run integration tests (mock/it/)
#   make all       — run both
#   make coverage  — run UT with HTML coverage report (uses pytest.ini cov config)
#   make clean     — remove pytest cache, pyc, htmlcov
#
# Note: The pytest.ini files in ut/ and it/ already configure coverage and warnings.
# This Makefile is a convenience wrapper for local development; the Azure Pipeline
# (probe-tests stage) invokes pytest directly.

PYTHON := python3
UT_DIR := ut
IT_DIR := it

.PHONY: help ut it all coverage clean

help:
	@echo "Available targets:"
	@echo "  ut         - Run probe unit tests (mock/ut/)"
	@echo "  it         - Run probe integration tests (mock/it/)"
	@echo "  all        - Run both UT and IT"
	@echo "  coverage   - Run UT with HTML coverage report"
	@echo "  clean      - Remove caches and reports"

ut:
	@echo "===== Running probe Unit Tests ====="
	cd $(UT_DIR) && $(PYTHON) -m pytest . --tb=short

it:
	@echo "===== Running probe Integration Tests ====="
	cd $(IT_DIR) && $(PYTHON) -m pytest . --tb=short

all: ut it

coverage:
	@echo "===== Running probe UT with coverage ====="
	cd $(UT_DIR) && $(PYTHON) -m pytest . --cov=../../probe --cov-report=html:htmlcov --cov-report=term-missing --tb=short
	@echo "HTML coverage report: $(UT_DIR)/htmlcov/index.html"

clean:
	@echo "Cleaning probe test artifacts..."
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete
	@rm -rf $(UT_DIR)/.pytest_cache $(IT_DIR)/.pytest_cache
	@rm -rf $(UT_DIR)/htmlcov $(IT_DIR)/htmlcov
	@rm -f $(UT_DIR)/.coverage $(IT_DIR)/.coverage
