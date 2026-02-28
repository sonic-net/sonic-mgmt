#!/bin/bash

# Run unit tests for category and expiry validation

cd "$(dirname "$0")"

echo "========================================================================"
echo "Running Category and Expiry Validation Unit Tests"
echo "========================================================================"
echo ""

echo "1. Unit Tests (Programmatic):"
echo "----------------------------------------------------------------------"
python unittest_category_expiry.py -v

echo ""
echo "2. Unit Tests (YAML-based):"
echo "----------------------------------------------------------------------"
python unittest_yaml_skip_categories.py -v
