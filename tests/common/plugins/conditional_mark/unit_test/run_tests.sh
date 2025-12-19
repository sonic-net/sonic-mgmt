#!/bin/bash

# Run unit tests for category and expiry validation

cd "$(dirname "$0")"

echo "========================================================================"
echo "Running Category and Expiry Validation Unit Tests"
echo "========================================================================"
echo ""

echo "1. Unit Tests (Programmatic):"
echo "----------------------------------------------------------------------"
/home/sagummaraj/.pyenv/versions/dev/bin/python unittest_category_expiry.py -v

echo ""
echo "2. Unit Tests (YAML-based):"
echo "----------------------------------------------------------------------"
/home/sagummaraj/.pyenv/versions/dev/bin/python unittest_yaml_skip_categories.py -v

echo ""
echo "========================================================================"
echo "Test Coverage:"
echo "  ✓ Category validation (permanent/temporary)"
echo "  ✓ Expiry date validation (required, format, max days)"
echo "  ✓ Expired skip handling"
echo "  ✓ Backward compatibility (no category)"
echo "  ✓ Error reporting"
echo "  ✓ YAML-based configuration testing"
echo ""
echo "To modify test scenarios:"
echo "  Edit: tests_skip_categories.yaml"
echo "========================================================================"
