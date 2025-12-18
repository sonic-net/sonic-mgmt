#!/bin/bash
#
# Standalone test runner for sample tests
# This script runs the sample tests without requiring full sonic-mgmt dependencies
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "Running Sample Tests for Category-Based Skip Management"
echo "======================================================================"
echo ""

echo "Test 1: Running sample tests (basic functionality)..."
echo "----------------------------------------------------------------------"
python -m pytest --rootdir=. test_backward_compat.py test_category_permanent.py -v

echo ""
echo "======================================================================"
echo "Tests completed successfully!"
echo "======================================================================"
echo ""
echo "To test with the conditional mark plugin and category validation:"
echo ""
echo "  python -m pytest --rootdir=. . \\"
echo "    --mark-conditions-files sample_mark_conditions.yaml \\"
echo "    --testbed sample-testbed \\"
echo "    --testbed_file sample_testbed.yaml \\"
echo "    -v"
echo ""
echo "Note: Plugin tests require some basic testbed configuration which may"
echo "show warnings. The core plugin functionality is validated by"
echo "test_implementation.sh"
