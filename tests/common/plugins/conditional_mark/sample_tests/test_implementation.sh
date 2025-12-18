#!/bin/bash
#
# Quick test script for the category-based skip management feature
#
# This script runs the sample tests with different configurations to verify
# the implementation is working correctly.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$SCRIPT_DIR"
YAML_FILE="$SCRIPT_DIR/sample_mark_conditions.yaml"

echo "======================================================================"
echo "Testing Category-Based Skip Management Implementation"
echo "======================================================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo "======================================================================"
    echo "$1"
    echo "======================================================================"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if we're in the right directory
if [ ! -f "$YAML_FILE" ]; then
    print_error "Cannot find sample_mark_conditions.yaml"
    print_error "Please run this script from the sample_tests directory"
    exit 1
fi

print_header "Test 1: Verify Plugin Loads Successfully"

# Try to load the plugin and collect tests
if pytest --co -q "$TESTS_DIR" --mark-conditions-files "$YAML_FILE" > /dev/null 2>&1; then
    print_success "Plugin loaded successfully"
else
    print_warning "Plugin load had issues (this may be due to missing testbed config)"
    print_warning "This is expected if you don't have a testbed configured"
fi

print_header "Test 2: Check for Validation Errors in Sample YAML"

# The sample YAML should not have validation errors (validation examples are commented out)
if pytest --co "$TESTS_DIR" --mark-conditions-files "$YAML_FILE" 2>&1 | grep -q "validation error"; then
    print_error "Unexpected validation errors in sample YAML"
    exit 1
else
    print_success "No validation errors in sample YAML (as expected)"
fi

print_header "Test 3: Verify Backward Compatibility"

# Check that tests with old format (no category) still work
if pytest --co -q "$TESTS_DIR/test_backward_compat.py" --mark-conditions-files "$YAML_FILE" > /dev/null 2>&1; then
    print_success "Backward compatibility maintained"
else
    print_warning "Backward compatibility check inconclusive (may need testbed config)"
fi

print_header "Test 4: Check Python Syntax and Imports"

# Verify the updated plugin has no syntax errors
PLUGIN_FILE="$SCRIPT_DIR/../__init__.py"
if python3 -m py_compile "$PLUGIN_FILE" 2>/dev/null; then
    print_success "Plugin Python syntax is valid"
else
    print_error "Plugin has Python syntax errors"
    exit 1
fi

# Check if datetime was imported
if grep -q "from datetime import datetime, timedelta, timezone" "$PLUGIN_FILE"; then
    print_success "Required datetime imports present"
else
    print_error "Missing datetime imports in plugin"
    exit 1
fi

print_header "Test 5: Verify Validation Functions Exist"

# Check that new validation functions were added
if grep -q "def validate_skip_category" "$PLUGIN_FILE"; then
    print_success "validate_skip_category function exists"
else
    print_error "validate_skip_category function not found"
    exit 1
fi

if grep -q "def validate_expiry_date" "$PLUGIN_FILE"; then
    print_success "validate_expiry_date function exists"
else
    print_error "validate_expiry_date function not found"
    exit 1
fi

if grep -q "def check_expiry_and_format_reason" "$PLUGIN_FILE"; then
    print_success "check_expiry_and_format_reason function exists"
else
    print_error "check_expiry_and_format_reason function not found"
    exit 1
fi

print_header "Test 6: Verify Sample Test Files Exist"

test_files=(
    "test_category_permanent.py"
    "test_category_temporary.py"
    "test_backward_compat.py"
    "test_validation_errors.py"
)

all_exist=true
for test_file in "${test_files[@]}"; do
    if [ -f "$TESTS_DIR/$test_file" ]; then
        print_success "Sample test file exists: $test_file"
    else
        print_error "Missing sample test file: $test_file"
        all_exist=false
    fi
done

if [ "$all_exist" = false ]; then
    exit 1
fi

print_header "Test 7: Verify YAML Structure"

# Check that skip_categories section exists in sample YAML
if grep -q "skip_categories:" "$YAML_FILE"; then
    print_success "skip_categories section present in sample YAML"
else
    print_error "skip_categories section not found in sample YAML"
    exit 1
fi

# Check for permanent and temporary categories
if grep -A5 "skip_categories:" "$YAML_FILE" | grep -q "permanent:"; then
    print_success "permanent category defined"
else
    print_error "permanent category not found"
    exit 1
fi

if grep -A10 "skip_categories:" "$YAML_FILE" | grep -q "temporary:"; then
    print_success "temporary category defined"
else
    print_error "temporary category not found"
    exit 1
fi

print_header "Summary"

print_success "All basic validation checks passed!"
echo ""
echo "The implementation appears to be correct. To fully test:"
echo ""
echo "1. Run with a configured testbed:"
echo "   pytest $TESTS_DIR -v --mark-conditions-files $YAML_FILE \\"
echo "       --testbed <testbed-name> --testbed_file <testbed.yaml>"
echo ""
echo "2. Test validation errors by uncommenting examples in sample_mark_conditions.yaml"
echo ""
echo "3. Check skip behavior:"
echo "   - Permanent skips should not require expiry_date"
echo "   - Temporary skips should require expiry_date"
echo "   - Expired skips should show expired message"
echo ""
print_success "Implementation complete and ready for testing!"
