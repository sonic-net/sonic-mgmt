#!/bin/bash
#
# Local Testing Script for Impacted Area Testing
#
# This script simulates the CI pipeline's impact analysis locally, allowing you to:
# - Test against specific branches or commits
# - Apply patch files to see what tests would run
# - Debug issues found in CI runs
#
# Usage:
#   ./test_locally.sh [options]
#
# Options:
#   --target-branch <branch>    Target branch to compare against (default: origin/master)
#   --source-branch <branch>    Source branch or commit to test (default: HEAD)
#   --patch <file>              Apply a patch file before testing
#   --trace                     Enable detailed trace logging
#   --help                      Show this help message
#
# Examples:
#   # Test current changes against master
#   ./test_locally.sh
#
#   # Test specific branch
#   ./test_locally.sh --source-branch my-feature-branch
#
#   # Test with a patch file
#   ./test_locally.sh --patch /path/to/changes.patch
#
#   # Compare two specific commits
#   ./test_locally.sh --target-branch abc123 --source-branch def456
#
#   # Enable detailed debugging
#   ./test_locally.sh --trace
#

set -e

# Default values
TARGET_BRANCH="origin/master"
SOURCE_BRANCH="HEAD"
PATCH_FILE=""
TRACE=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target-branch)
            TARGET_BRANCH="$2"
            shift 2
            ;;
        --source-branch)
            SOURCE_BRANCH="$2"
            shift 2
            ;;
        --patch)
            PATCH_FILE="$2"
            shift 2
            ;;
        --trace)
            TRACE="--trace"
            shift
            ;;
        --help)
            grep "^#" "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Run with --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Impacted Area Testing - Local Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Change to repo root
cd "$REPO_ROOT"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}Error: Not in a git repository${NC}"
    exit 1
fi

# Apply patch if provided
TEMP_BRANCH=""
if [[ -n "$PATCH_FILE" ]]; then
    if [[ ! -f "$PATCH_FILE" ]]; then
        echo -e "${RED}Error: Patch file not found: $PATCH_FILE${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Applying patch file: $PATCH_FILE${NC}"

    # Create a temporary branch to apply the patch
    TEMP_BRANCH="temp-test-$(date +%s)"
    git checkout -b "$TEMP_BRANCH" 2>/dev/null || true

    # Apply the patch
    if git apply --check "$PATCH_FILE" 2>/dev/null; then
        git apply "$PATCH_FILE"
        # Commit the applied patch on temp branch so commit-to-commit diff picks it up
        PATCHED_FILES=$(git diff --name-only)
        git config user.email "impact-local-test@example.com" >/dev/null 2>&1 || true
        git config user.name "impact-local-test" >/dev/null 2>&1 || true
        if [[ -n "$PATCHED_FILES" ]]; then
            git add $PATCHED_FILES
            git commit --no-verify -m "test_locally: apply patch" >/dev/null 2>&1 || true
        fi
        SOURCE_BRANCH="$TEMP_BRANCH"
        echo -e "${GREEN}Patch applied successfully${NC}"
    else
        echo -e "${RED}Error: Failed to apply patch${NC}"
        git checkout - 2>/dev/null || true
        git branch -D "$TEMP_BRANCH" 2>/dev/null || true
        exit 1
    fi
    echo ""
fi

# Ensure target branch exists
if ! git rev-parse --verify "$TARGET_BRANCH" > /dev/null 2>&1; then
    echo -e "${RED}Error: Target branch not found: $TARGET_BRANCH${NC}"
    [[ -n "$TEMP_BRANCH" ]] && git checkout - && git branch -D "$TEMP_BRANCH"
    exit 1
fi

# Ensure source branch exists
if ! git rev-parse --verify "$SOURCE_BRANCH" > /dev/null 2>&1; then
    echo -e "${RED}Error: Source branch not found: $SOURCE_BRANCH${NC}"
    [[ -n "$TEMP_BRANCH" ]] && git checkout - && git branch -D "$TEMP_BRANCH"
    exit 1
fi

echo -e "${BLUE}Configuration:${NC}"
echo "  Target Branch: $TARGET_BRANCH"
echo "  Source Branch: $SOURCE_BRANCH"
echo "  Trace Logging: ${TRACE:-disabled}"
echo ""

# Get the diff
echo -e "${YELLOW}Getting changed files...${NC}"
CHANGED_FILES=$(git diff --name-only "$TARGET_BRANCH...$SOURCE_BRANCH" | tr '\n' ' ')

if [[ -z "$CHANGED_FILES" ]]; then
    echo -e "${YELLOW}No changed files detected${NC}"
    echo ""
    echo -e "${GREEN}Result:${NC}"
    echo "  PR_CHECKERS: []"
    echo "  TEST_SCRIPTS: {}"
    [[ -n "$TEMP_BRANCH" ]] && git checkout - && git branch -D "$TEMP_BRANCH"
    exit 0
fi

echo -e "${GREEN}Changed files:${NC}"
for file in $CHANGED_FILES; do
    echo "  - $file"
done
echo ""

# Run the impact detection
echo -e "${YELLOW}Running impact analysis...${NC}"

# Stay in repo root so relative paths work, but reference the script with full path
DETECT_ARGS="--modified_files $CHANGED_FILES --feature_branch $SOURCE_BRANCH --target_branch $TARGET_BRANCH --directory tests --no-log"
if [[ -n "$TRACE" ]]; then
    DETECT_ARGS=$(echo "$DETECT_ARGS" | sed 's/--no-log//')
    DETECT_ARGS="$DETECT_ARGS $TRACE"
fi

# Run impact detection, capture stdout separately from stderr
# Stderr (warnings/logs) goes to terminal, stdout (JSON) goes to variable
if [[ -n "$TRACE" ]]; then
    # In trace mode, show stderr for debugging
    IMPACTED_TESTS=$(python "$SCRIPT_DIR/detect_function_changes.py" $DETECT_ARGS)
    EXIT_CODE=$?
else
    # In normal mode, suppress stderr (only contains "Loaded N module dependency rules")
    IMPACTED_TESTS=$(python "$SCRIPT_DIR/detect_function_changes.py" $DETECT_ARGS 2>/dev/null)
    EXIT_CODE=$?
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Impact Analysis Results${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [[ $EXIT_CODE -ne 0 ]]; then
    echo -e "${RED}Error: Impact detection failed with exit code $EXIT_CODE${NC}"
    echo "$IMPACTED_TESTS"
    [[ -n "$TEMP_BRANCH" ]] && cd "$REPO_ROOT" && git checkout - && git branch -D "$TEMP_BRANCH"
    exit 1
fi

# Parse the JSON output
if ! echo "$IMPACTED_TESTS" | jq empty > /dev/null 2>&1; then
    echo -e "${RED}Error: Invalid JSON output from impact detection${NC}"
    echo "$IMPACTED_TESTS"
    [[ -n "$TEMP_BRANCH" ]] && cd "$REPO_ROOT" && git checkout - && git branch -D "$TEMP_BRANCH"
    exit 1
fi

echo -e "${GREEN}Raw Impact Analysis Output:${NC}"
echo "$IMPACTED_TESTS" | jq '.'
echo ""

# Extract test files
IMPACTED_TEST_SCRIPTS=$(echo "$IMPACTED_TESTS" | jq -r '(.tests // []) | join(" ")')

if [[ -z "$IMPACTED_TEST_SCRIPTS" ]]; then
    echo -e "${YELLOW}No impacted tests found${NC}"
    echo ""
    echo -e "${GREEN}Result:${NC}"
    echo "  PR_CHECKERS: []"
    echo "  TEST_SCRIPTS: {}"
    [[ -n "$TEMP_BRANCH" ]] && cd "$REPO_ROOT" && git checkout - && git branch -D "$TEMP_BRANCH"
    exit 0
fi

echo -e "${GREEN}Impacted Test Files (${NC}$(echo "$IMPACTED_TEST_SCRIPTS" | wc -w)${GREEN}):${NC}"
for test in $IMPACTED_TEST_SCRIPTS; do
    echo "  - $test"
done
echo ""

# Categorize by topology
echo -e "${YELLOW}Categorizing tests by topology...${NC}"
# Capture stdout (JSON) separately from stderr (warnings)
TEST_SCRIPTS=$(python "$SCRIPT_DIR/categorize_test_scripts_by_topology.py" --files $IMPACTED_TEST_SCRIPTS 2>/dev/null)
EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
    echo -e "${RED}Error: Test categorization failed with exit code $EXIT_CODE${NC}"
    echo "$TEST_SCRIPTS"
    [[ -n "$TEMP_BRANCH" ]] && cd "$REPO_ROOT" && git checkout - && git branch -D "$TEMP_BRANCH"
    exit 1
fi

echo ""
echo -e "${GREEN}Categorized Test Scripts:${NC}"
echo "$TEST_SCRIPTS" | jq '.'
echo ""

# Extract PR checkers
PR_CHECKERS=$(echo "$TEST_SCRIPTS" | jq -c 'keys')

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Final Pipeline Variables${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}PR_CHECKERS:${NC}"
echo "$PR_CHECKERS" | jq '.'
echo ""
echo -e "${GREEN}TEST_SCRIPTS:${NC}"
echo "$TEST_SCRIPTS" | jq '.'
echo ""

# Summary statistics
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Changed Files:${NC} $(echo "$CHANGED_FILES" | wc -w)"
echo -e "${GREEN}Impacted Test Files:${NC} $(echo "$IMPACTED_TEST_SCRIPTS" | wc -w)"
echo -e "${GREEN}Topology Checkers:${NC} $(echo "$PR_CHECKERS" | jq '. | length')"
echo ""

# Show per-topology counts
for checker in $(echo "$PR_CHECKERS" | jq -r '.[]'); do
    count=$(echo "$TEST_SCRIPTS" | jq -r --arg checker "$checker" '.[$checker] | length')
    echo "  - ${checker}: ${count} tests"
done
echo ""

# Cleanup temp branch if created
if [[ -n "$TEMP_BRANCH" ]]; then
    echo -e "${YELLOW}Cleaning up temporary branch...${NC}"
    cd "$REPO_ROOT"
    git checkout - > /dev/null 2>&1
    git branch -D "$TEMP_BRANCH" > /dev/null 2>&1
    echo -e "${GREEN}Cleanup complete${NC}"
    echo ""
fi

echo -e "${GREEN}✓ Local testing complete!${NC}"
