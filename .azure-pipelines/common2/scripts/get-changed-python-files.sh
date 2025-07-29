#!/bin/bash

# Script to detect changed files in tests/common2/
# This script is reused by multiple Azure Pipeline steps to avoid code duplication
#
# Usage:
#   source get-changed-python-files.sh [python-only]
#   # Then use $CHANGED_PYTHON_FILES and $CHANGED_FILES variables
#
# Parameters:
#   python-only: if specified, only looks for Python files (default behavior)
#   all: looks for all changed files

set -e

FILTER_MODE=${1:-python-only}

echo "Checking for added or modified files in tests/common2..."

# Determine the base commit to compare against
# This is robust for PRs (merging into main/master) and direct pushes
BASE_COMMIT=$(git merge-base HEAD origin/master || echo HEAD~1)
if [ "$BASE_COMMIT" = "HEAD~1" ]; then
    echo "Warning: Could not determine merge base with origin/master. Comparing with previous commit (HEAD~1)."
else
    echo "Comparing changes since $BASE_COMMIT."
fi

if [ "$FILTER_MODE" = "all" ]; then
    # Get all changed files in tests/common2
    CHANGED_FILES=$(git diff --name-only "$BASE_COMMIT" HEAD -- tests/common2 | tr '\n' ' ')

    if [ -z "$CHANGED_FILES" ]; then
        echo "No files added or modified in tests/common2 in this commit."
        HAS_CHANGED_FILES=false
    else
        echo "Found files added or modified: $CHANGED_FILES"
        HAS_CHANGED_FILES=true
    fi

    # Also set Python-specific variables for compatibility
    CHANGED_PYTHON_FILES=$(git diff --name-status "$BASE_COMMIT" HEAD -- tests/common2 | grep -E '^(A|M).*py$' | awk '{print $2}' | tr '\n' ' ')
    HAS_CHANGED_PYTHON_FILES=$( [ -n "$CHANGED_PYTHON_FILES" ] && echo true || echo false )
else
    # Get names of added (A) or modified (M) files, filter to .py and tests/common2
    # The '^(A|M)' regular expression ensures we only match lines starting with A or M
    CHANGED_PYTHON_FILES=$(git diff --name-status "$BASE_COMMIT" HEAD -- tests/common2 | grep -E '^(A|M).*py$' | awk '{print $2}' | tr '\n' ' ')

    if [ -z "$CHANGED_PYTHON_FILES" ]; then
        echo "No .py files added or modified in tests/common2 in this commit."
        HAS_CHANGED_PYTHON_FILES=false
    else
        echo "Found .py files added or modified: $CHANGED_PYTHON_FILES"
        HAS_CHANGED_PYTHON_FILES=true
    fi

    # Also set general files variables for compatibility
    CHANGED_FILES="$CHANGED_PYTHON_FILES"
    HAS_CHANGED_FILES="$HAS_CHANGED_PYTHON_FILES"
fi

# Export variables so they can be used by the calling script
export CHANGED_PYTHON_FILES
export HAS_CHANGED_PYTHON_FILES
export CHANGED_FILES
export HAS_CHANGED_FILES
