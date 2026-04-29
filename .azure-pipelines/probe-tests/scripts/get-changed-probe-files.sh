#!/bin/bash
# Script to detect changed files affecting the MMU probe testing infrastructure.
# Mirrors .azure-pipelines/common2/scripts/get-changed-python-files.sh pattern.
#
# Usage:
#   source get-changed-probe-files.sh
#   # Then use $CHANGED_PROBE_FILES and $HAS_CHANGED_PROBE_FILES variables
#
# Probe-relevant paths:
#   - tests/saitests/probe/         (PTF probe runtime + executors)
#   - tests/saitests/mock/          (mock UT/IT tests)
#   - tests/qos/test_qos_probe.py   (pytest entry)

set -e

echo "Checking for added or modified files affecting the MMU probe testing infrastructure..."

BASE_COMMIT=$(git merge-base HEAD origin/master 2>/dev/null || echo HEAD~1)
if [ "$BASE_COMMIT" = "HEAD~1" ]; then
    echo "Warning: Could not determine merge base with origin/master. Comparing with previous commit (HEAD~1)."
else
    echo "Comparing changes since $BASE_COMMIT."
fi

PROBE_PATHS="tests/saitests/probe tests/saitests/mock tests/qos/test_qos_probe.py"

CHANGED_PROBE_FILES=$(git diff --name-status "$BASE_COMMIT" HEAD -- $PROBE_PATHS \
    | grep -E '^(A|M)' \
    | awk '{print $2}' \
    | tr '\n' ' ')

if [ -z "$CHANGED_PROBE_FILES" ]; then
    echo "No probe-relevant files added or modified."
    HAS_CHANGED_PROBE_FILES=false
else
    echo "Found probe-relevant files added or modified: $CHANGED_PROBE_FILES"
    HAS_CHANGED_PROBE_FILES=true
fi

export CHANGED_PROBE_FILES
export HAS_CHANGED_PROBE_FILES
