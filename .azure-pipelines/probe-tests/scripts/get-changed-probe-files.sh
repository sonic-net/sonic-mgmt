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

# Resolve the target branch we should compute the merge-base against.
# In Azure Pipelines PR context, $SYSTEM_PULLREQUEST_TARGETBRANCH carries the
# PR target ("master", "refs/heads/202405", etc.); strip refs/heads/ if present.
# In a non-PR (manual / push) context, fall back to "master".
TARGET_BRANCH_RAW="${SYSTEM_PULLREQUEST_TARGETBRANCH:-master}"
TARGET_BRANCH="${TARGET_BRANCH_RAW#refs/heads/}"
TARGET_REF="origin/${TARGET_BRANCH}"

echo "Checking for added or modified files affecting the MMU probe testing infrastructure (vs ${TARGET_REF})..."

BASE_COMMIT=$(git merge-base HEAD "${TARGET_REF}" 2>/dev/null || echo HEAD~1)
if [ "$BASE_COMMIT" = "HEAD~1" ]; then
    echo "Warning: Could not determine merge base with ${TARGET_REF}. Comparing with previous commit (HEAD~1)."
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
