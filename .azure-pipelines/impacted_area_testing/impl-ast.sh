#!/bin/bash
# AST-based Impact Analysis Implementation
# Extracted from get-impacted-area-ast.yml for percentage rollout
#
# This script analyzes code changes using AST (Abstract Syntax Tree) analysis to determine
# which test files are impacted by changes in the codebase.

set -e
set -u
set -o pipefail

echo "=========================================="
echo "AST-based Impact Analysis"
echo "=========================================="

git fetch origin
echo "Fetching changes from origin rc = $?"
echo "BUILD_BRANCH (parameter): $BUILD_BRANCH"
echo "GIT BRANCH: $(git branch)"

if [[ "$BUILD_BRANCH" == origin/* ]]; then
  TARGET_BRANCH="$BUILD_BRANCH"
else
  TARGET_BRANCH="origin/$BUILD_BRANCH"
fi

SOURCE_BRANCH=$(git rev-parse HEAD)
echo "SOURCE_BRANCH: $SOURCE_BRANCH"
echo "TARGET_BRANCH: $TARGET_BRANCH"

# Get merge base to handle both direct branch comparison and PR merge commits
MERGE_BASE=$(git merge-base HEAD $TARGET_BRANCH)
echo "MERGE_BASE: $MERGE_BASE"

# Compare HEAD against merge base to get only changes introduced by this branch/PR
CHANGED_FILES=$(git diff --name-only $MERGE_BASE HEAD | tr '\n' ' ')
echo "Changed files (from merge-base):"
echo "$CHANGED_FILES"

if [ -z "$CHANGED_FILES" ]; then
  echo "No changed files"
  PR_CHECKERS="[]"
  TEST_SCRIPTS="{}"
else
  # Detect impacted tests using AST analysis and module dependencies
  # Module dependencies are defined in .azure-pipelines/impacted_area_testing/test_dependencies.json

  # Generate TEST_SCRIPTS with retry logic and proper JSON handling
  # Azure Pipelines could have a transient issue with processing large values in the variable
  # Similar issue has been talked about here
  # Reference: https://stackoverflow.com/questions/78457457/azure-devops-yaml-pipeline-task-output-variable-is-truncating-opening-bracket-fr
  # Solution: Use jq -c to compress JSON to single line (no whitespace/newlines)
  # and handle any other transient variable corruption errors with retries

  MAX_RETRIES=3
  RETRY_COUNT=0
  SUCCESS=false

  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    echo "=========================================="
    echo "Attempt $((RETRY_COUNT + 1)) of $MAX_RETRIES: Analyzing impacted tests..."
    echo "=========================================="

    # Step 1: Detect impacted tests using AST analysis
    # Note: Do NOT use 2>&1 here - we only want stdout (JSON), not stderr (log messages)
    IMPACTED_TESTS=$(python ./.azure-pipelines/impacted_area_testing/detect_function_changes.py \
      --modified_files $CHANGED_FILES \
      --feature_branch $SOURCE_BRANCH \
      --target_branch $TARGET_BRANCH \
      --directory tests \
      --no-log)

    if [[ $? -ne 0 ]]; then
      echo "ERROR: detect_function_changes.py failed on attempt $((RETRY_COUNT + 1))"
      echo "Output: $IMPACTED_TESTS"
      RETRY_COUNT=$((RETRY_COUNT + 1))
      if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        echo "Retrying in 3 seconds..."
        sleep 3
      fi
      continue
    fi

    echo "Impacted tests output:"
    echo "$IMPACTED_TESTS"

    # Validate IMPACTED_TESTS is valid JSON
    if ! echo "$IMPACTED_TESTS" | jq empty > /dev/null 2>&1; then
      echo "ERROR: IMPACTED_TESTS is not valid JSON on attempt $((RETRY_COUNT + 1))"
      echo "Invalid JSON: $IMPACTED_TESTS"
      RETRY_COUNT=$((RETRY_COUNT + 1))
      if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        echo "Retrying in 3 seconds..."
        sleep 3
      fi
      continue
    fi

    # Step 2: Check if we have any impacted tests
    if [[ -n "$IMPACTED_TESTS" ]]; then
      # Extract test file paths
      IMPACTED_TEST_SCRIPTS=$(echo "$IMPACTED_TESTS" | jq -r '(.tests // []) | join(" ")')

      if [[ -z "$IMPACTED_TEST_SCRIPTS" || "$IMPACTED_TEST_SCRIPTS" == "" ]]; then
        echo "No impacted test scripts found in this attempt"
        # This might be valid (no tests impacted), not necessarily an error
        PR_CHECKERS="[]"
        TEST_SCRIPTS="{}"
        SUCCESS=true
        break
      fi

      echo "Impacted test scripts: $IMPACTED_TEST_SCRIPTS"

      # Step 3: Categorize tests by topology
      # CRITICAL: Use jq -c to compress output to single line (prevents Azure Pipelines truncation)
      # Note: Do NOT use 2>&1 here - we only want stdout (JSON), not stderr (log messages)
      TEST_SCRIPTS=$(python ./.azure-pipelines/impacted_area_testing/categorize_test_scripts_by_topology.py \
        --files $IMPACTED_TEST_SCRIPTS)

      if [[ $? -ne 0 ]]; then
        echo "ERROR: categorize_test_scripts_by_topology.py failed on attempt $((RETRY_COUNT + 1))"
        echo "Output: $TEST_SCRIPTS"
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
          echo "Retrying in 3 seconds..."
          sleep 3
        fi
        continue
      fi

      echo "Test scripts (raw output):"
      echo "$TEST_SCRIPTS"

      # Validate TEST_SCRIPTS is valid JSON
      if ! echo "$TEST_SCRIPTS" | jq empty > /dev/null 2>&1; then
        echo "ERROR: TEST_SCRIPTS is not valid JSON on attempt $((RETRY_COUNT + 1))"
        echo "Invalid JSON: $TEST_SCRIPTS"
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
          echo "Retrying in 3 seconds..."
          sleep 3
        fi
        continue
      fi

      # CRITICAL: Compress JSON to single line to avoid Azure Pipelines truncation bug
      # This removes all newlines and unnecessary whitespace
      TEST_SCRIPTS=$(echo "$TEST_SCRIPTS" | jq -c '.')

      if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to compress TEST_SCRIPTS JSON on attempt $((RETRY_COUNT + 1))"
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
          echo "Retrying in 3 seconds..."
          sleep 3
        fi
        continue
      fi

      echo "Test scripts (compressed, single-line JSON):"
      echo "$TEST_SCRIPTS"

      # Step 4: Extract PR checkers (topology types)
      # Also compress to single line
      PR_CHECKERS=$(echo "$TEST_SCRIPTS" | jq -c 'keys')

      if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to extract PR_CHECKERS on attempt $((RETRY_COUNT + 1))"
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
          echo "Retrying in 3 seconds..."
          sleep 3
        fi
        continue
      fi

      # Validate PR_CHECKERS is valid JSON array
      if ! echo "$PR_CHECKERS" | jq empty > /dev/null 2>&1; then
        echo "ERROR: PR_CHECKERS is not valid JSON on attempt $((RETRY_COUNT + 1))"
        echo "Invalid JSON: $PR_CHECKERS"
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
          echo "Retrying in 3 seconds..."
          sleep 3
        fi
        continue
      fi

      echo "PR checkers (compressed):"
      echo "$PR_CHECKERS"

      # All validations passed
      echo "=========================================="
      echo "SUCCESS: All validations passed on attempt $((RETRY_COUNT + 1))"
      echo "=========================================="
      SUCCESS=true
      break

    else
      echo "No impacted tests found (IMPACTED_TESTS is empty)"
      PR_CHECKERS="[]"
      TEST_SCRIPTS="{}"
      SUCCESS=true
      break
    fi
  done

  # Final validation - check if we succeeded
  if [[ "$SUCCESS" != "true" ]]; then
    echo "=========================================="
    echo "FATAL ERROR: Failed to generate valid test scripts after $MAX_RETRIES attempts"
    echo "=========================================="
    echo "Last IMPACTED_TESTS: $IMPACTED_TESTS"
    echo "Last TEST_SCRIPTS: $TEST_SCRIPTS"
    echo "Last PR_CHECKERS: $PR_CHECKERS"
    echo "##vso[task.complete result=Failed;]Failed to generate valid JSON after $MAX_RETRIES attempts"
    exit 1
  fi

  echo "=========================================="
  echo "Final Results:"
  echo "=========================================="
  echo "TEST_SCRIPTS (length: ${#TEST_SCRIPTS}):"
  echo "$TEST_SCRIPTS"
  echo ""
  echo "PR_CHECKERS (length: ${#PR_CHECKERS}):"
  echo "$PR_CHECKERS"
  echo "=========================================="
fi

# Set pipeline variables
# Using compressed single-line JSON to avoid Azure Pipelines truncation bug
echo "##vso[task.setvariable variable=PR_CHECKERS;isOutput=true]$PR_CHECKERS"
echo "##vso[task.setvariable variable=TEST_SCRIPTS;isOutput=true]$TEST_SCRIPTS"
