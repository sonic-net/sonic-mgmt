#!/bin/bash
# Legacy Directory-based Impact Analysis Implementation
# Extracted from master branch get-impacted-area.yml for percentage rollout
#
# This script analyzes code changes using directory-based analysis to determine
# which test files are impacted by changes in the codebase.

set -x

echo "=========================================="
echo "Legacy Directory-based Impact Analysis"
echo "=========================================="

git fetch --all
DIFF_FOLDERS=$(git diff $(git merge-base origin/$BUILD_BRANCH HEAD)..HEAD --name-only | xargs -n1 dirname | sort -u | tr '\n' ' ')

if [[ $? -ne 0 ]]; then
  echo "##vso[task.complete result=Failed;]Get diff folders fails."
  exit 1
fi

echo "DIFF_FOLDERS: $DIFF_FOLDERS"

pip install PyYAML
pip install natsort

FINAL_FEATURES=""
IFS=' ' read -ra FEATURES_LIST <<< "$DIFF_FOLDERS"

# Define the list of folders include common features
COMMON_DIRS=("tests/common" "tests/scripts")

for FEATURE in "${FEATURES_LIST[@]}"
do
  for COMMON_DIR in "${COMMON_DIRS[@]}"; do
    if [[ "$FEATURE" == *$COMMON_DIR* ]]; then
      FINAL_FEATURES=""
      break 2
    fi
  done

  # If changes only limited to specific feature, the scope of PR testing is impacted area.
  if [[ "$FEATURE" =~ ^tests\/.* ]]; then
    # Cut the feature path
    if [[ $FEATURE == */*/* ]]; then
        FEATURE=$(echo "$FEATURE" | cut -d'/' -f1-2)
    fi

    FEATURE=${FEATURE#tests/}

    if [[ -z "$FINAL_FEATURES" ]]; then
      FINAL_FEATURES="$FEATURE"
    elif [[ ! "$FINAL_FEATURES" == *$FEATURE* ]]; then
      FINAL_FEATURES="$FINAL_FEATURES,$FEATURE"
    fi

  # If changes related to other folders except tests, we also consider them as common part.
  # The scope of PR testing is all test scripts.
  else
    FINAL_FEATURES=""
    break
  fi
done

echo "FINAL_FEATURES: $FINAL_FEATURES"

# Generate TEST_SCRIPTS with retry logic for JSON validation
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  echo "Attempt $((RETRY_COUNT + 1)): Generating test scripts..."

  TEST_SCRIPTS=$(python ./.azure-pipelines/impacted_area_testing/get_test_scripts.py --features ${FINAL_FEATURES} --location tests)

  if [[ $? -ne 0 ]]; then
    echo "Get test scripts command failed on attempt $((RETRY_COUNT + 1))"
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
      echo "Retrying in 2 seconds..."
      sleep 2
    fi
    continue
  fi

  # Validate TEST_SCRIPTS is valid JSON
  if echo "$TEST_SCRIPTS" | jq empty > /dev/null 2>&1; then
    echo "TEST_SCRIPTS is valid JSON: $TEST_SCRIPTS"

    # Generate PR_CHECKERS
    PR_CHECKERS=$(echo "${TEST_SCRIPTS}" | jq -c 'keys')

    if [[ $? -eq 0 ]] && echo "$PR_CHECKERS" | jq empty > /dev/null 2>&1; then
      echo "PR_CHECKERS is valid list: $PR_CHECKERS"
      echo "All validations passed successfully"
      break
    else
      echo "PR_CHECKERS generation failed or invalid list: $PR_CHECKERS"
    fi
  else
    echo "TEST_SCRIPTS is not valid JSON: $TEST_SCRIPTS"
  fi

  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
    echo "Retrying in 2 seconds..."
    sleep 2
  fi
done

# Final validation
if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
  echo "##vso[task.complete result=Failed;]Failed to generate valid JSON after $MAX_RETRIES attempts. Last TEST_SCRIPTS: $TEST_SCRIPTS"
  exit 1
fi

echo "Final TEST_SCRIPTS: $TEST_SCRIPTS"
echo "Final PR_CHECKERS: $PR_CHECKERS"

echo "##vso[task.setvariable variable=PR_CHECKERS;isOutput=true]$PR_CHECKERS"
echo "##vso[task.setvariable variable=TEST_SCRIPTS;isOutput=true]$TEST_SCRIPTS"
