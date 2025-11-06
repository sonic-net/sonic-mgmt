#!/usr/bin/env bash

function handle_test_failure() {
  local step_exit_code=$?
  if [ $step_exit_code -eq 0 ]; then
          # Completed successfully
          exit 0
      fi
  local test_name="$1"
  local error_msg="$2"
  local error_type="$3"
  local testbed_name="$4"

  echo "Test step failed. Generating tr.json for: $test_name"
  python3 "$BUILD_SOURCESDIRECTORY/sonic-mgmt-int/test_reporting/generate_tr_json.py"\
    --output tr.json \
    --test-name "$test_name" \
    --result "error" \
    --error-msg "$error_msg" \
    --error-type "$error_type" \
    --testbed "$testbed_name"

  accessToken=$(az account get-access-token --resource https://api.kusto.windows.net --query accessToken -o tsv)
  export ACCESS_TOKEN=$accessToken

  echo "Uploading report to Kusto..."
  python3 "$BUILD_SOURCESDIRECTORY/sonic-mgmt-int/test_reporting/report_uploader.py" \
    -j tr.json SonicTestData \
    -c test_result \
    -e "${BUILD_DEFINITIONNAME}#${BUILD_BUILDID}" \
    -t "$testbed_name"
}
