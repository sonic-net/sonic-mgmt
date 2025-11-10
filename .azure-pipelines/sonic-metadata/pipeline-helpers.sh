#!/usr/bin/env bash

# upload_failure_report: always generate & upload a failure report.
# Does NOT change the caller's exit code; caller can choose to exit non-zero afterwards.
# Usage (direct call from a dedicated step):
#   upload_failure_report "<test_name>" "<error_msg>" "<error_type>" "<testbed_name>"
#
# Usage (trap-based steps):
#   trap 'upload_failure_report "upgrade_path::deploy_minigraph" \
#         "Minigraph deployment failed" \
#         "DEPLOY_MINIGRAPH" \
#         "${TESTBED_NAME}"' ERR
function upload_failure_report() {
  local test_name="$1"
  local error_msg="$2"
  local error_type="$3"
  local testbed_name="$4"

  echo "Uploading failure report for: $test_name"
  python3 "$BUILD_SOURCESDIRECTORY/sonic-mgmt-int/test_reporting/generate_tr_json.py" \
    --output tr.json \
    --test-name "$test_name" \
    --result "error" \
    --error-msg "$error_msg" \
    --error-type "$error_type" \
    --testbed "$testbed_name"

  accessToken=$(az account get-access-token --resource https://api.kusto.windows.net --query accessToken -o tsv) || {
    echo "Failed to obtain access token for Kusto upload" >&2
    return 1
  }
  export ACCESS_TOKEN=$accessToken

  echo "Uploading report to Kusto..."
  python3 "$BUILD_SOURCESDIRECTORY/sonic-mgmt-int/test_reporting/report_uploader.py" \
    -j tr.json SonicTestData \
    -c test_result \
    -e "${BUILD_DEFINITIONNAME}#${BUILD_BUILDID}" \
    -t "$testbed_name"
}
