# Demyst Notification Module - Design Document

## Overview

Sends test run information to the Demyst server for automated AI-based test failure analysis. Called after ring4 test completion from `do_full_run.py`.

## Module Structure

```
infra/demyst/
├── notify_demyst.py    # Main orchestration - validates inputs, builds payload, sends to server
└── utils.py            # Reusable utilities - validation, SSH, URL checks, HTTP communication
```

## notify_demyst.py

**Purpose**: Main entry point that orchestrates the notification workflow.

**Function**: `notify_demyst(testbed, build_id, jenkins_build_id, stream, allure_report_url, syslogs_url, testbed_info_dict, container_name, pipeline_type) -> Tuple[bool, Optional[str]]`

**Flow**:
1. Receives `pipeline_type` as parameter (caller reads from environment)
2. Validates it's a ring4 pipeline
3. Validates required input fields (jenkins_build_id, allure_report_url, syslogs_url)
4. Checks syslogs URL exists
5. Validates testbed configuration (topology, UCS credentials)
6. Fetches sonic_test commit from UCS container via SSH
7. Builds payload with all required fields
8. Sends POST request to demyst server
9. Returns success status and results URL

**Configuration**:
- `DEMYST_SERVER_URL`: `https://demyst.cisco.com:10003/api/v1/analysis/offline`

**Return Values**:
- `(True, url)` - Successfully sent, demyst URL returned
- `(True, None)` - Skipped (not ring4 pipeline)
- `(False, None)` - Validation failed or network/server error occurred

## utils.py

**Purpose**: Reusable utility functions organized by category.

### Validation Functions

**`is_ring4_pipeline(pipeline_type: str) -> bool`**
- Checks if pipeline type equals "ring4" (case-insensitive)

**`validate_demyst_inputs(jenkins_build_id, allure_report_url, syslogs_url) -> bool`**
- Validates required input fields are present
- Logs missing fields at INFO level
- Returns False if any field is missing

**`validate_testbed_config(testbed_info_dict, testbed_name) -> dict | None`**
- Validates testbed configuration by checking hw_cfg.json (required fields: topology, ucs_host, ucs_username, ucs_password)
- Returns dict with validated fields if valid, None otherwise
- Logs specific missing fields for debugging

### SSH Functions

**`run_ssh_cmd(client, cmd) -> tuple[str, str, int]`**
- Executes SSH command and returns (stdout, stderr, return_code)

**`get_sonic_test_commit(ucs_host, ucs_username, ucs_password, container_name) -> str`**
- Connects to UCS server via SSH
- Inspects sonic-mgmt container to find sonic-test mount path
- Runs `git rev-parse HEAD` to get commit hash
- Returns commit hash or empty string if failed

### URL Functions

**`get_syslogs_url(base_url) -> str | None`**
- Appends `sanity_logs.tar.gz` to base URL
- Makes HEAD request to verify file exists
- Returns full URL if found, None otherwise
- Suppresses SSL warnings for internal servers

### Server Communication

**`send_to_demyst(payload, server_url) -> tuple[bool, str | None]`**
- Sends POST request to demyst server with JSON payload
- Tries with system proxy first, falls back to no proxy
- Handles server responses:
  - 200/202: Success, returns (True, results_url)
  - 400 with status="not_supported": Skipped by server, returns (True, None)
  - Other errors: Returns (False, None)
- Suppresses SSL warnings for internal servers

## Payload Structure

The client builds and sends this JSON payload to the demyst server:

```json
{
  "build_id": "12345",
  "submitter_cec_id": "cicd_t1-m3-4-cmono",
  "run_id": "t1-m3-4-cmono_67890",
  "sonic_test_commit_id": "abc123...",
  "log_source": "allure_url",
  "allure_report_url": "https://allure.cisco.com/.../allure-report/",
  "syslogs_url": "https://logs.cisco.com/.../sanity_logs.tar.gz",
  "testbed": "t1-m3-4-cmono",
  "stream": "cisco.202511.1.signed",
  "topo_type": "t1",
  "run_type": "hardware",
  "sonic_test_repo_url": "sonic-test",
  "require_approval": false
}
```

### Field Descriptions

| Field | Value | Description |
|-------|-------|-------------|
| `build_id` | From parameter | Sonic buildimage build ID |
| `submitter_cec_id` | `cicd_{testbed}` | Identifies CICD submission |
| `run_id` | `{testbed}_{jenkins_build_id}` | Unique identifier for this run |
| `sonic_test_commit_id` | From UCS SSH | Git commit hash from sonic-test repo |
| `log_source` | `"allure_url"` | Indicates logs are from Allure URL |
| `allure_report_url` | From parameter | URL to Allure report |
| `syslogs_url` | Validated URL | Full path to sanity_logs.tar.gz |
| `testbed` | From parameter | Testbed name (server resolves to platform) |
| `stream` | From parameter | Stream name (server validates against allowlist) |
| `topo_type` | From testbed_info_dict | Topology type (t0, t1, etc.) |
| `run_type` | `"hardware"` | Always hardware for ring4 |
| `sonic_test_repo_url` | `"sonic-test"` | Repo identifier |
| `require_approval` | `false` | Auto-approved for CICD |
