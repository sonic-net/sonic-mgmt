# Demyst Notification Script

Notifies the Demyst server after ring4 test completion for automated test failure analysis.

## Usage

```bash
python3 notify_demyst.py --pipeline-type <TYPE> -t <TESTBED> -b <BUILD_ID> -r <RUN_ID> -m <STREAM> --results-json <PATH>
```

### Arguments

| Argument | Description | Example |
|----------|-------------|----------|
| `-p, --pipeline-type` | Pipeline type (e.g., ring4) | `ring4` |
| `-t, --testbed` | Testbed name (key in hw_cfg.json) | `t1-m3-4-cmono` |
| `-b, --build_id` | Sonic buildimage build ID (p2build_job_id) | `40126` |
| `-r, --run_id` | Jenkins job build ID | `5243` |
| `-m, --stream` | Stream name (for container lookup) | `202405`, `master` |
| `-j, --results-json` | Path to results.json file | `$WORKSPACE/results.json` |

### Example (from Jenkins)

```bash
python3 ./demyst/notify_demyst.py \
    -p $PIPELINE_TYPE \
    -t $TEST_BED \
    -b $P2_BUILD_JOB_ID \
    -r $BUILD_ID \
    -m $STREAM \
    -j $WORKSPACE/results.json
```

## Prerequisites

1. `--pipeline-type` must be `ring4` to send notification (other types skip gracefully)
2. Testbed must be listed in `supported_testbeds.txt`
3. Testbed must exist in `hw_cfg.json` (validated via `hw_setup_utils`)
4. `results.json` must contain `report_link` and `log_tarball_link` fields


## Payload Fields

| Field | Source | Description |
|-------|--------|-------------|
| `build_id` | CLI `-b` | Sonic buildimage build ID |
| `run_id` | Generated | `{testbed}_{run_id}_{timestamp}` |
| `testbed` | CLI `-t` | Testbed name (server resolves platform) |
| `topo_type` | hw_cfg.json | Topology type (e.g., `t0`, `t1`) |
| `sonic_test_commit_id` | UCS container | Commit from sonic-mgmt container's mounted sonic-test dir |
| `log_source` | | `"allure_url"` |
| `allure_report_url` | results.json `report_link` | Allure report URL |
| `syslogs_url` | results.json `log_tarball_link` | Syslogs tarball URL |
| `run_type` | | `"hardware"` |
| `sonic_test_repo_url` | | `"sonic-test"` |

## Configuration Files

### supported_testbeds.txt

```
# Supported testbeds for demyst analysis
t1-m3-4-cmono
```

## Exit Codes

| Code | Meaning |
|------|----------|
| 0 | Request sent successfully, or skipped (not ring4) |
| 1 | Error (testbed not supported, missing results.json fields, server error, etc.) |

## Logging

Logs are written to `NOTIFY_DEMYST.log`

## Files

| File | Description |
|------|-------------|
| `notify_demyst.py` | Main notification script |
| `supported_testbeds.txt` | Whitelist of supported testbeds |
| `README.md` | This documentation |
