# Demyst Notification Script

Notifies the Demyst server after ring4 test completion for automated test failure analysis.

## Usage

```bash
python3 notify_demyst.py -t <TESTBED> -b <BUILD_ID> -r <RUN_ID> -a <ALLURE_URL> -s <SYSLOGS_URL> -m <STREAM>
```

### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-t, --testbed` | Testbed name (key in hw_cfg.json) | `t1-m3-4-cmono` |
| `-b, --build_id` | Sonic buildimage build ID (p2build_job_id) | `40126` |
| `-r, --run_id` | Jenkins job build ID | `5243` |
| `-a, --allure_url` | Allure report URL | `https://allure.cisco.com/.../` |
| `-s, --syslogs_url` | Syslogs tarball base URL | `https://allure.cisco.com/.../` |
| `-m, --stream` | Stream name (required, for container lookup) | `202405`, `master` |

### Example (from Jenkins)

```bash
python3 ./demyst/notify_demyst.py \
    -t $TEST_BED \
    -b $P2BUILD_JOB_ID \
    -r $BUILD_ID \
    -a $ALLURE_LINK \
    -s $LOG_TARBALL_LINK \
    -m $STREAM
```

## Prerequisites

1. `PIPELINE_TYPE` environment variable must be `ring4`
2. Testbed must be listed in `supported_testbeds.txt`
3. Testbed must exist in `hw_cfg.json` (validated via `hw_setup_utils`)


## Payload Fields

| Field | Source | Description |
|-------|--------|-------------|
| `build_id` | CLI `-b` | Sonic buildimage build ID |
| `run_id` | Generated | `{testbed}_{run_id}_{timestamp}` |
| `testbed` | CLI `-t` | Testbed name (server resolves platform) |
| `topo_type` | hw_cfg.json | Topology type (e.g., `t0`, `t1`) |
| `sonic_test_commit_id` | UCS container | Commit from sonic-mgmt container's mounted sonic-test dir |
| `log_source` | | `"allure_url"` |
| `allure_report_url` | CLI `--allure_url` | Allure report URL |
| `syslogs_url` | CLI `--syslogs_url` | Syslogs tarball URL |
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
|------|---------|
| 0 | Request sent successfully to Demyst server |
| 1 | Any error (not ring4, testbed not supported, no syslogs, server error, etc.) |

## Logging

Logs are written to `NOTIFY_DEMYST.log`

## Files

| File | Description |
|------|-------------|
| `notify_demyst.py` | Main notification script |
| `supported_testbeds.txt` | Whitelist of supported testbeds |
| `README.md` | This documentation |
