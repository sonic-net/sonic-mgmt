# Feature Name
SonicMgmt Testcases for ZTP (Zero Touch Provisioning)
# High Level Design Document
#### Rev 1.0

# Table of Contents
  * [List of Tables](#list-of-tables)
  * [Revision](#revision)
  * [About this Manual](#about-this-manual)
  * [Scope](#scope)
  * [Testing Strategy for ZTP feature](#testing-strategy-for-ztp-feature)
  * [Topology](#topology)
  * [Architecture and Data Flow](#architecture-and-data-flow)
  * [Provisioning Model](#provisioning-model)
  * [ZTP Payload Structure](#ztp-payload-structure)
  * [Key File Paths on DUT](#key-file-paths-on-dut)
  * [Test cases](#test-cases)
    * [TC1: Validate ztp status command](#tc1-validate-ztp-status-command)
    * [TC2: Validate ztp enable and disable cycle](#tc2-validate-ztp-enable-and-disable-cycle)
    * [TC3: Validate payload schema validation and staging](#tc3-validate-payload-schema-validation-and-staging)
    * [TC4: Validate missing profile file negative path](#tc4-validate-missing-profile-file-negative-path)
    * [TC5: Validate end-to-end ZTP success](#tc5-validate-end-to-end-ztp-success)
    * [TC6: Validate config applied correctly after ZTP](#tc6-validate-config-applied-correctly-after-ztp)
    * [TC7: Validate ZTP service inactive after config present](#tc7-validate-ztp-service-inactive-after-config-present)
    * [TC8: Validate invalid payload path schema check](#tc8-validate-invalid-payload-path-schema-check)
    * [TC9: Validate discovery-stuck recovery command](#tc9-validate-discovery-stuck-recovery-command)
    * [TC10: Validate interrupt log visibility](#tc10-validate-interrupt-log-visibility)
    * [TC11: Validate halt-on-failure policy](#tc11-validate-halt-on-failure-policy)
    * [TC12: Validate ignore-result policy](#tc12-validate-ignore-result-policy)
    * [TC13: Validate safe teardown recovery](#tc13-validate-safe-teardown-recovery)
    * [TC14: Validate FRR file downloaded](#tc14-validate-frr-file-downloaded)
    * [TC15: Validate FRR service healthy](#tc15-validate-frr-service-healthy)
    * [TC16: Validate FRR runtime reflects config](#tc16-validate-frr-runtime-reflects-config)
    * [TC17: Validate FRR negative bad URL reachability](#tc17-validate-frr-negative-bad-url-reachability)
    * [TC18: Validate ignore-result for FRR policy](#tc18-validate-ignore-result-for-frr-policy)
    * [TC19: Validate local staged fallback when no Option 67](#tc19-validate-local-staged-fallback-when-no-option-67)
    * [TC20: Validate HWSKU present in ZTP config](#tc20-validate-hwsku-present-in-ztp-config)
    * [TC21: Validate HWSKU absent uses default](#tc21-validate-hwsku-absent-uses-default)
    * [TC22: Validate HWSKU invalid in ZTP config](#tc22-validate-hwsku-invalid-in-ztp-config)
    * [TC23: Validate config_db and ZTP mutual-exclusion contract](#tc23-validate-config_db-and-ztp-mutual-exclusion-contract)
    * [TC24: Validate config_db.json schema after ZTP](#tc24-validate-config_dbjson-schema-after-ztp)
    * [TC25: Validate graphservice option payload](#tc25-validate-graphservice-option-payload)
    * [TC26: Validate snmp option payload](#tc26-validate-snmp-option-payload)
    * [TC27: Validate firmware option payload](#tc27-validate-firmware-option-payload)
    * [TC28: Validate plugin option payload](#tc28-validate-plugin-option-payload)
    * [TC29: Validate connectivity-check option payload](#tc29-validate-connectivity-check-option-payload)
    * [TC30: Validate provisioning-script option payload](#tc30-validate-provisioning-script-option-payload)
    * [TC31: Validate reboot-on-success option payload](#tc31-validate-reboot-on-success-option-payload)
    * [TC32: Validate reboot-on-failure option payload](#tc32-validate-reboot-on-failure-option-payload)
    * [TC33: Validate restart-ztp-on-failure option payload](#tc33-validate-restart-ztp-on-failure-option-payload)
    * [TC34: Validate suspend-on-failure option payload](#tc34-validate-suspend-on-failure-option-payload)
    * [TC35: Validate maximum-retries option payload](#tc35-validate-maximum-retries-option-payload)
    * [TC36: Validate timestamp option payload](#tc36-validate-timestamp-option-payload)
  * [Fixtures and Timeouts](#fixtures-and-timeouts)
  * [Configuration and Environment](#configuration-and-environment)
  * [PTF Approach Findings](#ptf-approach-findings)
  * [References](#references)
  * [Abbreviations](#abbreviations)


# List of Tables
[Table 1: Abbreviations](#table-1-abbreviations)

ZTP - Zero Touch Provisioning

# Revision
| Rev |     Date    |                Author                | Change Description |
|:---:|:-----------:|:------------------------------------:|--------------------|
| 0.1 | 12/06/2026  | Saifuddin Beighlary                  | Initial version    |

# About this Manual
This document describes the approach taken to add automated Zero Touch Provisioning (ZTP) validation to the sonic-mgmt test suite. The suite lives under `tests/ztp/` and consists of two files: `test_ztp.py` (test logic) and `conftest.py` (shared fixtures). It contains 36 test cases (TC1-TC36) and is restricted to single-DUT t0 topologies via the module-level marker `pytest.mark.topology("t0")`.

# Scope
This document describes the high level details of the SONiC management test-cases for the ZTP feature. The suite verifies that a SONiC DUT can be provisioned end-to-end through ZTP. It actively probes for DHCP Option 67 at module startup; if detected, the suite runs in DHCP mode (local profile files are removed so ZTP uses the Option 67 download). If not detected after configurable retries, it runs in local mode (stages `/host/ztp/ztp_data.json` on the DUT). The mode can also be forced via `ZTP_PROVISIONING_MODE=local|dhcp`. Either way, the success criteria are the same.

In scope:
- ZTP CLI: `ztp status`, `ztp enable`, `ztp disable -y`, `ztp run -y`
- Active DHCP Option 67 probing via `resolve_ztp_provisioning_mode()`
- Dual-mode provisioning (DHCP mode vs local mode)
- Source detection from `ztp status` and `/var/log/ztp.log`
- `config_db.json` application and hostname-level post-ZTP validation
- FRR config download, file presence, BGP container health, `vtysh` runtime verification
- ZTP policy fields: `halt-on-failure`, `ignore-result` (schema-level)
- Negative cases: missing profile files, invalid source paths, unreachable URL
- Discovery-stuck recovery heuristic
- `config_db` backup/restore for destructive test isolation
- HWSKU handling: present in ZTP config, default_sku fallback, invalid HWSKU negative with guaranteed DUT recovery
- `config_db` / ZTP mutual-exclusion contract
- `config_db.json` schema and health validation
- Payload-level schema checks for 12 ZTP option surfaces: `graphservice`, `snmp`, `firmware`, `plugin`, `connectivity-check`, `provisioning-script`, `reboot-on-success`, `reboot-on-failure`, `restart-ztp-on-failure`, `suspend-on-failure`, `maximum-retries`, `timestamp`

# Testing Strategy for ZTP feature
Existing t0 topology will be used for developing the ZTP test suite. A simplified version of the topology has a single SONiC DUT (T0 leaf) with up to 64 downlink ports towards a docker-ptf container and uplinks toward Arista vEOS neighbors. Following mechanisms will be used in the test script implementation:

- The SONiC DUT will be driven using the `sudo ztp` CLI (`status`, `enable`, `disable -y`, `run -y`) and standard SONiC commands via `duthost.shell()` over SSH/Ansible.
- Verification of operational data will be performed by reading on-DUT files (`/etc/sonic/config_db.json`, `/etc/sonic/frr/frr.conf`, `/var/log/ztp.log`) and by inspecting platform/HWSKU directories under `/usr/share/sonic/device/<platform>/`.
- The test runner is the sonic-mgmt container running pytest. It uses the Ansible `localhost` connection (`wait_for`) to TCP-probe `duthost.mgmt_ip:22` so the harness can detect SSH stop/start across the destructive reboots driven by `ztp run -y`.
- DHCP Option 67 is treated as optional. At module startup, the `ztp_provisioning_mode` fixture probes the DUT for an Option 67 URL (reading `ztp_cfg.json` / `/etc/sonic/ztp.json`, resolving the `opt67-url` path, and verifying the file contains an `http(s)://` URL) before deciding between DHCP mode and local-staged mode. In local mode, `_stage_payload_files()` writes the ZTP profile to `/host/ztp/ztp.json` and `/host/ztp/ztp_data.json`. In DHCP mode, `_remove_local_ztp_profile_files()` deletes those files so ZTP must use the Option 67 URL.
- For destructive tests, the `backup_and_restore_config_db` fixture snapshots `/etc/sonic/config_db.json` to `/host/ztp/config_db.json.ztp_test_backup` before the test and restores it (plus runs `sudo ztp disable -y`) on teardown. TC22 additionally wraps its assertions in `try/finally` and calls `_recover_dut_after_invalid_hwsku()` which runs `sudo config reload -y -f`, waits for SSH and critical services, and hard-asserts that recovery succeeded.

# Topology
The suite targets a standard T0 testbed:

```
   INTERNET / SPINE
          |
  +---+ veos1 / veos2 / veos3 / veos4 (Arista vEOS leaf switches)
  |        |
  |   UPLINKS / PORTCHANNELS
  |        |
  +---> SONiC T0 DUT  (Device Under Test, pytest.mark.topology("t0"))
              |
        64 downlinks
              |
          docker_ptf  (PTF traffic generator / packet capture)

  sonic-mgmt test runner container -- pytest + Ansible -- duthost.shell() over SSH on duthost.mgmt_ip:22
```

# Architecture and Data Flow

| Actor         | What It Is                                       | How Tests Reach It                                                                 |
|---------------|--------------------------------------------------|------------------------------------------------------------------------------------|
| DUT           | SONiC device under test                          | `duthost.shell()` -- Ansible over SSH on `duthost.mgmt_ip`                         |
| Test Runner   | pytest running inside the sonic-mgmt container   | Uses `localhost` (Ansible connection) for TCP port probes via `wait_for`           |
| Testbed DHCP  | Optional -- the lab's DHCP server                | Not controlled by tests. `ztp_provisioning_mode` fixture probes the DUT for Option 67 signals at startup. If detected, DHCP mode runs; otherwise local mode runs. |

## Provisioning Model
The provisioning mode is determined at module startup by the `ztp_provisioning_mode` fixture, which calls `resolve_ztp_provisioning_mode()`.

- **Local mode**: tests stage a valid profile on the DUT via `_stage_payload_files()`, writing the JSON payload to both `/host/ztp/ztp_data.json` and `/host/ztp/ztp.json`.
- **DHCP mode**: tests call `_remove_local_ztp_profile_files()` to delete those files, so ZTP is forced to use the Option 67 URL that the testbed DHCP server provides.

The helper `_use_local_ztp_profile()` checks `ztp_payload["provisioning_mode"]` to decide which path to take. Either way, the success criteria are the same: `ztp_status == "SUCCESS"` and `ztp_service == "Inactive"`.

## ZTP Payload Structure
The `ztp_payload` fixture in `conftest.py` calls `_build_default_payload()`, which creates a two-step ZTP profile:

1. **Step `01-download`**: Downloads an FRR config file from `DEFAULT_FRR_URL` (or the `ZTP_FRR_URL` env var override) to `/etc/sonic/frr/frr.conf`. Flags: `halt-on-failure: false`, `ignore-result: false`, `reboot-on-failure: false`, `reboot-on-success: false`.
2. **Step `02-configdb-json`**: Copies `file:///host/ztp/config_db_to_apply.json` to `/etc/sonic/config_db.json`. Flags: `clear-config: false`, `save-config: true`.

## E2E Flow (used by TC5 and TC13)

| Step | What Happens                                                                                              | Code                                                       |
|:----:|------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| 1    | Build ZTP JSON payload from fixture                                                                        | `conftest.py: _build_default_payload()`                    |
| 2    | Backup `config_db.json` to `/host/ztp/config_db.json.ztp_test_backup`                                      | `conftest.py: backup_and_restore_config_db`                |
| 3    | Local mode: write payload JSON to `ztp_data.json` and `ztp.json`. DHCP mode: remove them.                  | `_stage_payload_files()` / `_remove_local_ztp_profile_files()` |
| 4    | Copy `config_db.json` to `config_db_to_apply.json`, run `sudo ztp enable`, then `sudo rm -f /etc/sonic/config_db.json` | `_prepare_for_ztp_run()`                       |
| 5    | Local mode: refresh `ztp_data.json` from `ztp.json`. Run `sudo ztp run -y`. Wait SSH stop (180s), SSH start (delay 30s, 900s), critical services (600s). Discovery-stuck recovery up to 12 x 20s. Poll `ztp status` until SUCCESS/Inactive (1200s @ 20s). | `_execute_ztp_run_and_wait()` |
| 6    | Teardown: `sudo ztp disable -y`, restore `config_db.json` from backup, delete backup + staged files        | `backup_and_restore_config_db` (yield teardown)            |

## Key File Paths on DUT

| Path                                                  | Purpose                                                                            |
|-------------------------------------------------------|------------------------------------------------------------------------------------|
| `/host/ztp/ztp_cfg.json`                              | ZTP service config -- read by `_read_ztp_service_cfg()` to find the `opt67-url` path |
| `/etc/sonic/ztp.json`                                 | Alternate ZTP service config location (fallback for `_read_ztp_service_cfg()`)     |
| `/host/ztp/ztp.json`                                  | ZTP master profile -- survives reboots                                              |
| `/host/ztp/ztp_data.json`                             | Working copy that ZTP reads at runtime                                              |
| `/host/ztp/config_db_to_apply.json`                   | Staged config that the ZTP profile references via `file://`                         |
| `/etc/sonic/config_db.json`                           | Running config -- removed to trigger ZTP, restored on teardown                      |
| `/etc/sonic/frr/frr.conf`                             | FRR config file applied by the ZTP download step                                    |
| `/var/log/ztp.log`                                    | ZTP daemon log -- parsed for DHCP-vs-local source detection                         |
| `/usr/share/sonic/device/<platform>/`                 | Platform root. Contains `default_sku` file and one subdirectory per supported HWSKU |
| `/usr/share/sonic/device/<platform>/default_sku`      | Platform default HWSKU. First word is the HWSKU used when `config_db.json` is generated by the factory path |
| `/usr/share/sonic/device/<platform>/<hwsku>/`         | HWSKU directory. Contains `port_config.ini` and/or `hwsku.json` consumed by SwSS/syncd |

# Test cases
The test cases here are to validate the ZTP CLI lifecycle, end-to-end provisioning success and recovery, ZTP profile payload schema, FRR rendering and BGP runtime health, HWSKU handling, the `config_db` / ZTP mutual-exclusion contract, and payload-level coverage of the supported ZTP option surfaces. Cases are documented in TC number order (pytest execution order follows function order in `test_ztp.py`, which is not the same as TC number order).

## TC1: Validate ztp status command
1) Run `sudo ztp status` on the SONiC DUT.
    ```
    sudo ztp status
    ```
2) Assert the command returns an exit code of 0.
3) Feed the output into `parse_ztp_status()` which splits each line on the first `:` into key/value pairs and normalizes keys to lowercase-with-underscores.
4) Assert the resulting dictionary is non-empty.

Pass: `rc == 0` and parseable output. Fail: command fails or output is empty/unparseable. Not destructive. No fixtures, no skips.

## TC2: Validate ztp enable and disable cycle
1) Run `sudo ztp enable` and assert `rc == 0`.
2) Run `sudo ztp status`, parse the output and assert `ztp_admin_mode == "True"`.
    ```
    sudo ztp enable
    sudo ztp status
    ```
3) Run `sudo ztp disable -y` and assert `rc == 0`.
4) Run `sudo ztp status` again and assert `ztp_admin_mode == "False"`.

Validates the full enable/disable toggle cycle. Not destructive. No fixtures, no skips.

## TC3: Validate payload schema validation and staging
1) Call `_validate_payload_schema()` on the auto-generated ZTP payload and assert it passes.
2) Branch on provisioning mode:
   - **Local mode**: call `_stage_payload_files()` to write the payload to `/host/ztp/ztp_data.json` and `/host/ztp/ztp.json`, and verify both files exist via `duthost.stat()`.
   - **DHCP mode**: call `_remove_local_ztp_profile_files()` to delete the local profiles so ZTP uses the Option 67 download.

Mode-aware, not destructive. Fixtures: `ztp_payload`. No skips.

## TC4: Validate missing profile file negative path
1) Skip cleanly if provisioning mode is DHCP (Option 67 would still provide a profile).
2) Call `_prepare_for_ztp_run()` -- copies `config_db.json` to the staged location, runs `sudo ztp enable`, removes the live `config_db.json`.
3) Deliberately delete both `/host/ztp/ztp_data.json` and `/host/ztp/ztp.json`.
4) Run `sudo ztp run -y` and wait for SSH (delay 10s, timeout 180s).
5) Poll with the negative-test timeout `NEGATIVE_POLL_TIMEOUT` (120s).
6) Assert ZTP did **not** complete successfully -- the missing profile is expected to keep ZTP from reaching SUCCESS.

Destructive. Fixtures: `backup_and_restore_config_db`, `ztp_payload`. Skips in DHCP mode.

## TC5: Validate end-to-end ZTP success
The main end-to-end test.

1) Branch on provisioning mode:
   - **Local mode**: `_stage_payload_files()` writes the ZTP profile to the DUT.
   - **DHCP mode**: `_remove_local_ztp_profile_files()` removes local profiles.
2) Call `_prepare_for_ztp_run()` followed by `_execute_ztp_run_and_wait()`. `_execute_ztp_run_and_wait()` conditionally refreshes `ztp_data.json` only in local mode.
3) Assert `ztp_status == "SUCCESS"` and `ztp_service == "Inactive"` within the configured timeouts.

Destructive (full reboot via `ztp run -y`). Mode-aware. Fixtures: `ztp_payload`, `backup_and_restore_config_db`.

## TC6: Validate config applied correctly after ZTP
1) Read `/etc/sonic/config_db.json` from the DUT via `sudo cat`, parse as JSON.
2) Extract `DEVICE_METADATA.localhost.hostname` and assert it is non-empty.
3) If `/host/ztp/config_db_to_apply.json` still exists on the DUT, parse it and assert that its `DEVICE_METADATA.localhost.hostname` equals the running hostname.

Depends on TC5 having run successfully (no explicit dependency enforcement). Not destructive. No fixtures, no skips.

## TC7: Validate ZTP service inactive after config present
1) Run `sudo ztp status` and parse the output.
2) Assert `ztp_service == "Inactive"` -- the ZTP service must have stopped once a valid config_db is in place after a successful run.

Depends on TC5 leaving the DUT in a post-ZTP success state. Not destructive. No fixtures, no skips.

## TC8: Validate invalid payload path schema check
1) Build a ZTP payload dict in which the `configdb` step's `source` is `file:///host/ztp/does_not_exist.json`.
2) Call `_validate_payload_schema()` and assert it returns `False`.

Pure Python logic test -- no DUT interaction. Not destructive. No fixtures, no skips.

## TC9: Validate discovery-stuck recovery command
1) Skip cleanly if provisioning mode is DHCP (the local `ztp.json`/`ztp_data.json` sync does not apply).
2) Call `_stage_payload_files()` to ensure both profile files exist.
3) Run:
    ```
    sudo cp -f /host/ztp/ztp.json /host/ztp/ztp_data.json && sudo sync
    ```
   and assert `rc == 0`.
4) Verify both files exist afterward via `duthost.stat()`.

This exercises the discovery-stuck recovery command path. Not destructive. Fixtures: `ztp_payload`. Skips in DHCP mode.

## TC10: Validate interrupt log visibility
1) Run `sudo tail -n 400 /var/log/ztp.log` on the DUT.
2) Assert `rc == 0` and that the substring `"ztp"` appears in the output (case-insensitive).

Confirms the ZTP log file exists, is readable, and contains ZTP-related content. Not destructive. No fixtures, no skips.

## TC11: Validate halt-on-failure policy
1) Build a Python dict representing a ZTP step with `"halt-on-failure": true`.
2) Assert the flag is set on the constructed dict.

Unit-level schema check -- does not run ZTP with this policy on a real DUT. Not destructive. No fixtures, no skips.

## TC12: Validate ignore-result policy
1) Build a Python dict representing a ZTP step with `"ignore-result": true`.
2) Assert the flag is set on the constructed dict.

Same pattern as TC11 -- unit-level schema validation only, no DUT interaction. Not destructive. No fixtures, no skips.

## TC13: Validate safe teardown recovery
The final recovery test -- same dual-mode flow as TC5.

1) Local mode: stage payload files; DHCP mode: remove local profiles.
2) Prepare for ZTP via `_prepare_for_ztp_run()`, run `sudo ztp run -y`, wait for completion via `_execute_ztp_run_and_wait()`.
3) Assert `ztp_status == "SUCCESS"` and `ztp_service == "Inactive"`.

The purpose is to leave the DUT in a known-good state at the end of the suite. Destructive. Mode-aware. Fixtures: `ztp_payload`, `backup_and_restore_config_db`.

## TC14: Validate FRR file downloaded
1) Check `_has_frr_step()` and skip if the payload has no FRR step.
2) Confirm the FRR file is present and non-empty:
    ```
    sudo test -s /etc/sonic/frr/frr.conf
    ```
3) Confirm the file contains expected marker lines:
    ```
    sudo grep -E '^(frr version|router bgp)' /etc/sonic/frr/frr.conf
    ```

Not destructive. Fixtures: `ztp_payload`. Skips if no FRR step.

## TC15: Validate FRR service healthy
1) Check `_has_frr_step()` and skip if the payload has no FRR step.
2) Confirm a `bgp` container is running on the DUT:
    ```
    sudo docker ps | awk 'NR>1 {print $NF}' | grep -w bgp
    ```
The `awk` workaround avoids Jinja templating collisions in Ansible.

Not destructive. Fixtures: `ztp_payload`. Skips if no FRR step.

## TC16: Validate FRR runtime reflects config
1) Check `_has_frr_step()` and skip if the payload has no FRR step.
2) Inspect FRR's running config:
    ```
    sudo docker exec bgp vtysh -c 'show running-config'
    ```
3) Assert `"router bgp"` appears in the output.

Confirms the FRR daemon has loaded a BGP configuration into its runtime. Not destructive. Fixtures: `ztp_payload`. Skips if no FRR step.

## TC17: Validate FRR negative bad URL reachability
1) Runs on the pytest host (not on the DUT).
2) Uses `urllib.request.urlopen` to try connecting to `http://127.0.0.1:9/does_not_exist_frr.conf` with a 2-second timeout.
3) Expects the connection to be refused -- assertion fires only if the call unexpectedly succeeds.

Limitation: runs on the test runner, not the DUT. Not destructive. No fixtures, no skips.

## TC18: Validate ignore-result for FRR policy
1) Build a ZTP policy dict in which the FRR section has `"ignore-result": true` and a bad source URL.
2) Assert the `ignore-result` flag is set.

Unit-level schema assertion only -- does not deploy this policy on a real DUT. Not destructive. No fixtures, no skips.

## TC19: Validate local staged fallback when no Option 67
1) Call `_detect_ztp_profile_source()` to determine how ZTP got its profile, based on `ztp status` output and `/var/log/ztp.log`.
2) Bidirectional check based on resolved provisioning mode:
   - **Local mode**: assert detected source is `"local"` (skip if unknown or not local).
   - **DHCP mode**: assert detected source is `"dhcp"` (skip if unknown or not DHCP).

Confirms the observed ZTP source matches the provisioning mode selected at module startup. Not destructive. Mode-aware. Fixtures: `ztp_payload`.

## TC20: Validate HWSKU present in ZTP config
Validates the "with HWSKU" path.

1) Read `DEVICE_METADATA.localhost.hwsku` via `sonic-cfggen -d -v` and assert it is non-empty.
2) Assert `/usr/share/sonic/device/<platform>/<hwsku>/` exists on the DUT.
3) Assert that HWSKU directory has at least one of `port_config.ini` or `hwsku.json`.

Read-only, not destructive. Fixtures: `platform_hwsku_info`.

## TC21: Validate HWSKU absent uses default
Read-only readiness check for the "without HWSKU" path. A destructive rebuild was intentionally avoided because SONiC's default-substitution path (config-setup factory) only triggers when `config_db.json` is completely absent -- stripping the `hwsku` field from a staged `config_db` would leave the DUT half-configured.

1) Read `/usr/share/sonic/device/<platform>/default_sku`, assert it exists and its first word is the default HWSKU name.
2) Assert `/usr/share/sonic/device/<platform>/<default_hwsku>/` exists and has `port_config.ini` or `hwsku.json`.
3) Skip cleanly if `default_sku` is missing or empty.

Not destructive. Fixtures: `platform_hwsku_info`. Skips if no `default_sku`.

## TC22: Validate HWSKU invalid in ZTP config
Negative test with guaranteed DUT recovery wrapped in `try/finally`.

1) Pre-check: assert the sentinel HWSKU `Invalid-HWSKU-Does-Not-Exist` does **not** already exist under the platform directory (must not collide with any real HWSKU).
2) Pre-check: assert `backup_and_restore_config_db` captured a real backup at setup (required for safe recovery).
3) Call `_stage_configdb_with_hwsku_override(duthost, INVALID_HWSKU_NAME)`:
   - copies live `config_db.json`,
   - overrides `DEVICE_METADATA.localhost.hwsku` to the sentinel,
   - stages it at `/host/ztp/config_db_to_apply.json`,
   - runs `sudo ztp enable`,
   - removes live `/etc/sonic/config_db.json`.
4) Run `sudo ztp run -y` and wait for SSH to return (up to 900s).
5) Poll `critical_services_fully_started()` with the negative-test timeout `NEGATIVE_POLL_TIMEOUT` (120s).
6) Assert services did **not** reach a fully-started state -- that is the correct negative outcome (an invalid HWSKU must never become production state). The assertion also covers the defensive case in which SONiC accepts the live config but substitutes a safe HWSKU; in that case the test verifies the invalid sentinel never became the running HWSKU.
7) **Recovery (always runs in `finally`)**: `_recover_dut_after_invalid_hwsku()` runs `sudo ztp disable -y`, restores `config_db.json` from backup, runs `sudo config reload -y -f`, waits for SSH plus critical services, and asserts recovery succeeded.

Destructive with auto-recovery. Fixtures: `ztp_payload`, `platform_hwsku_info`, `backup_and_restore_config_db`.

## TC23: Validate config_db and ZTP mutual-exclusion contract
Validates the SONiC invariant that ZTP only runs when `config_db.json` is absent.

1) Pre-check: assert `backup_and_restore_config_db` captured a real backup at setup time.
2) **State A**: run `sudo ztp enable`, assert `ztp_admin_mode == "True"` and `ztp_service == "Inactive"` while `config_db.json` is on disk.
3) Run:
    ```
    sudo rm -f /etc/sonic/config_db.json
    ```
4) **State B**: assert `config_db.json` is absent (via `duthost.stat()`) and `ztp_service != "Inactive"` -- ZTP is primed to run at the next boot.
5) In `finally`: copy the backup file back to `/etc/sonic/config_db.json`.

No ZTP run, no reboot -- the DUT's running state is never disturbed because SONiC serves from in-memory config until the next reload. Transient write. Fixtures: `backup_and_restore_config_db`.

## TC24: Validate config_db.json schema after ZTP
Read-only. Validates that the post-ZTP `config_db.json` is both syntactically and semantically valid, and that the switch is healthy.

1) Read `/etc/sonic/config_db.json` and parse as JSON (`json.loads`).
2) Assert mandatory top-level tables are present (currently: `DEVICE_METADATA`).
3) Assert `DEVICE_METADATA.localhost` contains all five mandatory fields: `hostname`, `hwsku`, `platform`, `mac`, `type`.
4) Run:
    ```
    sudo sonic-cfggen -j /etc/sonic/config_db.json --print-data
    ```
   and assert `rc == 0` -- SONiC's own parser accepts the file.
5) Call `_wait_for_critical_services(duthost)` and assert SwSS, syncd, bgp, lldp, etc. are all fully started.

Not destructive. No fixtures.

## TC25: Validate graphservice option payload
Option: `graphservice` -- pulls a minigraph from a URL.

1) Build a representative ZTP payload containing a `graphservice` step with a `minigraph-url` block.
2) Assert the step has a `minigraph-url` block.
3) Assert `minigraph-url.destination == "/etc/sonic/minigraph.xml"`.
4) JSON-serialize and deserialize the payload via `_assert_payload_json_roundtrips()` to catch non-serializable values.

Not destructive. No DUT interaction. No fixtures.

## TC26: Validate snmp option payload
Option: `snmp` -- configures SNMP community and location.

1) Build a payload with an `snmp` block containing `community_ro` and `snmp_location`.
2) Assert `community_ro` is a non-empty list.
3) Assert `snmp_location` is set (non-empty string).
4) JSON round-trip.

Not destructive. No fixtures.

## TC27: Validate firmware option payload
Option: `firmware` -- installs a SONiC image.

1) Build a payload with a `firmware` block containing an `install` substructure.
2) Assert `install.url.source` starts with `http`.
3) Assert `install.set-default == true`.
4) Assert `reboot-on-success == true` (standard for firmware steps).
5) JSON round-trip.

Not destructive. No fixtures.

## TC28: Validate plugin option payload
Option: `plugin` -- runs a custom plugin script.

1) Build a payload with a `plugin` step whose `plugin.url.destination` is an absolute path on the DUT.
2) Assert the `destination` starts with `/`.
3) JSON round-trip.

Not destructive. No fixtures.

## TC29: Validate connectivity-check option payload
Option: `connectivity-check` -- verifies reachability before continuing.

1) Build a payload with a `connectivity-check` block specifying a `ping` list and `retry-count`.
2) Assert `connectivity-check.ping` is a non-empty list.
3) Assert `retry-count` is a positive integer.
4) JSON round-trip.

Not destructive. No fixtures.

## TC30: Validate provisioning-script option payload
Option: `provisioning-script` -- downloads and runs an arbitrary script.

1) Build a payload with a `provisioning-script` block specifying `url.source` and `shell`.
2) Assert `url.source` is set.
3) Assert `shell` is one of `bash` / `sh` / `python` / `python3`.
4) JSON round-trip.

Not destructive. No fixtures.

## TC31: Validate reboot-on-success option payload
Flag: `reboot-on-success` -- reboot after the step succeeds.

1) Build a payload with `"reboot-on-success": true` at the step level.
2) Assert the flag equals `True`.
3) JSON round-trip.

Not destructive. No fixtures.

## TC32: Validate reboot-on-failure option payload
Flag: `reboot-on-failure` -- reboot after the step fails (retry from boot).

1) Build a payload with `"reboot-on-failure": true`.
2) Assert the flag equals `True`.
3) JSON round-trip.

Not destructive. No fixtures.

## TC33: Validate restart-ztp-on-failure option payload
Flag: `restart-ztp-on-failure` -- restart the whole ZTP session on failure.

1) Build a payload with `"restart-ztp-on-failure": true`.
2) Assert the flag equals `True`.
3) JSON round-trip.

Not destructive. No fixtures.

## TC34: Validate suspend-on-failure option payload
Flag: `suspend-on-failure` -- pause ZTP and wait for the operator.

1) Build a payload with `"suspend-on-failure": true`.
2) Assert the flag equals `True`.
3) JSON round-trip.

Not destructive. No fixtures.

## TC35: Validate maximum-retries option payload
Options: `maximum-retries` and `retry-interval` -- bounds on per-step retries.

1) Build a payload with `maximum-retries` and `retry-interval`.
2) Assert both are positive integers.
3) JSON round-trip.

Not destructive. No fixtures.

## TC36: Validate timestamp option payload
Metadata: `timestamp` at root and per-step levels -- ZTP engine populates start/end timestamps.

1) Build a payload with `timestamp` at the root and inside each step.
2) Assert root and step timestamps are present in the payload.
3) JSON round-trip.

Not destructive. No fixtures.

# Fixtures and Timeouts

## Fixtures

| Fixture                          | Scope             | What It Does |
|----------------------------------|-------------------|--------------|
| `ztp_provisioning_mode`          | module            | Calls `resolve_ztp_provisioning_mode(duthost)` once per module. Reads ZTP service config (`ztp_cfg.json` or `/etc/sonic/ztp.json`), resolves the `opt67-url` path, and checks if the file contains an `http(s)://` URL. Falls back to probing common `/run/ztp/` paths and `dhclient` lease files. Retries up to `ZTP_DHCP_PROBE_ATTEMPTS` (default 6) at `ZTP_DHCP_PROBE_INTERVAL` (default 5s). Overridable via `ZTP_PROVISIONING_MODE=local|dhcp`. Returns `"local"` or `"dhcp"`. |
| `ztp_payload`                    | module            | Depends on `ztp_provisioning_mode`. Calls `_build_default_payload()` once per module. Returns a dict with the ZTP JSON content, target file paths on the DUT, payload origin metadata, and the resolved `provisioning_mode`. The FRR source URL is overridable via `ZTP_FRR_URL`. |
| `platform_hwsku_info`            | module            | Probes the DUT once per module for `DEVICE_METADATA.localhost.platform`, `DEVICE_METADATA.localhost.hwsku`, and the first word of `/usr/share/sonic/device/<platform>/default_sku`. Returns `{platform, running_hwsku, default_hwsku, device_path}` consumed by TC20/TC21/TC22 so they share one DUT round-trip. |
| `backup_and_restore_config_db`   | function          | Setup: if `/etc/sonic/config_db.json` exists on the DUT, copy it to `/host/ztp/config_db.json.ztp_test_backup`. Teardown (always runs): `sudo ztp disable -y`, restore `config_db.json` from the backup, delete the backup and `config_db_to_apply.json`. Deliberately does not run `config reload` to avoid false failures from SwSS readiness transients during post-ZTP stabilization. TC22 supplements this with an explicit `config reload -y -f` + service-health recovery in its own `finally` block. |
| `core_dump_and_config_check`     | module / autouse  | No-op. Overrides the sonic-mgmt framework fixture that runs post-module teardown health checks. Those checks were causing false failures during post-ZTP stabilization because SwSS services take time to reach a steady state. Documented as temporary. |
| `sanity_check`                   | module / autouse  | No-op. Same pattern -- overrides the framework's sanity check fixture to keep the ZTP suite stable. Documented as temporary. |

## Helpers added for new tests

| Helper                                                          | Location       | What It Does |
|-----------------------------------------------------------------|----------------|--------------|
| `_stage_configdb_with_hwsku_override(duthost, override)`        | `test_ztp.py`  | Reads live `/etc/sonic/config_db.json`, mutates `DEVICE_METADATA.localhost.hwsku` per `override` (strip / replace / leave), writes the result to `/host/ztp/config_db_to_apply.json`, enables ZTP, removes the live `config_db.json`. Same post-condition as `_prepare_for_ztp_run()` so `_execute_ztp_run_and_wait()` can be reused. |
| `_recover_dut_after_invalid_hwsku(duthost, localhost, backup_info)` | `test_ztp.py` | Brings the DUT back to a healthy state after TC22 intentionally broke it: `ztp disable -y`, restore `config_db.json` from backup, `config reload -y -f`, wait for SSH, wait for critical services, hard-assert recovery succeeded. |
| `_read_ztp_status(duthost)`                                     | `test_ztp.py`  | Wraps `sudo ztp status` + `parse_ztp_status()`, asserts `rc == 0`, returns the parsed dict. Used by TC23. |
| `_assert_payload_json_roundtrips(payload)`                      | `test_ztp.py`  | Dumps the payload to JSON and reloads it -- catches accidental non-serializable values (e.g. `bytes`, `datetime`). Used by TC25-TC36. |
| `_resolve_running_platform_hwsku(duthost)` and `_resolve_default_hwsku(duthost, platform)` | `conftest.py` | Module-private helpers used by `platform_hwsku_info`. Read `DEVICE_METADATA.localhost.platform/hwsku` via `sonic-cfggen -d`, and the first word of `default_sku` respectively. |

## Timeouts

| Constant                    | Value                                | Why This Value |
|-----------------------------|--------------------------------------|----------------|
| `ZTP_POLL_TIMEOUT`          | 1200s (20 min)                       | ZTP may include DHCP discovery with retry cycles, HTTP downloads, config application, and service restarts. Outer bound for the entire ZTP process to finish. |
| `ZTP_POLL_INTERVAL`         | 20s                                  | How often `ztp status` is polled during completion wait. |
| `SSH_STOP_DETECT_TIMEOUT`   | 180s                                 | Max time waited for SSH to drop after `ztp run -y` initiates a reboot. |
| `SSH_START_DELAY`           | 30s                                  | After detecting SSH stopped, wait before checking SSH started. Avoids false-positive "started" on a port that has not fully gone down yet. |
| `SSH_START_TIMEOUT`         | 900s (15 min)                        | SONiC boot time can be long on simulated environments or slow hardware. |
| `CRITICAL_SERVICES_TIMEOUT` | 600s (10 min)                        | SwSS, syncd, bgp, lldp, etc. need time to start after a reboot. |
| `CRITICAL_SERVICES_INTERVAL`| 20s                                  | How often `critical_services_fully_started()` is polled. |
| `NEGATIVE_POLL_TIMEOUT`     | 120s                                 | Shorter timeout for negative tests -- we expect failure quickly. Used by TC4 and TC22. |
| `INVALID_HWSKU_NAME`        | `"Invalid-HWSKU-Does-Not-Exist"`     | Sentinel HWSKU value used by TC22. Pre-check ensures the sentinel does not collide with any real HWSKU directory on disk. |
| `HWSKU_REMOVE_SENTINEL`     | `"__REMOVE__"`                       | Signals to `_stage_configdb_with_hwsku_override()` to strip the `hwsku` field entirely (as opposed to replacing it). Reserved for future use; TC21 currently uses the non-destructive readiness-check path instead. |

# Configuration and Environment

## Environment Variables

| Variable                   | Default                                          | What It Controls |
|----------------------------|--------------------------------------------------|------------------|
| `ZTP_PROVISIONING_MODE`    | `auto`                                           | Controls the provisioning mode. `auto` (default): probes the DUT for DHCP Option 67 and decides automatically. `local`: forces local profile staging. `dhcp`: forces DHCP mode (local profiles removed). Read in `conftest.py` via `resolve_ztp_provisioning_mode()`. |
| `ZTP_DHCP_PROBE_ATTEMPTS`  | `6`                                              | Number of times to probe for DHCP Option 67 in auto mode before falling back to local. Only used when `ZTP_PROVISIONING_MODE=auto`. |
| `ZTP_DHCP_PROBE_INTERVAL`  | `5` (seconds)                                    | Seconds between DHCP Option 67 probe attempts in auto mode. |
| `ZTP_FRR_URL`              | `http://<lab-host>/ztp/<platform>/frr.conf`      | HTTP URL where the DUT will download its FRR config from during ZTP step `01-download`. Read in `conftest.py` via `os.getenv("ZTP_FRR_URL", DEFAULT_FRR_URL)`. |

## Testbed assumptions

- The module-level marker `pytest.mark.topology("t0")` restricts the suite to single-DUT t0 (leaf) topologies.
- The DUT must have the ZTP package installed -- specifically the `sudo ztp` CLI must be available.
- The DUT must have a `/host/ztp/` directory (standard on SONiC images with ZTP support).
- The DUT must have `/usr/share/sonic/device/<platform>/` populated with at least one HWSKU directory. For TC21, a `default_sku` file should exist; TC21 skips cleanly if not.
- The test runner (`localhost`) must be able to TCP-probe `duthost.mgmt_ip:22`.
- DHCP is optional: the `ztp_provisioning_mode` fixture probes the DUT for DHCP Option 67 signals at startup. If detected, the suite runs in DHCP mode (removes local profiles). If not, it stages a local profile. The mode can also be forced via `ZTP_PROVISIONING_MODE=local|dhcp`.
- The marker `pytest.mark.disable_loganalyzer` is set because ZTP produces a lot of log output that would trigger false positives in the log analyzer.

# PTF Approach Findings
Before finalizing the dual-mode approach (DHCP Option 67 when available, local staged profile as fallback), a PTF-based DHCP emulation approach was evaluated. The goal was to have the DUT receive Option 67 from PTF and fetch its ZTP profile from a PTF-hosted HTTP server.

**Objective and Environment**
- Goal: Run ZTP with PTF acting as a DHCP server, where Option 67 points to a PTF-hosted HTTP path for the ZTP profile.
- Platform: SONiC DUT + `docker-ptf` + T0 topology with Arista vEOS neighbors.
- Constraint: The management subnet also had an infrastructure DHCP server (e.g. `192.168.122.1`) already serving leases.

**Observation A -- DUT selected the infrastructure DHCP server, not PTF**

`tcpdump` on the DUT showed:
```
tcpdump -i any -nn -vv -e 'udp port 67 or udp port 68'
... DHCP Request from 02:56:32:62:ae:6f ...
Server-ID Option 54, length 4: 192.168.122.1
Requested-IP Option 50, length 4: 192.168.122.75
```
The DUT selected the lab's infrastructure DHCP server (`192.168.122.1`), not the PTF DHCP server. The DUT's DHCP client picks whichever server responds first, and in a shared management broadcast domain the infrastructure DHCP server typically wins.

**Observation B -- Lab DHCP blocked DHCP traffic from reaching PTF**

`tcpdump` on the PTF container across all interfaces (`eth0` through `eth64`) saw no DHCP packets at all (`udp port 67 or udp port 68`). The infrastructure DHCP server on the management subnet was answering all DHCP requests before they reached PTF.

**Conclusion**

These findings led to the current dual-mode design with active probing. `resolve_ztp_provisioning_mode()` in `conftest.py` actively checks the DUT for DHCP Option 67 signals at module startup -- reading the ZTP service config, resolving the `opt67-url` path, and probing common run-time paths and `dhclient` lease files. If Option 67 is detected, the suite enters DHCP mode and removes local profile files so ZTP must use the DHCP-provided URL. If not detected, it stages local profiles as fallback. This approach works reliably across labs with or without DHCP infrastructure, without requiring network isolation or changes to the lab's DHCP setup.

# References
- SONiC ZTP design: https://github.com/sonic-net/SONiC/blob/master/doc/ztp/ztp.md
- sonic-ztp project: https://github.com/sonic-net/sonic-ztp
- sonic-mgmt repository: https://github.com/sonic-net/sonic-mgmt
- ZTP suite under test: `tests/ztp/test_ztp.py`, `tests/ztp/conftest.py`

# Abbreviations
<a name="table-1-abbreviations"></a>

| Term  | Meaning                                       |
|-------|-----------------------------------------------|
| ZTP   | Zero Touch Provisioning                       |
| DUT   | Device Under Test                             |
| PTF   | Packet Test Framework                         |
| DHCP  | Dynamic Host Configuration Protocol           |
| HWSKU | Hardware Stock Keeping Unit                   |
| FRR   | Free Range Routing (BGP/IGP routing stack)    |
| SwSS  | Switch State Service                          |
| BGP   | Border Gateway Protocol                       |
| TC    | Test Case                                     |
| E2E   | End-to-End                                    |
| CLI   | Command Line Interface                        |
