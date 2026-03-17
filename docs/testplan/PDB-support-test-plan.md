# PDB (Power Distribution Board) Support Test Plan

## 1.1 Related Documents

| Document Name | Link |
|---------------|------|
| Support PDB flows HLD | [Support PDB flows.docx (internal)](https://nvidia-my.sharepoint.com/:w:/p/yualiu/EQk2jSLlpRlAjOhlv1j5jnIB_Q1GVGM7Ea6CQTGsW0aL1w) |

## 1.2 Overview

PDB (Power Distribution Board) is a new hardware component on direct-current platforms. It replaces PSU and is read-only (monitoring only). A new `PDBBase` platform object is added to SONiC for this purpose. This test plan describes the sonic-mgmt test changes needed to cover PDB support.

## 1.3 Scale / Performance

PDB count depends on hardware (typically 2-4 per chassis). The daemon polls every 3 seconds. No special scale or performance concerns for testing.

## 1.4 Test Duration / Test Memory Consumption

All tests run on a single DUT per HWSKU. No special topology needed. Each test case takes less than 5 minutes. No special log size concerns.

## 1.5 Related DUT CLI Commands

### 1.5.1 Configuration Commands

| Command | Comment |
|---------|---------|
| N/A | PDB is monitoring-only, no configuration commands |

### 1.5.2 Show Commands

| Command | Comment |
|---------|---------|
| `show platform psustatus` | On PDB platforms, shows PDB rows with the same column format as PSU |
| `show platform temperature` | On PDB platforms, shows PDB thermal sensor rows (e.g. `PDB-1 Temp`) |
| `show system-health detail` | Shows PDB entries with Type=PDB |

## 2. Test Structure

### 2.1.1 Setup Configuration

- DUT must have PDB hardware installed
- `platform.json` on the DUT must have the `pdbs` array with installed PDBs
- Platform API service must be running on the DUT

### 2.1.2 Configuration Diagram

No diagram needed.

### 2.1 Test Cases

PDB and PSU both inherit from `DeviceBase` but are separate objects. On PDB platforms, `get_num_psus()` returns 0 so PSU tests are skipped. A separate `test_pdb.py` is needed. All APIs in the PDB HLD have a matching test case below.

Tag meanings: `new` = completely new test, no PSU equivalent; `psu-adapted` = based on PSU test but logic changed; `psu-reuse` = same logic as PSU, only swap API module; `existing-modified` = existing test file modified to support PDB.

#### Platform API

Test PDB and chassis PDB APIs through the platform API service.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 1 | Platform API | `test_pdb.py::test_input_power` | 1. Get PDB count from `chassis.get_num_pdbs()`.<br>2. For each PDB, call `get_input_voltage()`, `get_input_current()`, `get_input_power()`.<br>3. Check each returns a float.<br>4. Check power is close to voltage x current (within 10%). | All return float; power close to voltage x current | New | **new** |
| 2 | Platform API | `test_chassis.py::test_pdbs` | 1. Call `chassis.get_num_pdbs()`, check it returns an integer.<br>2. Compare the count with `platform.json` `pdbs` array length.<br>3. Call `chassis.get_all_pdbs()`, check list length equals num_pdbs.<br>4. For each index, call `chassis.get_pdb(i)` and check it matches the list entry.<br>5. On PSU platforms, check `get_num_pdbs()` returns 0 and `get_all_pdbs()` returns empty list. | Count matches platform.json; list and index consistent | New | **new** |
| 3 | Platform API | `test_pdb.py::test_output_power` | Based on PSU `test_power`. Changes:<br>1. Use `get_output_voltage/current/power()` instead of `get_voltage/current/power()`.<br>2. Remove `get_powergood_status()` check (not in PDB HLD).<br>3. Remove `get_voltage_high/low_threshold()` checks (not in PDB HLD).<br>4. Keep `get_maximum_supplied_power()` and power validation. | All return float; power close to voltage x current; max_power >= output_power | New | **psu-adapted** |
| 4 | Platform API | `test_pdb.py::test_is_replaceable` | Based on PSU `test_is_replaceable`. Change: expect False instead of True (PDB is not replaceable per HLD). | Returns bool; expected False | New | **psu-adapted** |
| 5 | Platform API | `test_pdb.py::test_get_name` | For each PDB, call `get_name()`. | Returns non-empty string matching platform.json | New | **psu-reuse** |
| 6 | Platform API | `test_pdb.py::test_get_presence` | For each PDB, call `get_presence()`. | Returns bool; installed PDBs return True | New | **psu-reuse** |
| 7 | Platform API | `test_pdb.py::test_get_model` | For each PDB, call `get_model()`. | Returns non-empty string | New | **psu-reuse** |
| 8 | Platform API | `test_pdb.py::test_get_serial` | For each PDB, call `get_serial()`. | Returns non-empty string | New | **psu-reuse** |
| 9 | Platform API | `test_pdb.py::test_get_revision` | For each PDB, call `get_revision()`. | Returns non-empty string | New | **psu-reuse** |
| 10 | Platform API | `test_pdb.py::test_get_status` | For each PDB, call `get_status()`. | Returns bool; working PDBs return True | New | **psu-reuse** |
| 11 | Platform API | `test_pdb.py::test_temperature` | For each PDB, call `get_temperature()`. | Returns float in a reasonable range | New | **psu-reuse** |
| 12 | Platform API | `test_pdb.py::test_thermals` | For each PDB, call `get_num_thermals()`, `get_all_thermals()`, `get_thermal(i)`. | num_thermals matches list length; get_thermal(i) is consistent | New | **psu-reuse** |

#### psud Daemon / Database Schema

psud reads PDB data through the Platform API and writes it to the `PDB_INFO` table in STATE_DB. For PSU, `test_psud.py` checks that psud is running and that `PSU_INFO` data survives daemon restart. PDB needs the same checks. Modify `test_psud.py` to also collect and verify `PDB_INFO` on PDB platforms.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 13 | Daemon / DB | `test_psud.py::test_pmon_psud_running_status` | Changes:<br>1. On PDB platforms, `collect_data()` also reads all PDB_INFO keys from STATE_DB.<br>2. Check `chassis_info` table has `pdb_num` field matching `get_num_pdbs()`.<br>3. Check PDB_INFO keys and data exist while psud is running. | PDB_INFO keys exist; data is not empty; chassis_info pdb_num is correct | New | **existing-modified** |
| 14 | Daemon / DB | `test_psud.py::test_pmon_psud_stop_and_start_status` | Change: `collect_data()` reads PDB_INFO along with PSU_INFO. `verify_data()` compares PDB_INFO static fields (skip dynamic fields like power, temp, current, voltage) before and after psud stop/start. | PDB_INFO static fields match before and after restart | New | **existing-modified** |
| 15 | Daemon / DB | `test_psud.py::test_pmon_psud_term_and_start_status` | Same as #14 but psud is stopped with SIGTERM. Check PDB_INFO fields are restored after psud restarts. | PDB_INFO static fields match before and after restart | New | **existing-modified** |
| 16 | Daemon / DB | `test_psud.py::test_pmon_psud_kill_and_start_status` | Same as #14 but psud is stopped with SIGKILL. Check PDB_INFO fields are restored after psud restarts. | PDB_INFO static fields match before and after restart | New | **existing-modified** |

#### CLI

CLI commands read from STATE_DB and show PDB information to the user.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 17 | CLI | `test_show_platform.py::test_show_platform_psustatus` | Change: update `get_dut_psu_line_pattern()` regex to also match `PDB \d+` in addition to `PSU \d+`. No other changes needed. | PDB rows parsed correctly; status is OK, NOT OK, or WARNING | New | **existing-modified** |
| 18 | CLI | `test_show_platform.py::test_show_platform_psustatus_json` | Change: add `is_support_pdb` fixture so the test runs on PDB platforms. Check JSON output has PDB entries with expected keys (name, presence, status, led_status, model, serial, voltage, current, power). | All expected keys present; status is valid | New | **existing-modified** |
| 19 | CLI | `test_show_platform.py::test_show_platform_temperature` | Change: on PDB platforms, check that the output has PDB thermal rows (e.g. `PDB-1 Temp`). The existing test only checks column count; add a check for at least one PDB thermal row. | PDB thermal rows present; table format is valid | New | **existing-modified** |

#### System Health

System-health monitors PDB status through STATE_DB.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 20 | System Health | `test_system_health.py::test_device_checker` | Changes:<br>1. Add `mock_pdb_presence(False/True)` and `mock_pdb_status(False/True)` to `device_mocker.py`.<br>2. In `test_device_checker`, add PDB mock steps: mock PDB absent, check health table shows missing, then restore and check it clears.<br>Same pattern as existing PSU mock checks. | PDB absent: health table shows missing; after restore: entry clears | New | **existing-modified** |

#### Error Handling

Test PDB error scenarios and check system behavior.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 21 | Error Handling | `test_platform_info.py::test_pdb_error_status_and_log` | For PSU, `test_turn_on_off_psu_and_check_psustatus` uses a PDU controller to power off PSU, then checks CLI and syslog. PDB is not removable, so use mock sysfs instead:<br>1. Mock PDB absent via sysfs, run `show platform psustatus`, check PDB status shows the error.<br>2. Use `LogAnalyzer` to check that expected error logs show up in syslog and no unexpected errors appear.<br>3. Restore the mock, check PDB status goes back to OK and error logs clear. | PDB error shown in CLI; expected logs in syslog; status recovers after restore | New | **new** |

#### Sanity

Nightly sanity check for PDB health on all testbeds.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 22 | Sanity | `test_sanity_checker.py` | Change: add a PDB check block. On PDB platforms, go through all PDBs and check each one is present and working. Log any failures to sanity results. Same pattern as PSU/BMC checks. | All PDBs present and working; failures logged to sanity results | New | **existing-modified** |
