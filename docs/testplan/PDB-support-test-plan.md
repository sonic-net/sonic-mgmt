# PDB (Power Distribution Board) Support Test Plan

## 1.1 Related Documents

| Document Name | Link |
|---------------|------|
| Support PDB flows HLD | [sonic-net/SONiC#2219](https://github.com/sonic-net/SONiC/pull/2219) |
| PDB sonic-mgmt test implementation | [sonic-net/sonic-mgmt#24227](https://github.com/sonic-net/sonic-mgmt/pull/24227) |

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

### 2.1 Setup Configuration

- DUT must have PDB hardware installed
- `platform.json` on the DUT must have the `pdbs` array with installed PDBs
- Platform API service must be running on the DUT

### 2.2 Configuration Diagram

No diagram needed.

### 2.3 Test Cases

PDB and PSU both inherit from `DeviceBase` but are separate objects. On PDB platforms, `get_num_psus()` returns 0 so PSU-only tests are skipped. PDB API tests are implemented in `test_pdb.py` through `TestPdbApi(TestPowerApi)`, while existing PSU API tests are refactored into `TestPsuApi(TestPowerApi)`. Shared power-device checks live in `power_api_test_base.py`.

Tag meanings: `new` = completely new test, no PSU equivalent; `psu-adapted` = based on PSU test but logic changed; `existing-modified` = existing test file modified to support PDB.

#### Platform API

Test PDB and chassis PDB APIs through the platform API service.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 1 | Platform API | test_chassis.py::test_pdbs | 1. Call `chassis.get_num_pdbs()`, check it returns an integer.<br>2. Compare the count with `platform.json` `pdbs` array length.<br>3. Call `chassis.get_all_pdbs()`, check list length equals num_pdbs.<br>4. For each index, call `chassis.get_pdb(i)` and check it matches the list entry.<br>5. On PSU platforms, check `get_num_pdbs()` returns 0 and `get_all_pdbs()` returns empty list. | Count matches platform.json; list and index consistent | New | **new** |
| 2 | Platform API | test_pdb.py::test_power | Based on PSU test_power. Changes:<br>1. Call both input and output power APIs: `get_input_voltage/current/power()` and `get_output_voltage/current/power()`.<br>2. For each set, check returns are float and power is close to voltage x current (within 10%).<br>3. Call `get_maximum_supplied_power()`, check max_power >= output_power.<br>4. Remove `get_powergood_status()` check (not in PDB HLD).<br>5. Remove `get_voltage_high/low_threshold()` checks (not in PDB HLD). | All return float; power close to voltage x current; max_power >= output_power | New | **psu-adapted** |
| 3 | Platform API | test_pdb.py::test_is_replaceable | For each PDB, call `is_replaceable()`. Only check that the API returns successfully (not None). Do not assert a specific True/False value because the implementation only requires the API to be available. | Returns not None | New | **psu-adapted** |
| 4 | Platform API | test_pdb.py::TestPdbApi::test_get_name | The common check is implemented once in `TestPowerApi` (`power_api_test_base.py`) and inherited by `TestPdbApi`. For each PDB, call `get_name()`. | Returns non-empty string matching platform.json | New | **psu-adapted** |
| 5 | Platform API | test_pdb.py::TestPdbApi::test_get_presence | The common check is implemented once in `TestPowerApi` (`power_api_test_base.py`) and inherited by `TestPdbApi`. For each PDB, call `get_presence()`. | Returns bool; installed PDBs return True | New | **psu-adapted** |
| 6 | Platform API | test_pdb.py::TestPdbApi::test_get_model | The common check is implemented once in `TestPowerApi` (`power_api_test_base.py`) and inherited by `TestPdbApi`. For each PDB, call `get_model()`. | Returns non-empty string | New | **psu-adapted** |
| 7 | Platform API | test_pdb.py::TestPdbApi::test_get_serial | The common check is implemented once in `TestPowerApi` (`power_api_test_base.py`) and inherited by `TestPdbApi`. For each PDB, call `get_serial()`. | Returns non-empty string | New | **psu-adapted** |
| 8 | Platform API | test_pdb.py::TestPdbApi::test_get_revision | The common check is implemented once in `TestPowerApi` (`power_api_test_base.py`) and inherited by `TestPdbApi`. For each PDB, call `get_revision()`. | Returns non-empty string | New | **psu-adapted** |
| 9 | Platform API | test_pdb.py::TestPdbApi::test_get_status | The common check is implemented once in `TestPowerApi` (`power_api_test_base.py`) and inherited by `TestPdbApi`. For each PDB, call `get_status()`. | Returns bool; working PDBs return True | New | **psu-adapted** |
| 10 | Platform API | test_pdb.py::test_temperature | For each PDB, call `get_temperature()`. | Returns float in a reasonable range | New | **psu-adapted** |
| 11 | Platform API | test_pdb.py::TestPdbApi::test_thermals | The common check is implemented once in `TestPowerApi` (`power_api_test_base.py`) and inherited by `TestPdbApi`. For each PDB, call `get_num_thermals()`, `get_all_thermals()`, `get_thermal(i)`. | num_thermals matches list length; get_thermal(i) is consistent | New | **psu-adapted** |

#### psud Daemon / Database Schema

psud reads PDB data through the Platform API and writes it to the `PSU_INFO` table in STATE_DB with `PDB X` keys (e.g. `PSU_INFO|PDB 1`). This reuses the same table as PSU. The `chassis_info` table stores `pdb_num`. For PSU, `test_psud.py` checks that psud is running and that `PSU_INFO` data survives daemon restart. PDB needs the same checks. Modify `test_psud.py` to also collect and verify `PSU_INFO|PDB X` entries on PDB platforms. PDB temperature rows under `TEMPERATURE_INFO|PDB X Temp` are owned by `thermalctld`, so they are covered by the thermal/CLI checks instead of psud restart checks.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 12 | Daemon / DB | test_psud.py::test_pmon_psud_running_status | Changes:<br>1. On PDB platforms, collect_data() also reads all PSU_INFO\|PDB * keys from STATE_DB.<br>2. Check chassis_info table has pdb_num field matching get_num_pdbs().<br>3. Check PSU_INFO\|PDB X keys and data exist while psud is running. | PSU_INFO\|PDB X keys exist; chassis_info pdb_num correct | New | **existing-modified** |
| 13 | Daemon / DB | test_psud.py::test_pmon_psud_stop_and_start_status | Change: collect_data() reads PSU_INFO\|PDB * along with PSU_INFO\|PSU *. verify_data() compares PDB static fields (skip dynamic fields like power, temp, current, voltage) before and after psud stop/start. | PDB static fields in PSU_INFO match before and after restart | New | **existing-modified** |
| 14 | Daemon / DB | test_psud.py::test_pmon_psud_term_and_start_status | Same as #13 but psud is stopped with SIGTERM. Check PSU_INFO\|PDB X fields are restored after psud restarts. | PDB static fields in PSU_INFO match before and after restart | New | **existing-modified** |
| 15 | Daemon / DB | test_psud.py::test_pmon_psud_kill_and_start_status | Same as #13 but psud is stopped with SIGKILL. Check PSU_INFO\|PDB X fields are restored after psud restarts. | PDB static fields in PSU_INFO match before and after restart | New | **existing-modified** |

#### CLI

CLI commands read from STATE_DB and show PDB information to the user.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 16 | CLI | test_show_platform.py::test_show_platform_psustatus | Change: update `get_dut_psu_line_pattern()` regex to also match `PDB \d+` in addition to `PSU \d+`. No other changes needed. | PDB rows parsed correctly; status is OK, NOT OK, or WARNING | New | **existing-modified** |
| 17 | CLI | test_show_platform.py::test_show_platform_psustatus_json | Changes:<br>1. Add `is_support_pdb` fixture from `duthost_utils.py`; it checks PDB support by reading `pdb_num` from `CHASSIS_INFO\|chassis 1` in STATE_DB and returns True when `pdb_num > 0`.<br>2. Check JSON output has PDB entries with expected keys (name, presence, status, led_status, model, serial, voltage, current, power).<br>3. Per HLD, all PDBs share a single front-panel power LED. Verify all PDB entries have the same `led_status` value. | All expected keys present; status is valid; all PDBs share the same led_status | New | **existing-modified** |
| 18 | CLI / Thermal | test_show_platform.py::test_show_platform_temperature | Change: on PDB platforms, check that `thermalctld`-owned temperature data is visible through CLI output with PDB thermal rows (e.g. `PDB-1 Temp`). The existing test only checks column count; add a check for at least one PDB thermal row. | PDB thermal rows present; table format is valid | New | **existing-modified** |

#### System Health

System-health monitors PDB status through STATE_DB.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 19 | System Health | test_system_health.py::test_pdb_device_checker | Changes:<br>1. Add PDB-specific mock helpers in `tests/common/helpers/pdb_mocker.py` and vendor support in `tests/system_health/mellanox/mellanox_device_mocker.py`.<br>2. Expose `mock_pdb_presence(False/True)` and `mock_pdb_status(False/True)` through `device_mocker.py`.<br>3. Add a separate `test_pdb_device_checker` test instead of folding PDB steps into the existing PSU `test_device_checker`.<br>4. Mock PDB absence and no-power status, verify the health table reports the expected PDB error, then restore and verify it clears.<br>5. Run `show system-health detail`, verify PDB rows have `Type` column set to `PDB` (per HLD). | PDB absent/no power: health table shows the expected error; after restore: entry clears; Type column is PDB | New | **existing-modified** |

#### Error Handling

Test PDB error scenarios and check system behavior.

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
|---|-----------|-----------|-----------------|----------------------|--------|------|
| 20 | Error Handling | test_platform_info.py::test_pdb_error_status_and_log | For PSU, `test_turn_on_off_psu_and_check_psustatus` uses a PDU controller to power off PSU, then checks CLI and syslog. PDB error validation should not depend on physical removal or PDU control, so use mock sysfs instead:<br>1. Mock PDB absent via sysfs, run `show platform psustatus`, check PDB status shows the error.<br>2. Use `LogAnalyzer` to check that expected error logs show up in syslog and no unexpected errors appear.<br>3. Restore the mock, check PDB status goes back to OK and error logs clear. | PDB error shown in CLI; expected logs in syslog; status recovers after restore | New | **new** |
