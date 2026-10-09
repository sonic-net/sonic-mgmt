# BMC Platform API and Daemon Test Plan

* [Definitions/Abbreviation](#definitionsabbreviation)
* [Overview](#overview)
  * [HLD](#hld)
  * [Testbed](#testbed)
* [Test Cases](#test-cases)
  * [Platform API Tests](#platform-api-tests)
  * [Bmcctld Daemon Tests](#bmcctld-daemon-tests)
  * [Thermalctld Daemon Tests](#thermalctld-daemon-tests)
  * [CLI Command Tests](#cli-command-tests)
  * [BMC Watchdog Tests](#bmc-watchdog-tests)

---

## Definitions/Abbreviation

| **Term** | **Description** |
|----------|-----------------|
| BMC | Baseboard Management Controller |
| SWITCH-HOST | Module representing the Switch and CPU cards in a BMC-managed system |
| LeakageSensorBase | Platform API for liquid cooling leak detection sensors |
| ModuleBase | Platform API for controlling switch modules |
| Bmcctld | BMC control daemon managing switch-host lifecycle |
| Thermalctld | Thermal management daemon with leak detection enhancements |
| CHASSIS_MODULE_INFO | State DB table for module configuration |
| LIQUID_COOLING_INFO | State DB table for leak sensor status |
| SYSTEM_LEAK_STATUS | State DB table for system-level leak status |

---

## Overview

This test plan covers comprehensive testing of new BMC platform APIs and daemon enhancements for SONiC BMC systems. The tests verify:

1. **LeakageSensorBase Platform API** - New API for accessing liquid cooling leak detection sensors
2. **ModuleBase SWITCH-HOST APIs** - New APIs for controlling the switch-host module in BMC systems
3. **Thermal Leak Detection State DB** - New State DB schema for leak detection status
4. **Bmcctld Daemon** - New daemon managing switch-host power lifecycle and module control
5. **Thermalctld Enhancements** - Updates to thermal daemon for leak detection and escalation
6. **CLI Commands** - New and updated CLI commands for BMC management

### HLD

The following are the design documents referenced for this testplan

- **BMC Design Document**: https://github.com/sonic-net/SONiC/blob/master/doc/bmc/sonicBMC/pmon-bmc-design.md
- **BMC High-Level Test Plan**: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/bmc/BMC-high-level-test-plan.md

### Testbed

Any SONiC BMC testbed with:
- BMC running SONiC
- Optional liquid cooling system (for leak detection tests)
- Optional SWITCH-HOST module support (for module control tests)

Tests will gracefully skip features not available on the target platform.

## Test Architecture

This section captures the BMC-specific additions on top of the existing sonic-mgmt test framework.

### 1. Inventory and Testbed Wiring

BMC and switch host live as regular entries in the `sonic` inventory group with a `-bmc` suffix on the BMC host (e.g. `host1-switch` / `host1-switch-bmc`). The pair is wired at the testbed layer — the `dut:` list holds the BMC and the existing `bmc_host:` field points at the paired switch — so `duthost` resolves to the BMC and `tbinfo['bmc_host']` to the switch.

Sample inventory entry (fields follow the existing `ansible/lab` style — `model`, `serial`, `base_mac`, `syseeprom_info` map of ONIE TLVs):

```yaml
sonic:
  hosts:
    host1-switch:
      ansible_host: 192.168.200.20
      hwsku: <switch-hwsku>
      mgmt_subnet_mask_length: 24
      model: <switch-model>
      serial: <switch-serial>
      base_mac: 24:8a:07:11:22:33
      syseeprom_info:
        "0x21": "<part-number>"
        "0x22": "<part-number-alt>"
        "0x23": "<serial>"
        "0x24": "24:8a:07:11:22:33"
        "0x25": "<mfg-date>"

    host1-switch-bmc:
      ansible_host: 192.168.200.10
      hwsku: <bmc-hwsku>
      mgmt_subnet_mask_length: 24
      console_baudrate: 115200
      model: <bmc-model>
      serial: <bmc-serial>
      base_mac: 24:8a:07:11:22:34
      syseeprom_info:
        "0x21": "<part-number>"
        "0x22": "<part-number-alt>"
        "0x23": "<serial>"
        "0x24": "24:8a:07:11:22:34"
        "0x25": "<mfg-date>"
```

Corresponding `ansible/testbed.yaml` entry:

```yaml
- conf-name: testbed-host1-switch-bmc
  topo: bmc-dual-mgmt
  dut:
    - host1-switch-bmc
  bmc_host: host1-switch
  inv_name: lab
```

### 2. BMC vs Switch Host Discrimination

The following APIs exists today

 - `is_bmc()` on `SonicHost` returns `self.facts.get('router_type') == 'NetworkBmc'` (Check if it is BMC)
 - `get_bmc_host()` (Get Switch-Host from BMC)

New API added to get the BMC instance from switch-host

 - `get_bmc_from_host()`


### 3. Topology Marker

Tests mark `@pytest.mark.topology('bmc')` to opt into the BMC topology. No new topo file is introduced — the existing `topo_bmc-dual-mgmt.yml` is reused.

### 4. Platform API Connection

Two new helpers under `tests/common/helpers/platform_api/` mirror the upstream classes and call through the existing `platform_api_conn` fixture:

| Helper | Upstream class | Endpoint prefix |
|---|---|---|
| `liquid_cooling.py` | `LiquidCoolingBase` | `/platform/chassis/liquid_cooling/{name}` |
| `leak_sensor.py` | `LeakageSensorBase` / `LeakSensorProfileBase` | `/platform/chassis/liquid_cooling/leak_sensor/{index}/{name}` |

### 5. Liquid Cooling Feature Gate

Leak-sensor tests run only on liquid-cooled systems. A module-scoped autouse fixture `skip_if_not_liquid_cooled` probes `Chassis().is_liquid_cooled()` once over SSH and skips the module when `False`. Per-test setup calls `liquid_cooling.get_num_leak_sensors()` over the platform API and skips when the count is 0.

### 6. Test Style Conventions

- One API call per assertion; no duplicate consecutive reads to "confirm consistency."
- Identity attributes validated for type/shape (e.g. non-empty string) rather than compared against `platform.json` values.
- Chassis-level feature gates are module-scoped; per-test state is function-scoped.
- Use `@pytest.mark.topology('bmc')` unless a test is exclusive to one BMC topology.

---

## Test Cases

### Platform API Tests

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`, `tests/platform_tests/api/test_liquid_cooling_leakage.py`, `tests/platform_tests/api/test_switch_host_module.py`

These tests use the `platform_api_conn` fixture, which is an HTTP connection to the `platform_api_server` running inside the `pmon` docker. Each API call is dispatched as an HTTP request to the server, which invokes the vendor platform implementation and returns the result. No direct shell or redis access is used in this section.

#### Test Case #1: test_leak_sensor_identity_attributes

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

**Test Objective**:
Verify LeakageSensorBase identity attributes: name, type, location.

**Test Steps**:
1. Skip if no leak sensors detected
2. For each sensor, call `get_name()` — verify non-empty string, consistent across calls
3. For each sensor, call `get_leak_sensor_type()` — verify string or None, non-empty if present
4. For each sensor, call `get_leak_sensor_location()` — verify string or None, non-empty if present

**Expected Result**:
- `get_name()`, `get_leak_sensor_type()`, `get_leak_sensor_location()` return non-empty strings
- Values are consistent across repeated calls

---

#### Test Case #2: test_leak_sensor_status_attributes

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

**Test Objective**:
Verify LeakageSensorBase status attributes: `is_leak()`, `is_leak_sensor_ok()`, `get_leak_severity()`.

**Test Steps**:
1. Skip if no leak sensors detected
2. For each sensor, call `is_leak()` — verify boolean, consistent
3. For each sensor, call `is_leak_sensor_ok()` — verify boolean, consistent
4. For each sensor, call `get_leak_severity()` — verify value in {MINOR, CRITICAL, None}

**Expected Result**:
- Status fields return correct types
- Severity is one of the valid enum values
- All values are consistent across repeated calls

---

#### Test Case #3: test_leak_sensor_profile

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

**Test Objective**:
Verify `LeakSensorProfileBase` methods (`get_type()`, `get_leak_max_minor_duration_sec()`) and `LiquidCoolingBase.get_all_profiles()`.

**Test Steps**:
1. Skip if no leak sensors detected
2. For each sensor: call `get_profile_type()` — verify non-empty string (e.g. `rope`, `spot`, `flex_pcb`)
3. For each sensor: call `get_leak_max_minor_duration_sec()` — verify None (unsupported) or a positive number
4. Call `liquid_cooling.get_all_profiles()` — if non-None, verify it is a list

**Expected Result**:
- `get_profile_type()` returns a non-empty string for every sensor
- `get_leak_max_minor_duration_sec()` returns a positive int/float or None
- `get_all_profiles()` returns a list of profile objects (when supported)

---

#### Additional Coverage: test_liquid_cooling_leakage.py

**File**: `tests/platform_tests/api/test_liquid_cooling_leakage.py`

This module is also part of the BMC liquid-cooling API scope. It validates the same leak-sensor domain through `LiquidCoolingBase`/`LeakageSensorBase` entry points with:
- `test_get_name`
- `test_is_leak`
- `test_get_leak_sensor_status`
- `test_get_all_leak_sensors`

It complements Test Cases #1-#3 by covering aggregate leak-sensor API behavior on liquid-cooled BMC platforms.

---


#### Test Case #4: test_switch_host_identity

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify SWITCH-HOST module identity attributes: name, description, serial, type.

**Test Steps**:
1. Skip if SWITCH-HOST not supported
2. `get_name()` — non-empty string
3. `get_description()` — non-empty string
4. `get_serial()` — non-empty string
5. `get_type()` — non-empty string

**Expected Result**:
- All four identity attributes are non-empty strings

---

#### Test Case #5: test_switch_host_status_control

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify SWITCH-HOST admin/oper status attributes and their consistency relationship.

**Test Steps**:
1. `module.get_oper_status()` — value in `{Online, Offline}`
2. Read CONFIG_DB `CHASSIS_MODULE|SWITCH-HOST admin_status`
3. Cross-check admin/oper consistency: `up → Online`, `down → Offline`
4. **Disruptive shutdown/startup cycle** on paired Switch-Host:
   - `set_admin_state(False)` → wait for oper == `Offline` (case-insensitive)
   - `set_admin_state(True)` → wait for `critical_services_fully_started`
   - Assert `uptime -s` advanced and `show reboot-cause` reports a BMC-initiated cause
   - Assert oper == `Online` (case-insensitive)

**Expected Result**:
- `get_oper_status()` returns `Online` or `Offline` (case-insensitive)
- CONFIG_DB `admin_status` matches the effective oper status per the table above
- `set_admin_state(up: bool)` returns `True`
- After the down→up cycle the paired switch boots and reports the expected reboot cause

---

#### Test Case #6: test_chassis_is_bmc

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify `chassis.is_bmc()` returns `True` on BMC topology and `get_bmc()` returns a non-None object.

**Test Steps**:
1. Call `is_bmc()` via platform API — verify returns `bool`
2. Assert result is `True` (test runs on `topology('bmc')`)
3. Call `get_bmc()` — verify returns non-None object

**Expected Result**:
- `is_bmc()` returns `True` on all BMC-topology DUTs
- `get_bmc()` returns a valid (non-None) BMC object

---

#### Test Case #7: test_chassis_is_liquid_cooled

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify `chassis.is_liquid_cooled()` returns a boolean consistent with `get_liquid_cooling()`.

**Test Steps**:
1. Call `is_liquid_cooled()` — verify returns `bool`, consistent across two calls
2. If `True` — call `get_liquid_cooling()` and verify it returns non-None
3. If `False` — log that chassis is air-cooled (valid result)

**Expected Result**:
- Return value is always a bool
- Value is stable across repeated calls
- `get_liquid_cooling()` is non-None when `is_liquid_cooled()` is `True`

---

#### Test Case #8: test_chassis_module_enumeration

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify module enumeration APIs: `get_num_modules()`, `get_all_modules()`, `get_module(index)`, and `get_module_index(name)` round-trip.

**Test Steps**:
1. Call `get_num_modules()` — verify non-negative integer
2. If > 0: call `get_all_modules()` — verify list length matches `get_num_modules()`
3. Call `get_module(0)` — verify non-None for valid index
4. Call `get_module_index('SWITCH-HOST')` — verify valid integer if SWITCH-HOST present
5. Round-trip: `get_module(get_module_index('SWITCH-HOST'))` — verify non-None

**Expected Result**:
- Module count is a non-negative integer
- `get_all_modules()` length matches count
- `get_module(0)` returns a valid module object
- SWITCH-HOST index round-trip returns a non-None module

---

#### Test Case #9: test_switch_host_do_power_cycle

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify the `do_power_cycle()` platform API powers the SWITCH-HOST off and back on, and that the switch genuinely came back up afterwards.

**Test Steps**:
1. Call `chassis.get_module_index('SWITCH-HOST')` — skip if not found
2. Resolve paired switch via `duthost.get_bmc_host()`; record pre-cycle `uptime -s`
3. Call `module.do_power_cycle()` via platform API — assert return is `True`
4. Wait for `host.critical_services_fully_started()` (up to `graceful_shutdown_timeout + power_on_delay + 300 s`)
5. Run `uptime -s` on the paired switch — assert post-cycle boot timestamp is newer than pre-cycle
6. Run `show reboot-cause` on the paired switch — assert cause is `power down request from BMC` or `graceful shutdown from BMC`

**Expected Result**:
- `do_power_cycle()` returns `True`
- Paired switch's `uptime -s` advances (newer boot timestamp)
- `show reboot-cause` reports a BMC-initiated cause

---

### Bmcctld Daemon Tests

**File**: `tests/platform_tests/daemon/test_bmcctld.py`

#### Test Case #10: test_bmcctld_initialization

**Test Objective**:
Verify bmcctld initializes CHASSIS_MODULE_INFO and HOST_STATE tables on startup
after a BMC reboot, and skips the boot delay for non-power-loss reboot causes.

**Test Steps**:
1. Cold-reboot the BMC and wait for bmcctld to come up
2. Query `CHASSIS_MODULE_INFO:SWITCH-HOST` — required fields present
3. Query `HOST_STATE` — `device_status` and `timestamp` present
4. Scan pmon journal for `Skipping SWITCH_HOST_POWER_ON_DELAY` (cold reboot is not power-loss)

**Expected Result**:
- bmcctld is running after reboot
- State DB tables initialized with required fields on BMC platforms
- pmon journal contains `"Skipping SWITCH_HOST_POWER_ON_DELAY"` — boot delay is
  skipped for non-power-loss reboot causes

---

#### Test Case #11: test_bmcctld_event_trigger

**Test Objective**:
Verify bmcctld reacts to HSET writes on all four `SubscriberStateTable`-monitored tables, logs the corresponding event, and dispatches the configured power action when severity escalates to `CRITICAL`. Also verifies bmcctld's daemon integrations (`thermalctld` running, `config chassis modules` CLI present) and that the BMC event log file `/host/bmc/event.log` exists with fresh entries after triggers.

**Test Steps**:

Each non-disruptive scenario injects a value, waits up to 30 s for the expected log entry, then restores the original value in `finally`.

1. **Admin status flip** — CONFIG_DB `CHASSIS_MODULE|SWITCH-HOST admin_status` (up↔down); check syslog for `SWITCH-HOST`
2. **MINOR leak (`syslog_only`)** — STATE_DB `SYSTEM_LEAK_STATUS:system device_leak_status = MINOR`
   - **Pause `thermalctld`** while the value is injected so it does not overwrite `device_leak_status` back to clear; restart it in `finally`
   - Syslog contains a `leak` entry; **no** power action (Switch-Host SSH stays up, `uptime -s` unchanged)
   - **Check**: `/host/bmc/event.log` must NOT contain a MINOR leak entry (MINOR is syslog-only; `event.log` is reserved for CRITICAL)
3. **CRITICAL leak → Switch-Host power off** (disruptive):
   - Snapshot Switch-Host `uptime -s`
   - Ensure `system_critical_leak_action = power_off`
   - **Pause `thermalctld`** to keep the injected value pinned; set `device_leak_status = CRITICAL`
   - Wait for Switch-Host SSH drop, then for `critical_services_fully_started`
   - Assert `uptime -s` advanced and `show reboot-cause` reports a BMC-initiated cause
   - `finally`: restart `thermalctld`, restore policy, and if needed `config chassis modules startup SWITCH-HOST` to recover
4. **Rack-manager alert** — inject STATE_DB `RACK_MANAGER_ALERT:test_trigger_alert severity = MINOR`; default action is syslog-only; no power action
5. **Pre-flight checks** — `thermalctld` is RUNNING and `config chassis modules --help` exposes the `startup`/`shutdown` commands
6. **Post-check** — if `/host/bmc/event.log` exists, it has fresh entries; otherwise log info

**Expected Result**:
- Each trigger produces the expected log entry
- MINOR leak: syslog only, paired Switch-Host stays up
- CRITICAL leak: paired Switch-Host is powered off and reboots; `show reboot-cause` on the Switch-Host reports a BMC-initiated cause
- Duplicate HSET with the same value is ignored (dedup)
- All injected keys are cleaned up regardless of test outcome
- Platforms without BMC support log info messages and the assertion is skipped
- `thermalctld` running and `config chassis modules` CLI present
- `/host/bmc/event.log` (when present) contains fresh entries after the triggers

---

#### Test Case #12: test_bmcctld_rack_manager_command

**File**: `tests/platform_tests/daemon/test_bmcctld.py`

**Test Objective**:
Verify bmcctld dispatches the correct power action for each valid `RACK_MANAGER_COMMAND` (`POWER_OFF`, `GRACEFUL_SHUT`, `POWER_ON`, `POWER_CYCLE`), the `status` field transitions `PENDING → IN_PROGRESS → DONE`, the paired Switch-Host actually undergoes the requested power transition with a BMC-initiated reboot cause, and unknown commands are rejected with `status = FAILED` without any power action.

**Test Steps**:

Each scenario snapshots Switch-Host `uptime -s` first; the `finally` block restores the Switch-Host with `config chassis modules startup SWITCH-HOST` if it didn't auto-recover.

1. **POWER_OFF then POWER_ON** — issue each command; assert command `status = DONE`, Switch-Host SSH drops then comes back, `uptime -s` advances, reboot-cause is BMC-initiated
2. **GRACEFUL_SHUT then POWER_ON** — same flow; reboot-cause is `graceful shutdown from BMC`
3. **POWER_CYCLE** — single command; assert `status = DONE`, `uptime -s` advances, reboot-cause is BMC-initiated
4. **POWER_ON blocked by CRITICAL leak** (negative):
   - Inject `SYSTEM_LEAK_STATUS|system device_leak_status = CRITICAL`
   - Issue `POWER_ON`; assert `status = FAILED` and the error field contains `CRITICAL_LEAK_PRESENT`
5. **Unknown command rejected** (negative, non-disruptive):
   - Issue `command = TEST_UNKNOWN_COMMAND`; assert `status = FAILED` and Switch-Host `uptime -s` unchanged

**Expected Result**:
- For each valid command (`POWER_OFF`, `GRACEFUL_SHUT`, `POWER_ON`, `POWER_CYCLE`) the command `status` transitions to `DONE`
- Switch-Host undergoes the requested power transition; `uptime -s` advances; `show reboot-cause` on the Switch-Host reports a BMC-initiated cause
- `POWER_ON` issued while a CRITICAL leak is present fails with status `FAILED` and reason `CRITICAL_LEAK_PRESENT`
- Unknown commands fail with status `FAILED` and the paired Switch-Host is not power-cycled
- All injected keys are deleted and the Switch-Host is left powered on in `finally`

---

#### Test Case #13: test_bmcctld_power_on_delay

**File**: `tests/platform_tests/daemon/test_bmcctld.py`

**Test Objective**:
Verify that `power_on_delay` is configurable via `config chassis modules power-on-delay`, that bmcctld picks up the new value from CONFIG_DB, and that bmcctld's apply-vs-skip decision is driven by the **BMC's own last reboot cause** (not by anything the Switch-Host does):
- Non-power-loss reboot of the BMC → bmcctld **skips** the delay
- Power-loss reboot of the BMC (real AC loss via external PDU) → bmcctld **applies** the configured delay before dispatching POWER_ON to the Switch-Host
- Note: default `power_on_delay` may be pre-seeded by platform policy (for example, 300s on liquid-cooled systems)

**Test Steps**:
1. Snapshot original `power_on_delay`; set a short test value (e.g. 30 s) via `config chassis modules power-on-delay SWITCH-HOST 30`; assert CONFIG_DB reflects it
2. **Scenario A — BMC cold reboot** (non-power-loss):
   - Cold-reboot the BMC; scan pmon journal — `Skipping SWITCH_HOST_POWER_ON_DELAY` present, no delay applied
3. **Scenario B — BMC power loss via external PDU** (skip if no PDU controller):
   - PDU off then on; scan pmon journal — `SWITCH_HOST_POWER_ON_DELAY 30` present, then assert the subsequent `Issuing power_on` log line lands `30 ± 30 s` later
4. `finally`: restore the original `power_on_delay`

**Expected Result**:
- `config chassis modules power-on-delay` updates CONFIG_DB; new value is reflected in `CHASSIS_MODULE|SWITCH-HOST power_on_delay`
- Scenario A: bmcctld emits a "Skipping" log on non-power-loss reboot; no delay is applied
- Scenario B: bmcctld emits `SWITCH_HOST_POWER_ON_DELAY <N>` on power-loss reboot and waits ≥`<N>` seconds before dispatching POWER_ON
- Scenario B is gracefully skipped on testbeds without a PDU controller
- Original `power_on_delay` value is restored

---

#### Test Case #14: test_bmc_reboot_does_not_affect_switch_host

**File**: `tests/platform_tests/daemon/test_bmcctld.py`

**Test Objective**:
Verify the BMC SONiC instance can be cold-rebooted in isolation: the paired Switch-Host must NOT power-cycle, reboot, or see any service interruption. Confirmed via reboot-cause history on both sides — a new entry must appear on the BMC, and no new entry must appear on the Switch-Host.

**Test Steps**:
1. Snapshot both sides: `uptime -s` and `show reboot-cause history` length on BMC and Switch-Host
2. Cold-reboot the BMC and wait for `critical_services_fully_started`
3. Assert BMC `uptime -s` advanced and its reboot-cause history grew by exactly 1
4. Assert Switch-Host `uptime -s` unchanged and reboot-cause history length unchanged

**Expected Result**:
- BMC reboot succeeds; BMC's own reboot-cause history shows a new "User issued 'reboot' command" entry
- Switch-Host is undisturbed: uptime unchanged, no new reboot-cause history entry
- This confirms BMC↔Switch-Host fault isolation: a BMC self-reboot does not trigger any `POWER_OFF`, `POWER_ON`, or `POWER_CYCLE` action on the Switch-Host

---

#### Test Case #15: test_pmon_bmcctld_running_status

**Test Objective**: Verify bmcctld is in RUNNING state with a valid pid at test start.

**Test Steps**:
1. Skip if bmcctld is not enabled (`check_pmon_daemon_enable_status`)
2. Call `get_pmon_daemon_status("bmcctld")` — assert status is `RUNNING` and pid != -1

**Expected Result**: bmcctld is running with a positive pid.

---

#### Test Case #16: test_pmon_bmcctld_stop_and_start_status

**Test Objective**: Verify bmcctld stops cleanly via supervisorctl and recovers after start.

**Test Steps**:
1. Record pre-stop pid
2. `stop_pmon_daemon(bmcctld, None)` — assert status becomes `STOPPED`, pid == -1
3. `start_pmon_daemon(bmcctld)` — wait up to 120 s for new pid > pre-stop pid
4. Assert post-restart status is `RUNNING` and pid incremented

**Expected Result**: bmcctld stops and restarts with a new pid.

---

#### Test Case #17: test_pmon_bmcctld_term_and_start_status

**Test Objective**: Verify bmcctld auto-restarts after SIGTERM (supervisord autorestart).

**Test Steps**:
1. Record pre-term pid
2. `stop_pmon_daemon(bmcctld, "-15", pid)` — send SIGTERM
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-term pid and status `RUNNING`

**Expected Result**: bmcctld auto-restarts after SIGTERM.

---

#### Test Case #18: test_pmon_bmcctld_kill_and_start_status

**Test Objective**: Verify bmcctld auto-restarts after SIGKILL (supervisord autorestart) and remains functional afterwards.

**Test Steps**:
1. Record pre-kill pid
2. `stop_pmon_daemon(bmcctld, "-9", pid)` — send SIGKILL
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-kill pid and status `RUNNING`
4. **Post-restart smoke** — verify bmcctld is functional again:
   - HSET `CONFIG_DB CHASSIS_MODULE|SWITCH-HOST admin_status` to its current value (no-op flip-restore)
   - Confirm syslog records the subscription-handler entry within 30 s (proves SubscriberStateTable callbacks reattached)
   - Read `STATE_DB CHASSIS_MODULE_TABLE|SWITCH-HOST oper_status` — assert non-empty
   - Read `STATE_DB HOST_STATE|switch-host device_status` — assert non-empty

**Expected Result**:
- bmcctld auto-restarts after SIGKILL with a new pid
- After restart the daemon serves at least one CONFIG_DB subscription event and STATE_DB tables remain populated

---

### Thermalctld Daemon Tests

**File**: `tests/platform_tests/daemon/test_thermalctld.py`

#### Test Case #19: test_thermalctld_leak_status

**Status**: **Deferred / Not currently supported**

**Reason**: Reliable verification of `SYSTEM_LEAK_STATUS device_leak_status` requires either a real hardware leak (cannot be exercised in the test fleet) or a vendor-specific leak-injection knob (not yet standardised across platforms). Direct STATE_DB injection bypasses thermalctld's own state-machine and would only re-test what the bmcctld and thermalctld event-trigger tests already cover.

This test will be enabled once a generic vendor-agnostic leak-injection mechanism is added to `sonic-platform-common` (tracked separately). Until then the test file contains a `pytest.skip("Not supported until generic leak injection is available")` placeholder so the test ID stays reserved.

**Planned Test Steps (for reference, not executed)**:
1. Query `SYSTEM_LEAK_STATUS:system device_leak_status` — verify in {MINOR, CRITICAL, None}
2. For each `LIQUID_COOLING_INFO` sensor:
   - `leaking` must be `Yes | No | N/A`
   - `leak_sensor_status` must be `Good | Fault`
   - `leak_severity` must be `MINOR | CRITICAL`
3. Query each `LEAK_PROFILE` entry — verify `max_minor_duration_sec > 0`
4. When `device_leak_status = CRITICAL`, assert at least one sensor shows `leak_severity = CRITICAL`
5. Verify CRITICAL leak propagates to `HOST_STATE:switch-host device_status`

---

#### Test Case #20: test_thermalctld_event_trigger

**Test Objective**:
Inject a leaking sensor state into LIQUID_COOLING_INFO and verify STATE_DB presence and the associated syslog entry.

**LIQUID_COOLING_INFO schema** (from `LiquidCoolingUpdater._refresh_leak_status`):
- `leaking` — `Yes | No | N/A`
- `leak_sensor_status` — `Good | Fault`
- `name`, `type`, `location`, `leak_severity`

**Syslog message thermalctld emits on hardware transition**:
- `is_leak()=True` → `log_error('...sensor {} reported leaking')`
- Recovery → `log_notice('...sensor {} recovered from leaking')`

**Test Steps**:
1. Inject `LIQUID_COOLING_INFO:test_sensor_leaking` with `leaking=Yes, leak_sensor_status=Good`; verify STATE_DB presence and syslog contains `reported leaking`
2. `finally`: delete injected key

**Expected Result**:
- The trigger produces STATE_DB evidence or a syslog entry on a liquid-cooled system
- The injected key is cleaned up regardless of outcome

---

#### Test Case #21: test_thermalctld_leak_severity_aggregation

**File**: `tests/platform_tests/daemon/test_thermalctld.py`

**Status**: **Deferred / Not currently supported**

**Reason**: Verifying `SYSTEM_LEAK_STATUS|system` aggregation requires flipping `is_leak()` on real sensor objects (a vendor-specific or generic leak-injection mechanism). Direct STATE_DB injection into `LIQUID_COOLING_INFO` cannot drive thermalctld's in-memory aggregator (`self.leaking_sensors`, populated only from hardware polls in `_refresh_leak_status`).

The test file contains a `pytest.skip("Not supported until generic leak injection is available")` placeholder so the test ID stays reserved.

**Test Objective (planned)**:
Exercise the §2.1.5 aggregation truth table end-to-end: hardware `is_leak()` → in-memory `self.leaking_sensors` → `LIQUID_COOLING_INFO|<sensor>` (per-sensor row) → `SYSTEM_LEAK_STATUS|system device_leak_status` (aggregated).

**Aggregation truth table**:

| # | Individual Leak Sensors                              | System Leak (expected output) |
|---|------------------------------------------------------|-------------------------------|
| 1 | 1 CRITICAL sensor                                    | `CRITICAL`                    |
| 2 | 2+ sensors of any severity                           | `CRITICAL`                    |
| 3 | 1 MINOR sensor staying for > `max_minor_duration_sec`| `CRITICAL` (escalation)       |
| 4 | 1 MINOR sensor (< escalation threshold)              | `MINOR`                       |

**Planned Test Steps (for reference, not executed)**:
1. Pre-flight: skip if leak injection is not supported on this platform. Skip if current `device_leak_status` is already `CRITICAL`.
2. **Rule 1** — inject a leak on 1 sensor with leak_severity `CRITICAL`; wait ≤2 poll cycles; assert `LIQUID_COOLING_INFO|<s0>.leaking=Yes, leak_sensor_status=Good, leak_severity=CRITICAL` and `SYSTEM_LEAK_STATUS|system.device_leak_status=CRITICAL`. Clear the leak; wait for `device_leak_status` to recover.
3. **Rule 2** — inject a leak on 2 sensors (any severity); wait ≤2 poll cycles; assert both per-sensor rows have `leaking=Yes` and `SYSTEM_LEAK_STATUS=CRITICAL` (multi-sensor bumps to CRITICAL regardless of individual severity). Recover.
4. **Rule 3** — temporarily set `LEAK_PROFILE|<type>.max_minor_duration_sec=5`; inject a leak on 1 sensor with leak_severity `MINOR`; wait ≤2 poll cycles → assert `SYSTEM_LEAK_STATUS=MINOR`; wait >5s → assert escalates to `SYSTEM_LEAK_STATUS=CRITICAL` and per-sensor `leak_severity=CRITICAL`. Recover; restore profile.
5. **Rule 4** — with the default `max_minor_duration_sec`, inject a leak on 1 sensor with leak_severity `MINOR`; wait ≤2 poll cycles; assert `SYSTEM_LEAK_STATUS=MINOR` and per-sensor `leak_severity=MINOR`. Recover.
6. `finally`: clear any injected leaks, restore any modified `LEAK_PROFILE` rows, and verify `device_leak_status` returns to its original value.

**Expected Result**:
- Rule 1: 1 CRITICAL sensor → `SYSTEM_LEAK_STATUS=CRITICAL`
- Rule 2: 2 sensors (any severity) → `SYSTEM_LEAK_STATUS=CRITICAL`
- Rule 3: 1 MINOR sensor + shortened threshold → `SYSTEM_LEAK_STATUS` transitions `MINOR` → `CRITICAL` after `max_minor_duration_sec`
- Rule 4: 1 MINOR sensor (default threshold) → `SYSTEM_LEAK_STATUS=MINOR`
- Every per-sensor `LIQUID_COOLING_INFO` row reflects the mocked `leaking` and `leak_severity` consistently
- After clearing the injected leaks, `device_leak_status` clears within ≤2 poll cycles; all profile fields and original system state restored
- syslog contains the expected thermalctld `Liquid cooling leakage sensor <name> reported leaking` / `recovered from leaking` lines for each mocked sensor

---

#### Test Case #22: test_thermalctld_faulty_sensor

**Test Objective**:
Verify thermalctld correctly represents a faulty/unreadable sensor in STATE_DB and
confirm the associated syslog format.

**Test Steps**:
1. Inject `LIQUID_COOLING_INFO:test_faulty_sensor_check` with `leaking=N/A, leak_sensor_status=Fault, leak_severity=CRITICAL, type=liquid, location=rack`
2. Verify `leaking=N/A` and `leak_sensor_status=Fault` land in STATE_DB
3. Check recent syslog for real `reported faulty` events — verify format contains `leakage sensor` or `liquid`
4. Verify `SYSTEM_LEAK_STATUS:system timestamp` is present (thermalctld updates system table even when sensors are faulty)
5. `finally`: delete injected key

**Expected Result**:
- `leaking=N/A` and `leak_sensor_status=Fault` confirmed in STATE_DB
- Real `reported faulty` syslog entries (if present) match expected format
- `SYSTEM_LEAK_STATUS:system` timestamp present on liquid-cooled platforms
- Injected key deleted in `finally` block

---

#### Test Case #23: test_thermalctld_chassis_thermal_monitoring

**Test Objective**:
Verify the end-to-end BMC chassis-thermal monitoring pipeline on the BMC (topology=`bmc`):

1. Switch-Host's thermalctld mirrors `TEMPERATURE_INFO` into the BMC's STATE_DB
   (`TemperatureUpdater._bmc_table_set()` via `db_connect_remote`).
2. BMC's thermalctld reads those entries (`_check_switch_host_thermals()`) and logs
   CRITICAL threshold breaches to syslog and `/host/bmc/event.log`.

Both aspects are validated in a single test since they share the same data
(`TEMPERATURE_INFO|*` in the BMC's STATE_DB) and run on the same BMC DUT.

**Test Steps**:
1. Login to the paired Switch-Host via `get_switch_host_or_skip_test(duthost)`; skip if unreachable.
2. Assert Switch-Host syslog contains `"Mirroring TEMPERATURE_INFO to BMC STATE_DB"`
   (confirms `_init_bmc_temperature_table()` ran on the Switch-Host).
3. Assert `TEMPERATURE_INFO|*` entries exist in the BMC's STATE_DB (push landed); skip if empty.
4. Assert BMC syslog contains `"Monitoring chassis thermals.*TEMPERATURE_INFO.*CRITICAL"`
   (confirms BMC thermalctld activated `_init_switch_host_thermal_monitor()`).
5. Inject `TEMPERATURE_INFO|test_critical_thermal_monitor` with
   `temperature=120.0, critical_high_threshold=80.0`.
6. Wait up to 90 s; assert syslog contains
   `"CRITICAL chassis thermal.*test_critical"` (transition-based, fires once on new breach).
7. `finally`: delete injected key.

**Expected Result**:
- Switch-Host syslog confirms mirror push was initiated.
- `TEMPERATURE_INFO|*` entries are present in the BMC STATE_DB.
- BMC syslog confirms chassis-thermal monitoring is active.
- Injected 120 °C > 80 °C threshold breach produces a `"CRITICAL chassis thermal"` log within 90 s.
- Injected key is cleaned up regardless of outcome.

---

#### Test Case #24: test_pmon_thermalctld_running_status

**Test Objective**: Verify thermalctld is in RUNNING state with a valid pid at test start.

**Test Steps**:
1. Skip if thermalctld is not enabled (`check_pmon_daemon_enable_status`)
2. Call `get_pmon_daemon_status("thermalctld")` — assert status is `RUNNING` and pid != -1

**Expected Result**: thermalctld is running with a positive pid.

---

#### Test Case #25: test_pmon_thermalctld_stop_and_start_status

**Test Objective**: Verify thermalctld stops cleanly via supervisorctl and recovers after start.

**Test Steps**:
1. Record pre-stop pid
2. `stop_pmon_daemon(thermalctld, None)` — assert status becomes `STOPPED`, pid == -1
3. `start_pmon_daemon(thermalctld)` — wait up to 120 s for new pid > pre-stop pid
4. Assert post-restart status is `RUNNING` and pid incremented

**Expected Result**: thermalctld stops and restarts with a new pid.

---

#### Test Case #26: test_pmon_thermalctld_term_and_start_status

**Test Objective**: Verify thermalctld auto-restarts after SIGTERM.

**Test Steps**:
1. Record pre-term pid
2. `stop_pmon_daemon(thermalctld, "-15", pid)` — send SIGTERM
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-term pid and status `RUNNING`

**Expected Result**: thermalctld auto-restarts after SIGTERM.

---

#### Test Case #27: test_pmon_thermalctld_kill_and_start_status

**Test Objective**: Verify thermalctld auto-restarts after SIGKILL and remains functional afterwards.

**Test Steps**:
1. Record pre-kill pid
2. `stop_pmon_daemon(thermalctld, "-9", pid)` — send SIGKILL
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-kill pid and status `RUNNING`
4. **Post-restart smoke** — verify thermalctld is functional again:
   - Read `STATE_DB SYSTEM_LEAK_STATUS|system` — assert key/fields remain present after restart
     (timestamp may not advance without a leak-state transition)
   - Read at least one `STATE_DB TEMPERATURE_INFO|<sensor>` row — assert non-empty
     (proves the thermal-polling loop has resumed)

**Expected Result**:
- thermalctld auto-restarts after SIGKILL with a new pid
- After restart, leak-status timestamp advances and TEMPERATURE_INFO continues to be updated

---

### CLI Command Tests

**File**: `tests/platform_tests/cli/test_show_bmc.py`

#### Test Case #28: test_show_version_serial_numbers_bmc

**Test Objective**:
On BMC topology, `show version` on the BMC exposes two serial fields per the SONiC BMC design ([pmon-bmc-design §2.3.2](https://github.com/sonic-net/SONiC/blob/master/doc/bmc/sonicBMC/pmon-bmc-design.md#232-show-commands)):

```
Serial Number: <BMC serial number>
Switch-Host Serial Number: <Switch serial number>
```

Verify both serials match the corresponding inventory `serial:` fields for the BMC host and its paired switch host.

**Test Steps**:
1. `show version` on the BMC; parse `Serial Number:` → `bmc_serial` and `Switch-Host Serial Number:` → `sw_serial`
2. Compare `bmc_serial` to inventory `serial:` for the BMC hostname
3. Compare `sw_serial` to inventory `serial:` for the paired switch hostname (resolved via `duthost.get_bmc_host()`)

**Expected Result**:
- `show version` output contains both `Serial Number:` and `Switch-Host Serial Number:` fields
- When `serial:` is declared in inventory for either host, it matches the corresponding field from `show version`
- Inventory comparison is best-effort: an absent `serial:` is logged but not failed

---

#### Test Case #29: test_show_chassis_module_status

**Test Objective**:
Verify `show chassis module status` returns SWITCH-HOST entry with oper status (LC, AC).

**Test Steps**:
1. Execute `show chassis module status` — verify rc=0, non-empty output
2. Verify SWITCH-HOST entry is present in output
3. Verify oper status column is present (online/offline/status)
4. Verify BMC timing columns `Power-On-Delay (sec)` and `Shutdown-Timeout (sec)` are present

**Expected Result**:
- Command succeeds with rc=0
- SWITCH-HOST entry appears in the table
- Oper status field is populated
- BMC timing columns are present (`Power-On-Delay (sec)`, `Shutdown-Timeout (sec)`)

---

#### Test Case #30: test_show_platform_temperature

**Test Objective**:
Verify `show platform temperature` lists thermal sensors with threshold columns (LC, AC) and, on a BMC, surfaces the paired Switch-Host's sensors as well (so a single CLI on the BMC gives a unified thermal view of both BMC-local and Switch-Host sensors).

**Test Steps**:
1. Execute `show platform temperature` on the BMC — verify rc=0, non-empty output
2. Verify sensor name and temperature value columns present
3. Verify high threshold / critical threshold columns present
4. Resolve paired Switch-Host via `duthost.get_bmc_host()`; run `show platform temperature` on the Switch-Host and collect its sensor names
5. Parse BMC `show platform temperature` sensor names
6. Assert the BMC output includes **at least one** Switch-Host sensor name (presence-only check; values are not compared)

**Expected Result**:
- Command succeeds with rc=0
- Sensor rows are present with temperature readings
- Threshold columns (High TH, Crit High TH) are shown
- BMC's `show platform temperature` includes ≥1 Switch-Host sensor name — confirming the BMC mirrors the paired Switch-Host thermals into its own CLI surface

---

#### Test Case #31: test_config_chassis_modules

**Test Objective**:
Verify `config chassis modules` commands `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout` (LC, AC), and that each shutdown / startup transition is functionally honoured by the paired Switch-Host.

**Test Steps**:
1. `config chassis modules --help` — graceful skip on non-BMC; help text mentions `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout`
2. `startup --help` / `shutdown --help` are individually invokable
3. **Functional shutdown/startup smoke** (disruptive):
   - Snapshot Switch-Host `uptime -s`
   - `config chassis modules shutdown SWITCH-HOST` — wait for SSH drop and `HOST_STATE` `device_status` in `{OFFLINE, POWERED_OFF}`
   - `config chassis modules startup SWITCH-HOST` — wait for `critical_services_fully_started`; assert `uptime -s` advanced and `show reboot-cause` reports a BMC-initiated cause
4. `finally`: restore original `admin_status`

**Expected Result**:
- Help text documents all four commands
- startup/shutdown commands are individually invokable
- After the shutdown/startup pair, the Switch-Host's `uptime -s` advances and `show reboot-cause` reports a BMC-initiated cause

---

#### Test Case #32: test_liquid_cool_config_commands

**Test Objective**:
Verify `config liquid-cool leak-control` and `config liquid-cool leak-action` on liquid-cooled (LC) platforms functionally update `LEAK_CONTROL_POLICY` and the change is reflected in `show platform leak control-policy` — the test asserts behaviour, not just help text.

**Test Steps**:
1. `config liquid-cool --help` — skip on non-LC (non-zero rc)
2. Snapshot current policy via `show platform leak control-policy`
3. For each `(target, severity) ∈ {system, rack_mgr} × {minor, critical}`:
   - Pick a different safe action from `{syslog_only, graceful_shutdown, power_off}`
   - `config liquid-cool leak-action <target> <severity> <new_action>` (rc=0); re-parse policy and assert the field updated
4. For each `target ∈ {system, rack_mgr}`: toggle `leak-control` (rc=0), assert policy updated, restore immediately
5. `finally`: restore every leak-action change recorded in step 3

**Expected Result**:
- On LC systems: every `config liquid-cool …` command returns rc=0 and its effect is visible in `show platform leak control-policy`
- On non-LC systems: the test is skipped via `pytest.skip`
- All original policy values are restored after the test completes

---

#### Test Case #33: test_show_platform_leak_commands

**Test Objective**:
Verify `show platform leak` commands produce valid output on LC platforms.

**Test Steps**:
1. Run `show platform leak rack-manager alerts` — verify `Severity` and `Timestamp` columns
2. Run `show platform leak profiles` — verify `Sensor-Type` and `Max-Minor-Duration-Sec` columns
3. Run `show platform leak status` — verify `Name`, `Leak`, and `leak-severity` columns

**Expected Result**:
- Each `show platform leak` command outputs the expected column headers
- Non-LC platforms return gracefully (non-zero rc tolerated for LC-only commands)

> `show platform leak control-policy` is exercised end-to-end (config write + verify) by `test_liquid_cool_config_commands`, so it is not re-checked here.

---

### BMC Watchdog Tests

There are watchdog tests which are run on BMC platforms.
 - `tests/platform_tests/api/test_watchdog.py` — platform API arm/disarm/remaining-time via `platform_api_conn`; runs on BMC (handles the keepalive timer).
 - `tests/platform_tests/test_hw_watchdog.py` — generic `watchdogutil` CLI/format/remaining-time coverage (runs on BMC too)
 - `tests/platform_tests/daemon/test_bmc_watchdog.py` — BMC-specific: `/host/bmc/watchdog.log` routing and `watchdogutil` arm/disarm round-trip.

Add an explicit watchdog test in test_bmc_watchdog to test bmc specific characteristics,

#### Test Case #34: test_watchdog_bmc_integration

**Test Objective**:
Verify BMC watchdog: `watchdogutil arm`/`disarm` round-trips correctly **and** `/host/bmc/watchdog.log` is the persistent log sink for the Aspeed `watchdog-keepalive.sh` daemon.

**Test Steps**:
1. Assert `/host/bmc/watchdog.log` exists and is non-empty (keepalive daemon lifecycle entries)
2. Assert no `/var/log/watchdog*` files exist — BMC persistent-log convention requires `/host/bmc/`
3. Capture initial `watchdogutil status` state; if `Unarmed`, arm with `watchdogutil arm -s 180` first
4. `watchdogutil disarm` → assert `watchdogutil status` reports `Unarmed` within 15s
5. `watchdogutil arm -s 180` → assert `watchdogutil status` reports `Armed`; if armed, parse `Time remaining` and assert `remaining <= 180` (timeout sanity) and `remaining >= 30` (liveness floor). Warn-log if remaining cannot be parsed or state is not Armed.
6. Restore the pre-test arm state in `finally`

**Expected Result**:
- `/host/bmc/watchdog.log` exists and has at least one keepalive-daemon entry
- No stray `/var/log/watchdog*` files
- `watchdogutil` disarm/arm transitions are visible in `watchdogutil status` within 15s
- Safe on a live BMC: the keepalive script continues kicking `/dev/watchdog0` every 60s independently of `watchdogutil disarm`

---
