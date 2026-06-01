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
 - `is_bmc()` on `SonicHost` returns `self.facts.get('router_type') == 'NetworkBmc'`
 - `get_bmc_host()` (BMC → switch)

The below API is added newly to get the BMC instance from switch-host

- `get_bmc_from_host()` (switch → BMC)


### 3. Topology Marker

Tests mark `@pytest.mark.topology('bmc')` to opt into the BMC topology. No new topo file is introduced — the existing `topo_bmc-dual-mgmt.yml` is reused.

### 4. Platform API Connection

Two new helpers under `tests/common/helpers/platform_api/` mirror the upstream classes and call through the existing `platform_api_conn` fixture:

| Helper | Upstream class | Endpoint prefix |
|---|---|---|
| `liquid_cooling.py` | `LiquidCoolingBase` | `/platform/chassis/liquid_cooling/{name}` |
| `leak_sensor.py` | `LeakageSensorBase` / `LeakSensorProfileBase` | `/platform/chassis/liquid_cooling/leak_sensor/{index}/{name}` |

### 5. Liquid Cooling Feature Gate

Leak-sensor tests run only on liquid-cooled systems. A module-scoped autouse fixture `skip_if_not_liquid_cooled` probes `Chassis().is_liquid_cooled()` once over SSH and skips the module when `False`. Per-test setup also reads `duthost.facts['chassis']['leak_sensors']` (the `platform.json` list) and skips if empty.

### 6. Test Style Conventions

- One API call per assertion; no duplicate consecutive reads to "confirm consistency."
- Identity attributes compared against `platform.json` values, not hardcoded strings.
- Chassis-level feature gates are module-scoped; per-test state is function-scoped.
- Use `@pytest.mark.topology('bmc')` unless a test is exclusive to one BMC topology.

---

## Test Cases

### Platform API Tests

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`, `tests/platform_tests/api/test_switch_host_module.py`

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
4. For each sensor, call `get_leak_severity()` — verify value in {MINOR, CRITICAL}

**Expected Result**:
- Status fields return correct types
- Severity is one of the valid enum values
- All values are consistent across repeated calls

---

#### Test Case #3: test_leak_sensor_profile

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

**Test Objective**:
Verify the `LeakSensorProfileBase` methods (`get_type()`, `get_leak_max_minor_duration_sec()`) and `get_all_profiles()` on the liquid cooling device.

**Test Steps**:
1. Skip if no leak sensors detected
2. For each sensor index: call `get_leak_max_minor_duration_sec()` over the REST proxy
   (URL: `.../leak_sensor/{idx}/leak_profile/get_leak_max_minor_duration_sec`) — verify
   non-`None` and a non-negative number. A successful response implicitly proves
   `get_leak_profile()` returned a valid profile object on the server side.
3. For each sensor index: call `get_type()` over the REST proxy
   (URL: `.../leak_sensor/{idx}/leak_profile/get_type`) — verify a non-empty string
   (e.g., `'rope'`, `'spot'`, `'flex_pcb'`)
4. Call `get_all_profiles()` on the liquid cooling device (URL: `.../liquid_cooling/get_all_profiles`)
   — verify returns a list (if supported)

**Expected Result**:
- The REST call for `get_leak_max_minor_duration_sec()` returns a non-negative integer/float (e.g., 300, 600)
  for every valid sensor index — implicitly confirming the server-side `get_leak_profile()` hop succeeded
- `get_type()` returns a non-empty profile-type string
- `get_all_profiles()` returns a list of profile objects

---


#### Test Case #4: test_switch_host_identity

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify SWITCH-HOST module identity attributes: name, description, serial, type.

**Test Steps**:
1. Skip if SWITCH-HOST not supported
2. Call `get_name()` — verify non-empty string
3. Call `get_description()` — verify string or None
4. Call `get_serial()` — verify non-empty string (SWITCH-HOST module must report a real serial)
5. Call `get_type()` — verify string or None

**Expected Result**:
- Name and serial are non-empty strings
- Description and type are strings or None (some platforms may not populate them)

---

#### Test Case #5: test_switch_host_status_control

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify SWITCH-HOST admin/oper status attributes and their consistency relationship.

**Test Steps**:
1. Call `module.get_oper_status()` — verify return is one of the `MODULE_STATUS_*` values:
   `Empty`, `Offline`, `PoweredDown`, `Present`, `Fault`, `Online`
2. Read admin status from CONFIG_DB on the BMC — `CHASSIS_MODULE|SWITCH-HOST admin_status`
   (`ModuleBase` exposes only `set_admin_state(up)`, no getter)
3. Verify admin/oper relationship:
   - `admin_status=up` → oper must be one of `{Present, Online}`
   - `admin_status=down` → oper must be one of `{Offline, PoweredDown, Empty}`
4. **Disruptive shutdown/startup cycle** (actually power-cycles the paired Switch-Host):
   - Resolve paired switch via `duthost.get_bmc_host()`; record pre-action `uptime -s`
   - Call `module.set_admin_state(False)` — assert return is `True`; wait for SSH to drop on
     the paired switch and `get_oper_status()` to read one of `{Offline, PoweredDown}`
   - Call `module.set_admin_state(True)` — assert return is `True`
   - Wait for `host.critical_services_fully_started()` (up to `power_on_delay + 300 s`)
   - Verify `uptime -s` is newer than pre-action snapshot and `show reboot-cause` reports
     one of `{Power Loss, power down request from BMC, graceful shutdown from BMC}`
   - Verify `get_oper_status()` now reads one of `{Present, Online}`

**Expected Result**:
- `get_oper_status()` returns one of the `MODULE_STATUS_*` strings
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
1. Reboot the BMC (cold reboot via `reboot()` helper)
2. Verify bmcctld process is running
3. Query CHASSIS_MODULE_INFO — verify SWITCH-HOST entry with required fields
4. Query HOST_STATE — verify `device_status` field and `timestamp` present
5. Log tables as empty if not present (non-BMC platforms)
6. Check pmon journal for `"Skipping SWITCH_HOST_POWER_ON_DELAY"` — must be present
   since a cold reboot is not a power-loss event

**Expected Result**:
- bmcctld is running after reboot
- State DB tables initialized with required fields on BMC platforms
- pmon journal contains `"Skipping SWITCH_HOST_POWER_ON_DELAY"` — boot delay is
  skipped for non-power-loss reboot causes (power-loss path covered by TC#13)

---

#### Test Case #11: test_bmcctld_event_trigger

**Test Objective**:
Verify bmcctld reacts to HSET writes on all four `SubscriberStateTable`-monitored tables, logs the corresponding event, and dispatches the configured power action when severity escalates to `CRITICAL`. Also verifies bmcctld's daemon integrations (`thermalctld` running, `config chassis modules` CLI present) and that the BMC event log file `/host/bmc/event.log` exists with fresh entries after triggers.

**Test Steps**:

Each non-disruptive step injects a value, waits up to 30 s for a log entry, then restores the
original value (or deletes the injected key).

1. **CONFIG_DB `CHASSIS_MODULE|SWITCH-HOST` `admin_status`** — flip the value (up↔down)
   and check syslog for `SWITCH-HOST`.  Restores the original value in `finally`.
2. **MINOR leak (`syslog_only`)** — STATE_DB `SYSTEM_LEAK_STATUS:system` `device_leak_status`
   = `MINOR` (skip if already `CRITICAL`). Default `system_minor_leak_action = syslog_only`.
   - Verify syslog contains a `leak` entry within 30 s
   - Verify **no power action** is dispatched: paired Switch-Host SSH stays up, `uptime -s`
     unchanged, no `power down request from BMC` reboot cause
   - **Routing assertion**: snapshot `/host/bmc/event.log` line count before the trigger;
     after the trigger, assert any new lines appended to `event.log` do NOT contain a
     MINOR leak entry (MINOR severity must be syslog-only; `event.log` is reserved for
     CRITICAL events — TC#24 covers the positive CRITICAL → `event.log` case)
   - Restore `device_leak_status` in `finally`
3. **CRITICAL leak → Switch-Host power off** (disruptive — reboots the paired Switch-Host):
   - Resolve paired Switch-Host via `duthost.get_bmc_host()`; snapshot `uptime -s`
   - Set `LEAK_CONTROL_POLICY system_critical_leak_action = power_off` (default)
   - HSET STATE_DB `SYSTEM_LEAK_STATUS:system device_leak_status = CRITICAL`
   - Wait up to 120 s for Switch-Host SSH to drop
   - Wait for `host.critical_services_fully_started()` (up to `power_on_delay + 300 s`)
   - Assert post-reboot `uptime -s` advanced and `show reboot-cause` on the Switch-Host
     reports `power down request from BMC` or `graceful shutdown from BMC`
   - Restore `device_leak_status` and policy in `finally`; if Switch-Host did not auto-power-on,
     issue `config chassis modules startup SWITCH-HOST` to recover the testbed
4. **STATE_DB `RACK_MANAGER_ALERT:test_trigger_alert` `severity`** — inject `MINOR`.
   Default `rack_mgr_minor_alert_action` is `syslog_only`; no power action is
   dispatched.  Key is deleted in `finally`.
5. **Pre-flight checks** — assert `thermalctld` is RUNNING and `config chassis modules --help` exposes the `admin` subcommand (CONFIG_DB CLI integration).
6. **Post-check `/host/bmc/event.log`** — if the file exists, assert it has fresh entries after the triggers; otherwise log info (platform may emit only to syslog).

> **Note**: `RACK_MANAGER_COMMAND` triggers (both valid commands and the unknown-command negative path) are covered end-to-end in TC#12 `test_bmcctld_rack_manager_command`.

**Expected Result**:
- Each trigger produces the expected log entry
- MINOR leak: syslog only, paired Switch-Host stays up
- CRITICAL leak: paired Switch-Host is powered off and reboots; `show reboot-cause` on the Switch-Host reports a BMC-initiated cause
- Duplicate HSET with the same value is ignored (dedup added in bmc_enhance)
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

For each scenario, resolve the paired Switch-Host via `duthost.get_bmc_host()` and snapshot `uptime -s` before the action. After each transition, restore the testbed via `config chassis modules startup SWITCH-HOST` if needed.

1. **POWER_OFF then POWER_ON** (full off/on cycle):
   - HSET `RACK_MANAGER_COMMAND|test_power_off command=POWER_OFF status=PENDING`
   - Wait ≤180 s for Switch-Host SSH to drop; assert command `status = DONE`
   - HSET `RACK_MANAGER_COMMAND|test_power_on command=POWER_ON status=PENDING`
   - Wait for `host.critical_services_fully_started()` (≤420 s); assert command `status = DONE`
   - Assert post-cycle `uptime -s` advanced
   - Assert `show reboot-cause` on the Switch-Host reports `power down request from BMC` or `graceful shutdown from BMC`
2. **GRACEFUL_SHUT then POWER_ON** (graceful shutdown variant):
   - HSET `RACK_MANAGER_COMMAND|test_graceful_shut command=GRACEFUL_SHUT status=PENDING`
   - Wait ≤`graceful_shutdown_timeout + 60 s` for Switch-Host SSH to drop; assert command `status = DONE`
   - HSET `RACK_MANAGER_COMMAND|test_power_on2 command=POWER_ON status=PENDING`
   - Wait for `host.critical_services_fully_started()`; assert command `status = DONE`
   - Assert `uptime -s` advanced and `show reboot-cause` reports `graceful shutdown from BMC`
3. **POWER_CYCLE** (single-command round trip):
   - HSET `RACK_MANAGER_COMMAND|test_power_cycle command=POWER_CYCLE status=PENDING`
   - Wait for `host.critical_services_fully_started()`; assert command `status = DONE`
   - Assert `uptime -s` advanced and `show reboot-cause` reports a BMC-initiated cause
4. **POWER_ON when CRITICAL leak is present** (negative case):
   - HSET `SYSTEM_LEAK_STATUS|system device_leak_status=CRITICAL`
   - HSET `RACK_MANAGER_COMMAND|test_blocked_power_on command=POWER_ON status=PENDING`
   - Assert command `status = FAILED` and `error/reason` field contains `CRITICAL_LEAK_PRESENT`
   - Restore `device_leak_status` in `finally`
5. **Unknown command rejected** (negative case, non-disruptive):
   - Snapshot Switch-Host `uptime -s`
   - HSET `RACK_MANAGER_COMMAND|test_unknown_cmd command=TEST_UNKNOWN_COMMAND status=PENDING`
   - Wait ≤30 s; assert command `status = FAILED`
   - Assert Switch-Host `uptime -s` unchanged (no power action dispatched)
   - Key is deleted in `finally`

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

**Test Steps**:
1. Snapshot current `power_on_delay` from CONFIG_DB `CHASSIS_MODULE|SWITCH-HOST`
2. Set a short test value (e.g., 30 s) via `config chassis modules power-on-delay SWITCH-HOST 30`
3. Read back `CONFIG_DB CHASSIS_MODULE|SWITCH-HOST power_on_delay` — assert it equals `30`
4. **Scenario A — BMC cold reboot (non-power-loss)**:
   - Call `reboot(duthost, localhost, REBOOT_TYPE_COLD)` on the BMC
   - Wait for BMC `critical_services_fully_started()`
   - Scan the BMC pmon journal since BMC `uptime -s`:
     - Assert `"Skipping SWITCH_HOST_POWER_ON_DELAY"` log is present
     - Assert no `"SWITCH_HOST_POWER_ON_DELAY <N>"` delay-applied log is present
5. **Scenario B — BMC power loss via external PDU**:
   - Resolve the BMC's PDU controller via `get_pdu_controller(duthost)` — skip the scenario if no PDU is wired
   - `pdu_ctrl.turn_off_outlet(outlet)` for each BMC outlet; wait for BMC SSH to drop
   - `pdu_ctrl.turn_on_outlet(outlet)`; wait for BMC `critical_services_fully_started()`
   - Scan the BMC pmon journal since BMC `uptime -s`:
     - Assert `"SWITCH_HOST_POWER_ON_DELAY <N>"` is logged with `<N>` matching the configured `30`
     - Find the subsequent `"Issuing power_on"` (or equivalent dispatch) log line
     - Assert the elapsed time between the two log lines is in `[30 s, 30 + 30 s]`
6. In `finally`: restore the original `power_on_delay` value

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
1. Resolve the paired Switch-Host via `duthost.get_bmc_host()`
2. Snapshot pre-reboot state on both sides:
   - Switch-Host: `uptime -s`, length of `show reboot-cause history`
   - BMC: `uptime -s`, length of `show reboot-cause history`
3. Cold-reboot the BMC (`reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD)`)
4. After BMC SSH returns and `critical_services_fully_started()` passes, snapshot post-reboot state on both sides
5. Assert BMC `uptime -s` advanced and `show reboot-cause history` grew by exactly one entry
6. Assert Switch-Host `uptime -s` is unchanged and `show reboot-cause history` length is unchanged
7. (Optional) Verify Switch-Host `critical_services_fully_started()` is still true throughout

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

**Reason**: Reliable verification of `SYSTEM_LEAK_STATUS device_leak_status` requires either a real hardware leak (cannot be exercised in the test fleet) or a vendor-specific leak-injection knob (not yet standardised across platforms). Direct STATE_DB injection bypasses thermalctld's own state-machine and would only re-test what TC#11 / TC#20 already cover.

This test will be enabled once a generic vendor-agnostic leak-injection mechanism is added to `sonic-platform-common` (tracked separately). Until then the test file contains a `pytest.skip("Not supported until generic leak injection is available")` placeholder so the test ID stays reserved.

**Planned Test Steps (for reference, not executed)**:
1. Query `SYSTEM_LEAK_STATUS:system device_leak_status` — verify in {MINOR, CRITICAL, None}
2. For each `LIQUID_COOLING_INFO` sensor:
   - `leaking` must be `Yes | No | N/A`
   - `leak_sensor_status` must be `Good | Fault`
   - `severity` must be `MINOR | CRITICAL`
3. Query each `LEAK_PROFILE` entry — verify `max_minor_duration_sec > 0`
4. When `device_leak_status = CRITICAL`, assert at least one sensor shows `severity = CRITICAL`
5. Verify CRITICAL leak propagates to `HOST_STATE:switch-host device_status`

---

#### Test Case #20: test_thermalctld_event_trigger

**Test Objective**:
Inject a leaking sensor state into LIQUID_COOLING_INFO and verify STATE_DB presence and the associated syslog entry. The faulty-sensor path is covered separately by TC#22 `test_thermalctld_faulty_sensor`.

**LIQUID_COOLING_INFO schema** (from `LiquidCoolingUpdater._refresh_leak_status`):
- `leaking` — `Yes | No | N/A`
- `leak_sensor_status` — `Good | Fault`
- `name`, `type`, `location`, `severity`

**Syslog message thermalctld emits on hardware transition**:
- `is_leak()=True` → `log_error('...sensor {} reported leaking')`
- Recovery → `log_notice('...sensor {} recovered from leaking')`

**Test Steps**:
1. **Trigger — leaking sensor** (`leaking=Yes, leak_sensor_status=Good`):
   Inject entry, verify STATE_DB presence, check syslog for `reported leaking`.
   Key deleted in `finally`.

**Expected Result**:
- The trigger produces STATE_DB evidence or a syslog entry on a liquid-cooled system
- The injected key is cleaned up regardless of outcome

---

#### Test Case #21: test_thermalctld_leak_escalation

**File**: `tests/platform_tests/daemon/test_thermalctld.py`

**Test Objective**:
Verify the MINOR→CRITICAL leak escalation configuration is in place and that, when the system reports a CRITICAL leak, the responsible sensor is also CRITICAL — i.e. escalation is profile-driven, not a side-effect of an unrelated daemon path.

**Background** (bmc_enhance):
`LiquidCoolingUpdater` queries `profile.get_leak_max_minor_duration_sec()` for each leaking sensor. Once a sensor has been MINOR for longer than the configured threshold, the daemon escalates it to CRITICAL, which propagates into `SYSTEM_LEAK_STATUS:system device_leak_status`. The escalation threshold is stored per profile in `LEAK_PROFILE`.

**Test Steps**:
1. List all `LEAK_PROFILE:*` keys (skip if none — non-liquid-cooled platform)
2. For **every** profile, assert `max_minor_duration_sec > 0`
3. List sensors from `LIQUID_COOLING_INFO:*`; for each sensor:
   - Assert `severity ∈ {MINOR, CRITICAL}`
   - For any CRITICAL sensor, look up its `profile` field, resolve the corresponding `LEAK_PROFILE` entry, and assert that profile's `max_minor_duration_sec > 0` (cross-reference: a CRITICAL sensor must trace back to a profile with a valid escalation threshold)
4. Read `SYSTEM_LEAK_STATUS:system device_leak_status`; when it equals `CRITICAL`, assert at least one sensor in `LIQUID_COOLING_INFO` has `severity = CRITICAL` (system status must be backed by a sensor)

**Expected Result**:
- Every `LEAK_PROFILE` has `max_minor_duration_sec > 0`
- All sensor severities are valid
- Every CRITICAL sensor maps to a profile with a valid escalation threshold
- `SYSTEM_LEAK_STATUS = CRITICAL` correlates with at least one CRITICAL sensor

**Note**: The CRITICAL cross-correlation branches only execute when a CRITICAL leak is currently active on the testbed (rare in normal CI). The profile-threshold checks always run on liquid-cooled platforms.

---

#### Test Case #22: test_thermalctld_leak_severity_aggregation

**File**: `tests/platform_tests/daemon/test_thermalctld.py`

**Test Objective**:
Verify thermalctld's individual-sensor → `SYSTEM_LEAK_STATUS` aggregation rules from `pmon-bmc-design.md` §2.1.5 by actively injecting sensor combinations into `LIQUID_COOLING_INFO` and asserting that `SYSTEM_LEAK_STATUS:system device_leak_status` converges to the expected aggregated value.

**Aggregation truth table** (the design contract under test):

| # | Individual Leak Sensors                              | System Leak (expected output) |
|---|------------------------------------------------------|-------------------------------|
| 1 | 1 CRITICAL sensor                                    | `CRITICAL`                    |
| 2 | 2+ sensors of any severity                           | `CRITICAL`                    |
| 3 | 1 MINOR sensor staying for > `max_minor_duration_sec`| `CRITICAL` (escalation)       |
| 4 | 1 MINOR sensor (< escalation threshold)              | `MINOR`                       |

**Test Steps**:
1. Pre-flight: skip if `SYSTEM_LEAK_STATUS:system device_leak_status` is already `CRITICAL` (cannot run safely)
2. For each scenario, inject the corresponding test sensor row(s) into `LIQUID_COOLING_INFO` (key prefix `test_agg_sensor_*`) with the daemon's wire schema (`name`, `leaking=Yes`, `leak_sensor_status=Good`, `severity=<MINOR|CRITICAL>`)
3. Wait up to ~2 poll cycles (40 s, polled every 5 s) for `device_leak_status` to converge to the expected value
4. Confirm the injected rows survived the daemon's next poll (skip assertion if rows were evicted — the daemon may overwrite test entries from real hardware on its next cycle)
5. Assert `device_leak_status == <expected>` and clean up injected rows; wait for the system to settle back before the next scenario
6. Rule 3 (escalation) only: temporarily HSET `LEAK_PROFILE:<first_profile> max_minor_duration_sec = 5`, inject 1 MINOR sensor, wait up to 40 s for escalation to CRITICAL, restore the original threshold in `finally`
7. Restore all injected rows and the original `device_leak_status` in `finally`

**Expected Result**:
- Rule 1: 1 CRITICAL sensor → `SYSTEM_LEAK_STATUS = CRITICAL`
- Rule 2: 2 MINOR sensors → `SYSTEM_LEAK_STATUS = CRITICAL`
- Rule 3: 1 MINOR sensor + shortened threshold → `SYSTEM_LEAK_STATUS = CRITICAL` (escalation)
- Rule 4: 1 MINOR sensor (default threshold) → `SYSTEM_LEAK_STATUS = MINOR`
- All test sensor rows are deleted and the original `device_leak_status` is restored
- Scenarios where the daemon evicted the injected rows on its next poll log info and skip the assertion (rather than asserting a false negative)

---

#### Test Case #23: test_thermalctld_faulty_sensor

**Test Objective**:
Verify thermalctld correctly represents a faulty/unreadable sensor in STATE_DB and
confirm the associated syslog format.

**Test Steps**:
1. Inject `LIQUID_COOLING_INFO:test_faulty_sensor_check` with `leaking=N/A`,
   `leak_sensor_status=Fault`, `severity=CRITICAL`, `type=liquid`, `location=rack`
2. Verify `leaking=N/A` is present in STATE_DB within 15 s
3. Verify `leak_sensor_status=Fault` is present in STATE_DB within 10 s
4. Check syslog (last 30 min) for real `reported faulty` events from hardware —
   verify log format contains `leakage sensor` or `liquid`
5. Verify `SYSTEM_LEAK_STATUS:system timestamp` is present (thermalctld updates
   system table even when sensors are faulty)

**Expected Result**:
- `leaking=N/A` and `leak_sensor_status=Fault` confirmed in STATE_DB
- Real `reported faulty` syslog entries (if present) match expected format
- `SYSTEM_LEAK_STATUS:system` timestamp present on liquid-cooled platforms
- Injected key deleted in `finally` block

---

#### Test Case #24: test_thermalctld_bmc_temperature_mirror

**Test Objective**:
Verify thermalctld on the Switch-Host mirrors `TEMPERATURE_INFO` to the BMC's STATE_DB.
To avoid asserting on stale journal/STATE_DB content, the test restarts thermalctld first
and observes the next mirror cycle.

**Test Steps**:
1. Skip if not a Switch-Host (`switch_host=1` absent in `/etc/sonic/platform_env.conf`)
2. **Restart thermalctld** on the Switch-Host (`stop_pmon_daemon` + `start_pmon_daemon`); wait up to 120 s for new pid
3. After the restart, scan pmon journal **since the new pid** for `"Mirroring TEMPERATURE_INFO to BMC STATE_DB"` or
   `"Failed to open remote BMC TEMPERATURE_INFO table"`
4. Verify local `TEMPERATURE_INFO:*` keys are populated post-restart
5. Resolve the paired BMC via `duthost.get_bmc_from_host()` and verify the mirrored
   `TEMPERATURE_INFO:*` keys appear on the BMC STATE_DB within one polling interval

**Expected Result**:
- After restart, thermalctld logs confirm BMC mirror init or graceful degradation on unreachable BMC
- Local `TEMPERATURE_INFO` is populated and (when BMC is reachable) the mirror is observed on the paired BMC
- Graceful skip on non-Switch-Host platforms

---

#### Test Case #25: test_thermalctld_switch_host_thermal_monitoring

**Test Objective**:
Verify thermalctld on the BMC logs CRITICAL threshold breaches in `TEMPERATURE_INFO`
to `/host/bmc/event.log`. To avoid asserting on a stale init log, the test restarts
thermalctld first and observes the next initialization + injection cycle.

**Test Steps**:
1. Skip if not a BMC (`duthost.is_bmc()` returns False)
2. **Restart thermalctld** on the BMC (`stop_pmon_daemon` + `start_pmon_daemon`); wait up to 120 s for new pid
3. After the restart, check pmon journal **since the new pid** for `"Monitoring chassis thermals"` initialization message
4. Inject `TEMPERATURE_INFO:test_critical_thermal_monitor` with `temperature=120.0`,
   `critical_high_threshold=80.0`
5. Wait up to 90 s for event.log entry matching the test sensor (fallback: syslog)
6. Delete injected entry in `finally`

**Expected Result**:
- Post-restart init log confirms Switch-Host thermal monitoring is active
- CRITICAL breach logs `"CRITICAL chassis thermal: <name> temperature <T>C >= critical_high_threshold <T>C"` within 90 s
- Injected key is cleaned up regardless of outcome

---

#### Test Case #26: test_pmon_thermalctld_running_status

**Test Objective**: Verify thermalctld is in RUNNING state with a valid pid at test start.

**Test Steps**:
1. Skip if thermalctld is not enabled (`check_pmon_daemon_enable_status`)
2. Call `get_pmon_daemon_status("thermalctld")` — assert status is `RUNNING` and pid != -1

**Expected Result**: thermalctld is running with a positive pid.

---

#### Test Case #27: test_pmon_thermalctld_stop_and_start_status

**Test Objective**: Verify thermalctld stops cleanly via supervisorctl and recovers after start.

**Test Steps**:
1. Record pre-stop pid
2. `stop_pmon_daemon(thermalctld, None)` — assert status becomes `STOPPED`, pid == -1
3. `start_pmon_daemon(thermalctld)` — wait up to 120 s for new pid > pre-stop pid
4. Assert post-restart status is `RUNNING` and pid incremented

**Expected Result**: thermalctld stops and restarts with a new pid.

---

#### Test Case #28: test_pmon_thermalctld_term_and_start_status

**Test Objective**: Verify thermalctld auto-restarts after SIGTERM.

**Test Steps**:
1. Record pre-term pid
2. `stop_pmon_daemon(thermalctld, "-15", pid)` — send SIGTERM
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-term pid and status `RUNNING`

**Expected Result**: thermalctld auto-restarts after SIGTERM.

---

#### Test Case #29: test_pmon_thermalctld_kill_and_start_status

**Test Objective**: Verify thermalctld auto-restarts after SIGKILL and remains functional afterwards.

**Test Steps**:
1. Record pre-kill pid
2. `stop_pmon_daemon(thermalctld, "-9", pid)` — send SIGKILL
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-kill pid and status `RUNNING`
4. **Post-restart smoke** — verify thermalctld is functional again:
   - Read `STATE_DB SYSTEM_LEAK_STATUS|system timestamp` — assert it advances within one
     polling interval after the new pid (proves the leak-status loop has resumed)
   - Read at least one `STATE_DB TEMPERATURE_INFO|<sensor>` row — assert non-empty
     (proves the thermal-polling loop has resumed)

**Expected Result**:
- thermalctld auto-restarts after SIGKILL with a new pid
- After restart, leak-status timestamp advances and TEMPERATURE_INFO continues to be updated

---

### CLI Command Tests

**File**: `tests/platform_tests/cli/test_show_bmc.py`

#### Test Case #30: test_show_version_serial_numbers_bmc

**Test Objective**:
On BMC topology, `show version` on the BMC exposes two serial fields per the SONiC BMC design ([pmon-bmc-design §2.3.2](https://github.com/sonic-net/SONiC/blob/master/doc/bmc/sonicBMC/pmon-bmc-design.md#232-show-commands)):

```
Serial Number: <BMC serial number>
Switch-Host Serial Number: <Switch serial number>
```

Verify both serials match the corresponding inventory `serial:` fields for the BMC host and its paired switch host.

**Test Steps**:
1. Run `show version` on the BMC (`duthost`)
2. Parse the `Serial Number:` line → `bmc_serial`
3. Parse the `Switch-Host Serial Number:` line → `sw_serial`
4. Compare `bmc_serial` to inventory `serial:` for the BMC hostname
5. Resolve the paired switch via `duthost.get_bmc_host()`
6. Compare `sw_serial` to inventory `serial:` for the paired switch hostname

**Expected Result**:
- `show version` output contains both `Serial Number:` and `Switch-Host Serial Number:` fields
- When `serial:` is declared in inventory for either host, it matches the corresponding field from `show version`
- Inventory comparison is best-effort: an absent `serial:` is logged but not failed

---

#### Test Case #31: test_show_chassis_module_status

**Test Objective**:
Verify `show chassis module status` returns SWITCH-HOST entry with oper status (LC, AC).

**Test Steps**:
1. Execute `show chassis module status` — verify rc=0, non-empty output
2. Verify SWITCH-HOST entry is present in output
3. Verify oper status column is present (online/offline/status)

**Expected Result**:
- Command succeeds with rc=0
- SWITCH-HOST entry appears in the table
- Oper status field is populated

---

#### Test Case #32: test_show_platform_temperature

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

#### Test Case #33: test_config_chassis_modules

**Test Objective**:
Verify `config chassis modules` subcommands `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout` (LC, AC), and that each shutdown / startup transition is functionally honoured by the paired Switch-Host.

**Test Steps**:
1. Execute `config chassis modules --help` — verify help text returned or graceful skip on non-BMC
2. Verify help mentions: `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout`
3. Execute `config chassis modules startup --help` — verify available
4. Execute `config chassis modules shutdown --help` — verify available
5. **Post shutdown/startup functional smoke** (disruptive — actually reboots the paired Switch-Host):
   - Resolve paired switch via `duthost.get_bmc_host()`; record pre-action `uptime -s`
   - `config chassis modules shutdown SWITCH-HOST` — wait up to `graceful_shutdown_timeout + 60 s`
     for SSH to drop on the paired switch and `STATE_DB HOST_STATE|switch-host device_status`
     to read `OFFLINE` / `POWERED_OFF`
   - `config chassis modules startup SWITCH-HOST` — wait for `host.critical_services_fully_started()`
     (up to `power_on_delay + 300 s`); verify `uptime -s` is newer than pre-action snapshot and
     `show reboot-cause` reports `power down request from BMC` or `graceful shutdown from BMC`
   - Restore original `admin_status` in `finally`

**Expected Result**:
- Help text documents all four subcommands
- startup/shutdown subcommands are individually invokable
- After the shutdown/startup pair, the Switch-Host's `uptime -s` advances and `show reboot-cause` reports a BMC-initiated cause

---

#### Test Case #34: test_liquid_cool_config_commands

**File**: `tests/platform_tests/cli/test_show_bmc.py`

**Test Objective**:
Verify `config liquid-cool leak-control` and `config liquid-cool leak-action` on liquid-cooled (LC) platforms functionally update `LEAK_CONTROL_POLICY` and the change is reflected in `show platform leak control-policy` — the test asserts behaviour, not just help text.

**Test Steps**:
1. Pre-flight: run `config liquid-cool --help`; skip the test on non-LC platforms (non-zero rc)
2. Snapshot the current policy by parsing `show platform leak control-policy`
3. For each `(target, severity)` in `{system, rack_mgr} × {minor, critical}`:
   - Determine current `<target>_<severity>_leak_action` from the snapshot
   - Pick a different safe action from `{syslog_only, graceful_shutdown, power_off}`
   - Run `config liquid-cool leak-action <target> <severity> <new_action>` (assert rc=0)
   - Re-parse `show platform leak control-policy` and assert the field now equals `<new_action>`
4. For each `target ∈ {system, rack_mgr}`:
   - Determine current `<target>_leak_control` state from the snapshot
   - Issue `config liquid-cool leak-control <target> <toggled>` (assert rc=0)
   - Re-parse `show platform leak control-policy` and assert the state value changed
   - Restore the original state immediately
5. In `finally`, restore every leak-action change recorded in step 3 to its original value

**Expected Result**:
- On LC systems: every `config liquid-cool …` command returns rc=0 and its effect is visible in `show platform leak control-policy`
- On non-LC systems: the test is skipped via `pytest.skip`
- All original policy values are restored after the test completes

---

#### Test Case #35: test_show_platform_leak_commands

**File**: `tests/platform_tests/cli/test_show_bmc.py`

**Test Objective**:
Verify all `show platform leak` sub-commands produce valid output on LC platforms.

**Test Steps**:
1. Run `show platform leak control-policy` — verify `system_leak_policy` and `rack_mgr_leak_policy` fields
2. Run `show platform leak rack-manager alerts` — verify `Severity` and `Timestamp` columns
3. Run `show platform leak profiles` — verify `Sensor-Type` and `Max-Minor-Duration-Sec` columns
4. Run `show platform leak status` — verify `Name`, `Leak`, and `leak-severity` columns

**Expected Result**:
- Each `show platform leak` sub-command outputs the expected column headers
- Non-LC platforms return gracefully (non-zero rc tolerated for LC-only commands)

---

### BMC Watchdog Tests

There are watchdog tests which are run on BMC platforms. Add an explicit watchdog tests in test_bmc_watchdog to test bmc specific characteristics
- `tests/platform_tests/api/test_watchdog.py` — platform API arm/disarm/remaining-time via `platform_api_conn`; runs on BMC (handles the keepalive timer).
- `tests/platform_tests/test_hw_watchdog.py` — generic `watchdogutil` CLI/format/remaining-time coverage (runs on BMC too)
- `tests/platform_tests/daemon/test_bmc_watchdog.py` — BMC-specific: `/host/bmc/watchdog.log` routing and `watchdogutil` arm/disarm round-trip.

#### Test Case #36: test_watchdog_bmc_integration

**Test Objective**:
Verify BMC watchdog: `watchdogutil arm`/`disarm` round-trips correctly **and** `/host/bmc/watchdog.log` is the persistent log sink for the Aspeed `watchdog-keepalive.sh` daemon (sonic-buildimage commit `bc13e6afa`, `platform/aspeed/aspeed-platform-services/scripts/watchdog-keepalive.sh`).

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
