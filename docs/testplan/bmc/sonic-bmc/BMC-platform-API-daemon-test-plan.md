# BMC Platform API and Daemon Test Plan

* [Definitions/Abbreviation](#definitionsabbreviation)
* [Overview](#overview)
  * [HLD](#hld)
  * [Testbed](#testbed)
  * [Setup Configuration](#setup-configuration)
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

- **BMC Design Document**: https://github.com/sonic-net/SONiC/blob/master/doc/bmc/sonicBMC/pmon-bmc-design.md

### Testbed

Any SONiC BMC testbed with:
- BMC running SONiC
- Optional liquid cooling system (for leak detection tests)
- Optional SWITCH-HOST module support (for module control tests)

Tests will gracefully skip features not available on the target platform.

### Setup Configuration

#### Common Test Configuration

1. **System Requirements**:
   - BMC must be running SONiC
   - Access to platform APIs via `platform_api_conn` fixture

2. **Skip Conditions**:
   - Leak detection tests skip if system has no liquid cooling support
   - SWITCH-HOST module tests skip if system has no SWITCH-HOST module
   - Bmcctld tests skip if system is not BMC-managed
   - CLI tests for unavailable features gracefully skip

3. **Test Isolation**:
   - Tests do not modify persistent system state
   - All tests are read-only against State DB
   - No configuration changes persist after test completion


## Test Architecture

This section captures the BMC-specific additions on top of the existing sonic-mgmt test framework.

### 1. Inventory and Testbed Wiring

Follows the internal `sonic-mgmt-int` convention: BMC and switch hosts live as plain entries in the regular `sonic` inventory group with a `-bmc` suffix on the BMC host (e.g. `host1-switch` / `host1-switch-bmc`). No dedicated BMC inventory group is introduced. The pair is wired at the testbed layer — the `dut:` list holds the BMC and the existing `bmc_host:` field points at the paired switch — so `duthost` resolves to the BMC and `tbinfo['bmc_host']` to the switch.

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
  inv_name: <inventory-file>
```

### 2. BMC vs Switch Host Discrimination

`is_bmc()` on `SonicHost` returns `self.facts.get('router_type') == 'NetworkBmc'`. Cross-side traversal uses the existing `get_bmc_host()` (switch → BMC) and a new `get_paired_bmc()` (BMC → switch) on `MultiAsicSonicHost`.

### 3. Topology Marker

Tests mark `@pytest.mark.topology('bmc')` to opt into the BMC topology. No new topo file is introduced — the existing `topo_bmc-dual-mgmt.yml` is reused.

### 4. Platform API Connection

Two new helpers under `tests/common/helpers/platform_api/` mirror the upstream classes and call through the existing `platform_api_conn` fixture:

| Helper | Upstream class | Endpoint prefix |
|---|---|---|
| `liquid_cooling.py` | `LiquidCoolingBase` | `/platform/chassis/liquid_cooling/{name}` |
| `leak_sensor.py` | `LeakageSensorBase` / `LeakSensorProfileBase` | `/platform/chassis/liquid_cooling/leak_sensor/{index}/{name}` |

### 5. Liquid Cooling Feature Gate

A module-scoped autouse fixture `skip_if_not_liquid_cooled` probes `Chassis().is_liquid_cooled()` once over SSH and skips the module when `False`. No `pmon_daemon_control.json` fallback — the upstream API is the single source of truth.

### 6. Leak Sensor Enumeration (Two-Gate Pattern)

The per-test setup reads `duthost.facts['chassis']['leak_sensors']` (the `platform.json` list, merged in by `sonic_basic_facts`) and skips if empty. Combined with §5 this gives two independent gates: chassis-level (API says liquid-cooled) and data-level (`platform.json` declares sensors).

### 7. Test Style Conventions

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

#### Test Case #3: test_leak_sensor_reliability

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

**Test Objective**:
Verify LeakageSensorBase handles boundary conditions and invalid inputs gracefully.

**Test Steps**:
1. Skip if no leak sensors detected
2. Access out-of-range sensor index — verify None or handled exception (no crash)
3. Access first and last sensor — verify both return valid strings
4. Read same sensor 10 times — verify all values are identical

**Expected Result**:
- Invalid index does not crash the platform
- Boundary sensors return valid values
- Repeated reads are consistent (no state drift)

---

#### Test Case #4: test_leak_sensor_profile

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

**Test Objective**:
Verify the `LeakSensorProfileBase` methods (`get_type()`, `get_leak_max_minor_duration_sec()`) and `get_all_profiles()` on the liquid cooling device.

**Note on invocation**: The test process never calls these methods as Python objects on the DUT. All calls go through the `platform_api_conn` HTTP proxy (`start_platform_api_service` fixture) that runs inside pmon on the DUT. Profile methods are routed server-side via the URL path `/platform/chassis/liquid_cooling/leak_sensor/{idx}/leak_profile/{name}`, which inside pmon resolves to `chassis.get_liquid_cooling().get_leak_sensor(idx).get_leak_profile().{name}()`. Concretely, the test does NOT invoke `get_leak_profile()` itself — that hop is implicit in the URL — it only invokes the profile's leaf methods (`get_type`, `get_leak_max_minor_duration_sec`).

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


#### Test Case #5: test_switch_host_identity

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify SWITCH-HOST module identity attributes: name, description, serial.

**Test Steps**:
1. Skip if SWITCH-HOST not supported
2. Call `get_name()` — cast to `str()` for Ansible compatibility; verify non-empty, consistent across calls
3. Call `get_description()` — cast to `str()` if not None; verify string or None
4. Call `get_serial()` — cast to `str()` if not None; verify string or None

**Expected Result**:
- Name is a non-empty string (Ansible `AnsibleUnsafeText` normalized via `str()`)
- Description and serial are strings (may be None or empty on some platforms)

---

#### Test Case #6: test_switch_host_status_control

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify SWITCH-HOST admin/oper status attributes and their consistency relationship.

**Test Steps**:
1. Skip if SWITCH-HOST not supported
2. Call `module.get_oper_status()` — verify return is one of the `MODULE_STATUS_*` values:
   `Empty`, `Offline`, `PoweredDown`, `Present`, `Fault`, `Online`
3. Read admin status from CONFIG_DB on the BMC — `CHASSIS_MODULE|SWITCH-HOST admin_status`
   (`ModuleBase` exposes only `set_admin_state(up)`, no getter)
4. Verify admin/oper relationship:
   - `admin_status=up` → oper must be one of `{Present, Online}`
   - `admin_status=down` → oper must be one of `{Offline, PoweredDown, Empty}`
5. Call `module.set_admin_state(up: bool)` passing the current effective state as a no-op —
   verify return is `bool` and no exception
6. **Power-on verification (when transitioning admin down→up via `set_admin_state(True)`)**:
   - Resolve paired switch via `duthost.get_bmc_host()`
   - Wait up to `power_on_delay + graceful_shutdown_timeout` for SSH to come up on the switch
   - Read `uptime -s` and `show reboot-cause` on the switch — assert uptime is recent (< 5 min)
     and reboot cause is one of `{Power Loss, power down request from BMC, graceful shutdown from BMC}`
   - Restore original admin state via `set_admin_state(False)` in `finally`

**Expected Result**:
- `get_oper_status()` returns one of the `MODULE_STATUS_*` strings
- CONFIG_DB `admin_status` matches the effective oper status per the table above
- `set_admin_state(up)` is callable and returns `bool`
- After a real down→up transition the paired switch boots and reports the expected reboot cause

---

#### Test Case #7: test_chassis_is_bmc

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

#### Test Case #8: test_chassis_is_liquid_cooled

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

#### Test Case #9: test_chassis_module_enumeration

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

#### Test Case #10: test_switch_host_serial

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify `get_serial()` for the SWITCH-HOST module (the `get_switch_host_serial` pattern).

**Test Steps**:
1. Call `chassis.get_module_index('SWITCH-HOST')` — skip if not found
2. Call `module.get_serial(idx)` on the SWITCH-HOST module
3. Verify the returned value is a non-empty string

**Expected Result**:
- `chassis.get_module_index('SWITCH-HOST')` returns a valid non-negative index
- `module.get_serial()` returns a non-empty string serial number (e.g., `"SN12345"`)

---

#### Test Case #11: test_switch_host_do_power_cycle

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify the `do_power_cycle()` platform API powers the SWITCH-HOST off and back on, and that the switch genuinely came back up afterwards.

**Test Steps**:
1. Call `get_module_index('SWITCH-HOST')` — skip if not found
2. Resolve paired switch via `duthost.get_bmc_host()`; record pre-cycle `uptime -s`
3. Call `module.do_power_cycle()` via platform API — assert return is `True`
4. Wait up to `graceful_shutdown_timeout + power_on_delay + 180 s` for SSH to come back on the paired switch (`wait_until` polling)
5. Run `uptime -s` on the paired switch — assert post-cycle boot timestamp is newer than pre-cycle
6. Run `show reboot-cause` on the paired switch — assert cause is `power down request from BMC` or `graceful shutdown from BMC`

**Expected Result**:
- `do_power_cycle()` returns `True`
- Paired switch's `uptime -s` advances (newer boot timestamp)
- `show reboot-cause` reports a BMC-initiated cause

---

### CLI Tests

These tests use vendor SONiC CLI commands on the DUT (and, for cross-side cases, on the paired host via `get_bmc_host()` / `get_paired_bmc()`). They complement the Platform API tests by validating that the same data is exposed consistently through CLI and the inventory.

#### Test Case #11a: test_show_version_serial_numbers_bmc

**File**: `tests/platform_tests/cli/test_show_platform.py`

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

### Bmcctld Daemon Tests

**File**: `tests/platform_tests/daemon/test_bmcctld.py`

#### Test Case #12: test_bmcctld_initialization

**Test Objective**:
Verify bmcctld initializes CHASSIS_MODULE_INFO and HOST_STATE tables on startup and
applies the boot delay only on a power-loss reboot.

**Test Steps**:
1. Verify bmcctld process is running
2. Query CHASSIS_MODULE_INFO — verify SWITCH-HOST entry with required fields
3. Query HOST_STATE — verify `device_status` field and `timestamp` present
4. Log tables as empty if not present (non-BMC platforms)
5. Check pmon journal for boot-delay log: `"SWITCH_HOST_POWER_ON_DELAY"` on power-loss
   reboots or `"Skipping SWITCH_HOST_POWER_ON_DELAY"` on warm/fast/soft reboots

**Expected Result**:
- bmcctld is running
- State DB tables initialized with required fields on BMC platforms
- Boot delay is applied only after `REBOOT_CAUSE_POWER_LOSS`; skipped on all other reboot types

**Reviewer note (warm/fast reboot)**: Warm and fast reboot are not supported on the BMC SONiC instance itself. To exercise step 5's "skip boot-delay" branch we trigger a `warm-reboot` / `fast-reboot` on the **paired Switch-Host** (resolved via `duthost.get_paired_bmc()` from a switch test, or the inverse from a BMC test) and then verify the BMC pmon journal contains `"Skipping SWITCH_HOST_POWER_ON_DELAY"` for that reboot — i.e., we test the BMC's *handling* of the Switch-Host's warm/fast reboot cause, not warm/fast reboot of the BMC.

---

#### Test Case #13: test_bmcctld_state_db_consistency

**Test Objective**:
Verify CHASSIS_MODULE_TABLE oper_status reflects HOST_STATE, and admin_status mirrors CONFIG_DB.

**Test Steps**:
1. Query HOST_STATE:device_status and CHASSIS_MODULE_TABLE:SWITCH-HOST:oper_status
2. Verify both show the same effective state
3. Query CONFIG_DB and STATE_DB admin_status — verify they match
4. Read each field 5 times — verify no drift between reads

**Expected Result**:
- oper_status and HOST_STATE are synchronized
- admin_status in STATE_DB matches CONFIG_DB
- State is stable across repeated reads

---

#### Test Case #14: test_bmcctld_event_handling

**Test Objective**:
Verify bmcctld detects critical events and coordinates with thermalctld and psud.

**Test Steps**:
1. Verify bmcctld service is active
2. Check SYSTEM_LEAK_STATUS for any critical events — verify power-on is blocked if present
3. Check thermalctld is running alongside bmcctld
4. Check psud is running and CONFIG_DB integration is present

**Expected Result**:
- bmcctld service active
- Critical events prevent power-on (if present)
- Daemon coordination is in place

**Reviewer note (how to trigger `SYSTEM_LEAK_STATUS`)**: vendor hardware paths to inject a real leak differ per platform (some expose a debug sysfs/i2c knob, some have no in-band trigger at all). For deterministic CI we inject the table directly into STATE_DB on the BMC:

```
sonic-db-cli STATE_DB HSET 'SYSTEM_LEAK_STATUS|system' \
    device_leak_status MINOR timestamp "$(date -Iseconds)"
```

The injected row is deleted in `finally`. Vendor-specific hardware-injection (where supported) is out of scope for this generic test and will be covered as platform-specific add-ons.

---

#### Test Case #15: test_bmcctld_event_log

**Test Objective**:
Verify bmcctld logs critical events to /host/bmc/event.log using structured messages.

**Test Steps**:
1. Check if /host/bmc/event.log exists — skip gracefully if absent
2. Read last 20 log entries
3. Verify log entries have timestamps
4. Verify log entries contain severity levels (CRITICAL, ERROR, WARN, INFO)
5. Verify log entries contain BMC-relevant event types (leak, power, status, module)
6. Check for structured event message formats: `RACK_MGR_CMD FAILED`, `CHASSIS_MODULE admin_down NOOP`,
   `GRACEFUL_SHUTDOWN done`

**Expected Result**:
- Event log is present on BMC systems
- Log entries are timestamped and severity-marked
- Structured log messages follow `EVENT_TYPE: key=... result=...` format
- Empty or absent log is acceptable on new/non-BMC systems

---

#### Test Case #16: test_bmcctld_event_trigger

**Test Objective**:
Verify bmcctld reacts to HSET writes on all four `SubscriberStateTable`-monitored tables
and logs the corresponding event in syslog or /host/bmc/event.log.

**Test Steps**:

Each step injects a value, waits up to 30 s for a log entry, then restores the
original value (or deletes the injected key).

1. **CONFIG_DB `CHASSIS_MODULE|SWITCH-HOST` `admin_status`** — flip the value (up↔down)
   and check syslog for `SWITCH-HOST`.  Restores the original value in `finally`.
2. **STATE_DB `SYSTEM_LEAK_STATUS:system` `device_leak_status`** — inject `MINOR`
   (skip if already `CRITICAL`) and check syslog for `leak`.  Default action is
   `syslog_only`; no power action is dispatched.
3. **STATE_DB `RACK_MANAGER_COMMAND:test_trigger_cmd` `command`** — inject unknown
   value `TEST_TRIGGER` with empty `status`.  Handler logs a warning and marks the
   entry `FAILED`; no power action is dispatched.  Key is deleted in `finally`.
4. **STATE_DB `RACK_MANAGER_ALERT:test_trigger_alert` `severity`** — inject `MINOR`.
   Default `rack_mgr_minor_alert_action` is `syslog_only`; no power action is
   dispatched.  Key is deleted in `finally`.

**Expected Result**:
- On a live BMC system at least one of the four triggers produces a log entry
- No power action is dispatched for any trigger (safe payloads)
- Duplicate HSET with the same value is ignored (dedup added in bmc_enhance)
- All injected keys are cleaned up regardless of test outcome
- Platforms without BMC support log info messages and the assertion is skipped

**Reviewer note (CRITICAL leak → reboot)**: Trigger 2 above only injects `MINOR` (default action `syslog_only`). To exercise the `power_off` action path we add an additional sub-test guarded by `--bmc-allow-disruptive`:
1. Snapshot `uptime -s` on the paired Switch-Host (via `duthost.get_bmc_host()`)
2. Set `LEAK_CONTROL_POLICY system_critical_leak_action = power_off` (default)
3. HSET `SYSTEM_LEAK_STATUS|system device_leak_status = CRITICAL`
4. Wait up to 120 s for the Switch-Host SSH to drop, then for `show reboot-cause` on the Switch-Host to report `power down request from BMC` (or `graceful shutdown from BMC` if `graceful_shutdown_timeout > 0`)
5. Assert post-reboot `uptime -s` is newer than the snapshot
6. Restore `device_leak_status` and policy in `finally`; if Switch-Host did not auto-power-on, issue `config chassis modules startup SWITCH-HOST` to recover the testbed

---

#### Test Case #17: test_bmcctld_reboot_cause_boot_delay

**Test Objective**:
Verify bmcctld applies the startup boot delay only after a full power-loss reboot.

**Test Steps**:
1. Read `/host/reboot-cause/reboot-cause` to determine the last reboot cause
2. Scan pmon journal (last 60 min) for `"SWITCH_HOST_POWER_ON_DELAY"` (power-loss path)
   or `"Skipping SWITCH_HOST_POWER_ON_DELAY"` (warm/fast/soft path)
3. If reboot cause indicates power loss, assert delay log is present
4. If reboot cause is a non-power-loss event, assert skip log is present (or delay absent)

**Expected Result**:
- Boot delay log matches the actual reboot cause
- No delay on warm/fast/soft reboots
- Graceful info-only if no startup log found within 60-min window

---

#### Test Case #18: test_pmon_bmcctld_running_status

**Test Objective**: Verify bmcctld is in RUNNING state with a valid pid at test start.

**Test Steps**:
1. Skip if bmcctld is not enabled (`check_pmon_daemon_enable_status`)
2. Call `get_pmon_daemon_status("bmcctld")` — assert status is `RUNNING` and pid != -1

**Expected Result**: bmcctld is running with a positive pid.

---

#### Test Case #19: test_pmon_bmcctld_stop_and_start_status

**Test Objective**: Verify bmcctld stops cleanly via supervisorctl and recovers after start.

**Test Steps**:
1. Record pre-stop pid
2. `stop_pmon_daemon(bmcctld, None)` — assert status becomes `STOPPED`, pid == -1
3. `start_pmon_daemon(bmcctld)` — wait up to 120 s for new pid > pre-stop pid
4. Assert post-restart status is `RUNNING` and pid incremented

**Expected Result**: bmcctld stops and restarts with a new pid.

---

#### Test Case #20: test_pmon_bmcctld_term_and_start_status

**Test Objective**: Verify bmcctld auto-restarts after SIGTERM (supervisord autorestart).

**Test Steps**:
1. Record pre-term pid
2. `stop_pmon_daemon(bmcctld, "-15", pid)` — send SIGTERM
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-term pid and status `RUNNING`

**Expected Result**: bmcctld auto-restarts after SIGTERM.

---

#### Test Case #21: test_pmon_bmcctld_kill_and_start_status

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

#### Test Case #22: test_leak_state_db_schema

**Test Objective**:
Verify State DB tables written by thermalctld exist with correct schema (graceful skip on non-liquid-cooled platforms).

**Test Steps**:
1. Query SYSTEM_LEAK_STATUS:system — verify `device_leak_status` field exists
2. Query LIQUID_COOLING_INFO:<sensor> — log available fields
3. Query LEAK_PROFILE:<type> — log available configuration fields
4. If tables absent, log and continue (non-liquid-cooled platform)

**Expected Result**:
- On liquid-cooled platforms: all tables present with required fields
- On non-liquid-cooled platforms: graceful skip with log message

---

#### Test Case #23: test_leak_state_db_values

**Test Objective**:
Verify State DB values written by thermalctld are valid and within expected ranges.

**Test Steps**:
1. Query `device_leak_status` — verify value in {MINOR, CRITICAL, None}
2. Query each sensor's `leaking` field — verify value in {Yes, No, N/A}
3. Query each sensor's `leak_sensor_status` field — verify value in {Good, Fault}
4. Query each sensor's `severity` field — verify value in {MINOR, CRITICAL}
5. Query each profile's `max_minor_duration_sec` — verify positive number

**Expected Result**:
- All status values in valid sets per PR #776 schema
- Timeout values are positive numbers
- No null or malformed required fields

---

#### Test Case #24: test_thermalctld_initialization

**Test Objective**:
Verify thermalctld initializes leak monitoring tables on startup, including the startup
seed row for `SYSTEM_LEAK_STATUS|system`. To avoid asserting on a stale row populated long
before this test ran, restart thermalctld first and verify the row is re-seeded fresh.

**Test Steps**:
1. Verify thermalctld process is running in pmon container
2. **Restart thermalctld** (`stop_pmon_daemon` + `start_pmon_daemon`) and wait up to 120 s for new pid
3. Within 60 s of the new pid, query `SYSTEM_LEAK_STATUS:system` — verify row exists with
   `device_leak_status` and `timestamp` fields, and that `timestamp` is **newer than the restart
   moment** (proves the row was just seeded, not pre-existing)
4. Query LEAK_PROFILE keys — log count if present

**Expected Result**:
- thermalctld is running with a new pid after the restart
- `SYSTEM_LEAK_STATUS:system` row is re-seeded with `device_leak_status` in `{None, MINOR, CRITICAL}`
  and a `timestamp` newer than the restart moment
- Graceful info-only on non-liquid-cooled platforms (row may be absent)

---

#### Test Case #25: test_thermalctld_leak_status

**Status**: **Deferred / Not currently supported**

**Reason**: Reliable verification of `SYSTEM_LEAK_STATUS device_leak_status` requires either a real hardware leak (cannot be exercised in the test fleet) or a vendor-specific leak-injection knob (not yet standardised across platforms). Direct STATE_DB injection bypasses thermalctld's own state-machine and would only re-test what TC#16 / TC#26 already cover.

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

#### Test Case #26: test_thermalctld_event_trigger

**Test Objective**:
Inject sensor states into LIQUID_COOLING_INFO and verify STATE_DB presence and syslog entries.

**LIQUID_COOLING_INFO schema** (from `LiquidCoolingUpdater._refresh_leak_status`):
- `leaking` — `Yes | No | N/A`
- `leak_sensor_status` — `Good | Fault`
- `name`, `type`, `location`, `severity`

**Syslog messages thermalctld emits on hardware transitions**:
- `is_leak()=True` → `log_error('...sensor {} reported leaking')`
- `is_leak_sensor_ok()=False` → `log_error('...sensor {} reported faulty')`
- Recovery → `log_notice('...sensor {} recovered from leaking/fault')`

**Test Steps**:
1. **Trigger 1 — leaking sensor** (`leaking=Yes, leak_sensor_status=Good`):
   Inject entry, verify STATE_DB presence, check syslog for `reported leaking`.
   Key deleted in `finally`.
2. **Trigger 2 — faulty sensor** (`leaking=N/A, leak_sensor_status=Fault`):
   Inject entry, verify STATE_DB presence, check syslog for `reported faulty`.
   Key deleted in `finally`.

**Expected Result**:
- At least one trigger produces STATE_DB evidence or syslog entry on a liquid-cooled system
- Both injected keys are cleaned up regardless of outcome

---

#### Test Case #27: test_thermalctld_faulty_sensor

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

#### Test Case #28: test_thermalctld_startup_leak_seed

**Test Objective**:
Verify `SYSTEM_LEAK_STATUS|system` is present immediately after thermalctld starts.

**Test Steps**:
1. Verify `SYSTEM_LEAK_STATUS:system` key exists (`redis-cli EXISTS`)
2. Read `device_leak_status` — must be `'None'`, `'MINOR'`, or `'CRITICAL'`
3. Read `timestamp` — must be a non-empty string

**Expected Result**:
- Row present on startup even with no active leaks (`device_leak_status='None'`)
- `timestamp` is non-empty (written at init time)
- Info-only skip on platforms without liquid cooling

---

#### Test Case #29: test_thermalctld_bmc_temperature_mirror

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
5. Resolve the paired BMC via `duthost.get_paired_bmc()` and verify the mirrored
   `TEMPERATURE_INFO:*` keys appear on the BMC STATE_DB within one polling interval

**Expected Result**:
- After restart, thermalctld logs confirm BMC mirror init or graceful degradation on unreachable BMC
- Local `TEMPERATURE_INFO` is populated and (when BMC is reachable) the mirror is observed on the paired BMC
- Graceful skip on non-Switch-Host platforms

---

#### Test Case #30: test_thermalctld_switch_host_thermal_monitoring

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

#### Test Case #31: test_pmon_thermalctld_running_status

**Test Objective**: Verify thermalctld is in RUNNING state with a valid pid at test start.

**Test Steps**:
1. Skip if thermalctld is not enabled (`check_pmon_daemon_enable_status`)
2. Call `get_pmon_daemon_status("thermalctld")` — assert status is `RUNNING` and pid != -1

**Expected Result**: thermalctld is running with a positive pid.

---

#### Test Case #32: test_pmon_thermalctld_stop_and_start_status

**Test Objective**: Verify thermalctld stops cleanly via supervisorctl and recovers after start.

**Test Steps**:
1. Record pre-stop pid
2. `stop_pmon_daemon(thermalctld, None)` — assert status becomes `STOPPED`, pid == -1
3. `start_pmon_daemon(thermalctld)` — wait up to 120 s for new pid > pre-stop pid
4. Assert post-restart status is `RUNNING` and pid incremented

**Expected Result**: thermalctld stops and restarts with a new pid.

---

#### Test Case #33: test_pmon_thermalctld_term_and_start_status

**Test Objective**: Verify thermalctld auto-restarts after SIGTERM.

**Test Steps**:
1. Record pre-term pid
2. `stop_pmon_daemon(thermalctld, "-15", pid)` — send SIGTERM
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-term pid and status `RUNNING`

**Expected Result**: thermalctld auto-restarts after SIGTERM.

---

#### Test Case #34: test_pmon_thermalctld_kill_and_start_status

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

#### Test Case #35: test_show_chassis_module_status

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

#### Test Case #36: test_show_platform_temperature

**Test Objective**:
Verify `show platform temperature` lists thermal sensors with threshold columns (LC, AC).

**Test Steps**:
1. Execute `show platform temperature` — verify rc=0, non-empty output
2. Verify sensor name and temperature value columns present
3. Verify high threshold / critical threshold columns present

**Expected Result**:
- Command succeeds with rc=0
- Sensor rows are present with temperature readings
- Threshold columns (High TH, Crit High TH) are shown

---

#### Test Case #37: test_config_chassis_modules

**Test Objective**:
Verify `config chassis modules` subcommands `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout` (LC, AC), and that each shutdown / startup transition is functionally honoured by the paired Switch-Host.

**Test Steps**:
1. Execute `config chassis modules --help` — verify help text returned or graceful skip on non-BMC
2. Verify help mentions: `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout`
3. Execute `config chassis modules startup --help` — verify available
4. Execute `config chassis modules shutdown --help` — verify available
5. **Post shutdown/startup functional smoke** (gated by `--bmc-allow-disruptive`; skip otherwise):
   - Resolve paired switch via `duthost.get_bmc_host()`; record pre-action `uptime -s`
   - `config chassis modules shutdown SWITCH-HOST` — wait up to `graceful_shutdown_timeout + 60 s`
     for SSH to drop on the paired switch and `STATE_DB HOST_STATE|switch-host device_status`
     to read `OFFLINE` / `POWERED_OFF`
   - `config chassis modules startup SWITCH-HOST` — wait up to `power_on_delay + 180 s` for
     SSH to come back; verify `uptime -s` is newer than pre-action snapshot and
     `show reboot-cause` reports `power down request from BMC` or `graceful shutdown from BMC`
   - Restore original `admin_status` in `finally`

**Expected Result**:
- Help text documents all four subcommands
- startup/shutdown subcommands are individually invokable
- After the shutdown/startup pair, the Switch-Host's `uptime -s` advances and `show reboot-cause` reports a BMC-initiated cause

---

#### Test Case #38: test_liquid_cool_config_commands

**File**: `tests/platform_tests/cli/test_show_bmc.py`

**Test Objective**:
Verify `config liquid-cool leak-control` and `config liquid-cool leak-action` command syntax on liquid-cooled (LC) platforms.

**Test Steps**:
1. Run `config liquid-cool leak-control --help` — verify help text returned or graceful skip on non-LC
2. Verify help mentions `[system|rack_mgr]` and `[enabled|disabled]` options
3. Run `config liquid-cool leak-action --help` — verify help text returned
4. Verify help mentions action values: `syslog_only`, `graceful_shutdown`, `power_off`

**Expected Result**:
- On LC systems: help output includes correct option keywords
- On non-LC systems: command returns gracefully (non-zero rc tolerated)

---

#### Test Case #39: test_show_platform_leak_commands

**File**: `tests/platform_tests/cli/test_show_bmc.py`

**Test Objective**:
Verify `show chassis module status` and all `show platform leak` sub-commands produce valid output on LC/AC platforms.

**Test Steps**:
1. Run `show chassis module status` — verify SWITCH-HOST entry present (if BMC platform)
2. Run `show platform leak control-policy` — verify `system_leak_policy` and `rack_mgr_leak_policy` fields
3. Run `show platform leak rack-manager alerts` — verify `Severity` and `Timestamp` columns
4. Run `show platform leak profiles` — verify `Sensor-Type` and `Max-Minor-Duration-Sec` columns
5. Run `show platform leak status` — verify `Name`, `Leak`, and `leak-severity` columns

**Expected Result**:
- `show chassis module status` shows SWITCH-HOST with an oper-status field
- Each `show platform leak` sub-command outputs the expected column headers
- Non-LC platforms return gracefully (non-zero rc tolerated for LC-only commands)

---

### BMC Watchdog Tests

**Files**:
- `tests/platform_tests/api/test_watchdog.py` — platform API tests (`topology('any')`); runs on BMC
  and all other topologies. Covers arm/disarm/remaining-time via `platform_api_conn`.
- `tests/platform_tests/daemon/test_bmc_watchdog.py` — BMC-specific integration tests
  (`topology('bmc')`). Covers `watchdogutil` CLI, `/host/bmc` persistent log storage,
  reboot differentiation, and State DB. Uses `duthost.shell()` directly (no platform API server).

These two files are complementary: `test_watchdog.py` validates the platform API contract;
`test_bmc_watchdog.py` validates BMC-specific integration behavior.

#### Test Case #40: test_watchdog_status_and_configuration

**Test Objective**:
Verify watchdog service status, timeout configuration, performance, and error handling.

**Test Steps**:
1. Skip if watchdogutil not available
2. Run `watchdogutil status` — measure latency, verify rc=0, non-empty output with Armed/Unarmed
3. Verify latency < 5 seconds
4. If armed, parse `Time remaining` — verify value between 30s and 180s
5. Issue invalid command — verify service stays responsive

**Expected Result**:
- watchdogutil responds correctly
- Timeout is configured to 180s (armed state)
- Command latency is acceptable
- Service recovers gracefully after invalid input

---

#### Test Case #41: test_watchdog_bmc_integration

**Test Objective**:
Verify watchdog integrates with BMC infrastructure: systemd service, persistent logs, reboot differentiation, State DB.

**Test Steps**:
1. List systemd watchdog services — log if found, check service config
2. Check /host/bmc directory for watchdog logs — warn if found in /var/log instead
3. Check dmesg for watchdog/reboot entries — log if present
4. Query State DB for WATCH* keys — log if present

**Expected Result**:
- Watchdog systemd service exists with correct configuration (60s petting, 180s timeout)
- Logs stored in /host/bmc (not /var/log)
- Reboot reason is accessible
- State DB is consistent with watchdog state

---
