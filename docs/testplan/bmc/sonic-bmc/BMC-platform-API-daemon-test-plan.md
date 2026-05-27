# BMC Platform API and Daemon Test Plan

* [Definitions/Abbreviation](#definitionsabbreviation)
* [Overview](#overview)
  * [HLD](#hld)
  * [Scope](#scope)
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
| API | Application Programming Interface |
| Platform API | Hardware abstraction layer providing access to platform components |
| Daemon | Background service process (bmcctld, thermalctld, etc.) |
| State DB | Redis database storing system state information |
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

These features enable BMC systems to:
- Monitor and detect liquid cooling leaks
- Manage switch-host power states
- Enforce thermal policies with leak detection
- Provide user-friendly CLI access to BMC features

### HLD

- **BMC Design Document**: https://github.com/sonic-net/SONiC/blob/master/doc/bmc/sonicBMC/pmon-bmc-design.md

### Scope

#### In Scope

- LeakageSensorBase platform API validation (identity, state, severity)
- ModuleBase SWITCH-HOST API validation (identity and status control)
- Leak detection State DB schema validation
- Bmcctld daemon initialization and functionality
- Thermalctld leak detection enhancements
- CLI commands for BMC, chassis, leak, and thermal management
- Admin status configuration mirroring
- Critical event handling and power gating
- SWITCH-HOST module admin/oper status synchronization

#### Out of Scope

- Data plane functionality (not applicable to BMC)
- ASIC-specific features (BMC has no ASIC)
- Physical hardware testing (software API validation only)
- Performance testing of daemon response times
- Stress testing with thousands of sensors
- Hardware-specific platform implementations

### Testbed

Any SONiC BMC system or compatible virtual testbed with:
- BMC running SONiC
- Optional liquid cooling system (for leak detection tests)
- Optional SWITCH-HOST module support (for module control tests)

Tests will gracefully skip features not available on the target platform.

### Setup Configuration

#### Common Test Configuration

1. **System Requirements**:
   - BMC must be running SONiC
   - Access to platform APIs via `platform_api_conn` fixture
   - Access to State DB (Redis DB 6)

2. **Skip Conditions**:
   - Leak detection tests skip if system has no liquid cooling support
   - SWITCH-HOST module tests skip if system has no SWITCH-HOST module
   - Bmcctld tests skip if system is not BMC-managed
   - CLI tests for unavailable features gracefully skip

3. **Test Isolation**:
   - Tests do not modify persistent system state
   - All tests are read-only against State DB
   - No configuration changes persist after test completion

#### Common Tests Cleanup

- No persistent state modifications required
- Tests leave system unchanged after execution

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
3. For each sensor, call `get_type()` — verify string or None, non-empty if present
4. For each sensor, call `get_location()` — verify string or None, non-empty if present

**Expected Result**:
- All sensors return valid name, type, and location values
- Values are consistent across repeated calls

---

#### Test Case #2: test_leak_sensor_status_attributes

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

**Test Objective**:
Verify LeakageSensorBase status attributes: is_leak, is_leak_sensor_ok, severity.

**Test Steps**:
1. Skip if no leak sensors detected
2. For each sensor, call `get_is_leak()` — verify boolean, consistent
3. For each sensor, call `get_is_leak_sensor_ok()` — verify boolean, consistent
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
Verify `get_leak_profile()` and `get_leak_max_minor_duration_sec()` on `LeakageSensorBase` and `get_all_profiles()` on the liquid cooling device.

**Test Steps**:
1. Skip if no leak sensors detected
2. For each sensor index: call `get_leak_profile()` — verify non-None profile object
3. For each sensor with a valid profile: call `get_leak_max_minor_duration_sec()` — verify non-negative number
4. Call `get_all_profiles()` — verify returns a list (if supported)

**Expected Result**:
- `get_leak_profile()` returns a non-None profile object for every valid sensor index
- `get_leak_max_minor_duration_sec()` returns a non-negative integer/float (e.g., 300, 600)
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
2. Call `get_admin_status()` — cast to `str()`; verify value in {up, down}, consistent
3. Call `get_oper_status()` — cast to `str()`; verify consistent across calls
4. Verify admin/oper relationship (no fallback — must match exact valid set):
   - admin=up → oper must be one of {PRESENT, ONLINE, PoweredOn}
   - admin=down → oper must be one of {PoweredDown, OFFLINE, POWERED_DOWN}
5. Call `set_admin_status()` with current value — verify accessible without crash

**Expected Result**:
- Admin status is one of the valid values (Ansible string normalized via `str()`)
- Oper status matches the expected set for the current admin state
- set_admin_status is callable

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
Verify `get_serial()` for the SWITCH-HOST module — the `get_switch_host_serial` pattern from design doc section 2.3.2.

**Test Steps**:
1. Call `get_module_index('SWITCH-HOST')` — skip if not found
2. Call `get_module_serial('SWITCH-HOST')` via the chassis platform API helper
3. Verify the returned value is a non-empty string

**Expected Result**:
- `get_module_index('SWITCH-HOST')` returns a valid non-negative index
- `get_module_serial()` returns a non-empty string serial number (e.g., `"SN12345"`)

---

#### Test Case #11: test_switch_host_do_power_cycle

**File**: `tests/platform_tests/api/test_switch_host_module.py`

**Test Objective**:
Verify the `do_power_cycle()` platform API is present and returns a boolean for the SWITCH-HOST module.

**Note**: This test validates the API contract only. It does NOT trigger an actual power cycle to avoid disrupting the DUT.

**Test Steps**:
1. Call `get_module_index('SWITCH-HOST')` — skip if not found
2. Call `module.do_power_cycle()` via platform API
3. Verify the return value is a boolean (`True` or `False`)

**Expected Result**:
- `do_power_cycle()` is callable and returns a boolean
- No exception is raised during the call

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

**Test Objective**: Verify bmcctld auto-restarts after SIGKILL (supervisord autorestart).

**Test Steps**:
1. Record pre-kill pid
2. `stop_pmon_daemon(bmcctld, "-9", pid)` — send SIGKILL
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-kill pid and status `RUNNING`

**Expected Result**: bmcctld auto-restarts after SIGKILL.

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
seed row for `SYSTEM_LEAK_STATUS|system`.

**Test Steps**:
1. Verify thermalctld process is running in pmon container
2. Query `SYSTEM_LEAK_STATUS:system` — verify row exists with `device_leak_status` and `timestamp`
   fields (seeded at startup with `'None'` even before any leak event)
3. Query LEAK_PROFILE keys — log count if present

**Expected Result**:
- thermalctld is running
- `SYSTEM_LEAK_STATUS:system` row is present with `device_leak_status` in `{None, MINOR, CRITICAL}`
  and a non-empty `timestamp` (startup seed ensures the row always exists)
- Graceful info-only on non-liquid-cooled platforms (row may be absent)

---

#### Test Case #25: test_thermalctld_leak_status

**Test Objective**:
Verify thermalctld tracks leak status per sensor, MINOR→CRITICAL escalation config, and
bmcctld integration.

**Test Steps**:
1. Query `SYSTEM_LEAK_STATUS:system device_leak_status` — verify in {MINOR, CRITICAL, None}
2. For each `LIQUID_COOLING_INFO` sensor:
   - `leaking` must be `Yes | No | N/A`
   - `leak_sensor_status` must be `Good | Fault`
   - `severity` must be `MINOR | CRITICAL`
3. Query each `LEAK_PROFILE` entry — verify `max_minor_duration_sec > 0` (escalation threshold)
4. When `device_leak_status = CRITICAL`, assert at least one sensor shows `severity = CRITICAL`
5. Verify CRITICAL leak propagates to `HOST_STATE:switch-host device_status`

**Expected Result**:
- All field values match the schema from `LiquidCoolingUpdater._refresh_leak_status`
- Each profile has a positive escalation threshold (`MINOR` → `CRITICAL` after timeout)
- System `CRITICAL` correlates with at least one `CRITICAL` sensor
- bmcctld coordination is in place

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

**Test Steps**:
1. Skip if not a Switch-Host (`switch_host=1` absent in `/etc/sonic/platform_env.conf`)
2. Scan pmon journal for `"Mirroring TEMPERATURE_INFO to BMC STATE_DB"` or
   `"Failed to open remote BMC TEMPERATURE_INFO table"`
3. Verify local `TEMPERATURE_INFO:*` keys are populated
4. Log BMC connectivity status from journal entries

**Expected Result**:
- Switch-Host logs confirm BMC mirror init or graceful degradation on unreachable BMC
- Local `TEMPERATURE_INFO` is populated (source data for the mirror)
- Graceful skip on non-Switch-Host platforms

---

#### Test Case #30: test_thermalctld_switch_host_thermal_monitoring

**Test Objective**:
Verify thermalctld on the BMC logs CRITICAL threshold breaches in `TEMPERATURE_INFO`
to `/host/bmc/event.log`.

**Test Steps**:
1. Skip if not a BMC (`duthost.is_bmc()` returns False)
2. Check pmon journal for `"Monitoring chassis thermals"` initialization message
3. Inject `TEMPERATURE_INFO:test_critical_thermal_monitor` with `temperature=120.0`,
   `critical_high_threshold=80.0`
4. Wait up to 90 s for event.log entry matching the test sensor (fallback: syslog)
5. Delete injected entry in `finally`

**Expected Result**:
- Init log confirms Switch-Host thermal monitoring is active
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

**Test Objective**: Verify thermalctld auto-restarts after SIGKILL.

**Test Steps**:
1. Record pre-kill pid
2. `stop_pmon_daemon(thermalctld, "-9", pid)` — send SIGKILL
3. Wait up to 120 s for supervisord to restart; assert new pid > pre-kill pid and status `RUNNING`

**Expected Result**: thermalctld auto-restarts after SIGKILL.

---

### CLI Command Tests

**File**: `tests/platform_tests/cli/test_show_bmc.py`

#### Test Case #35: test_show_chassis_module_status

**Test Objective**:
Verify `show chassis module status` (design doc section 2.3.2) returns SWITCH-HOST entry with oper status (LC, AC).

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
Verify `show platform temperature` (design doc section 2.3.2) lists thermal sensors with threshold columns (LC, AC).

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
Verify `config chassis modules` subcommands match design doc section 2.3.1: `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout` (LC, AC).

**Test Steps**:
1. Execute `config chassis modules --help` — verify help text returned or graceful skip on non-BMC
2. Verify help mentions: `startup`, `shutdown`, `power-on-delay`, `shutdown-timeout`
3. Execute `config chassis modules startup --help` — verify available
4. Execute `config chassis modules shutdown --help` — verify available

**Expected Result**:
- Help text documents all four subcommands
- startup/shutdown subcommands are individually invokable

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
