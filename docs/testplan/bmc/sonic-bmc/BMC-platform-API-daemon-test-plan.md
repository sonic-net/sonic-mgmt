# BMC Platform API and Daemon Test Plan

* [Definitions/Abbreviation](#definitionsabbreviation)
* [Overview](#overview)
  * [HLD](#hld)
  * [Scope](#scope)
  * [Testbed](#testbed)
  * [Setup Configuration](#setup-configuration)
* [Test Cases](#test-cases)
  * [Leak Detection Platform API Tests](#leak-detection-platform-api-tests)
  * [SWITCH-HOST Module Control API Tests](#switch-host-module-control-api-tests)
  * [Leak Detection State DB Tests](#leak-detection-state-db-tests)
  * [Bmcctld Daemon Integration Tests](#bmcctld-daemon-integration-tests)
  * [Thermalctld Daemon Tests](#thermalctld-daemon-tests)
  * [CLI Command Tests](#cli-command-tests)
  * [BMC Watchdog Tests](#bmc-watchdog-tests)
* [Open Questions](#open-questions)

---

## Definitions/Abbreviation

| **Term** | **Description** |
|----------|-----------------|
| BMC | Baseboard Management Controller |
| API | Application Programming Interface |
| Platform API | Hardware abstraction layer providing access to platform components |
| Daemon | Background service process (bmcctld, thermalctld, etc.) |
| State DB | Redis database storing system state information |
| SWITCH-HOST | Module representing the main switch CPU in a BMC-managed system |
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

### Leak Detection Platform API Tests

**File**: `tests/platform_tests/api/test_thermal_leak_sensor.py`

#### Test Case #1: test_leak_sensor_identity_attributes

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

### SWITCH-HOST Module Control API Tests

**File**: `tests/platform_tests/api/test_switch_host_module.py`

#### Test Case #4: test_switch_host_identity

**Test Objective**:
Verify SWITCH-HOST module identity attributes: name, description, serial.

**Test Steps**:
1. Skip if SWITCH-HOST not supported
2. Call `get_name()` — verify non-empty string, consistent across calls
3. Call `get_description()` — verify string or None
4. Call `get_serial()` — verify string or None

**Expected Result**:
- Name is a non-empty string
- Description and serial are strings (may be None or empty on some platforms)

---

#### Test Case #5: test_switch_host_status_control

**Test Objective**:
Verify SWITCH-HOST admin/oper status attributes and their consistency relationship.

**Test Steps**:
1. Skip if SWITCH-HOST not supported
2. Call `get_admin_status()` — verify value in {up, down}, consistent
3. Call `get_oper_status()` — verify valid string, consistent
4. Verify admin/oper relationship:
   - admin=up → oper in {PRESENT, ONLINE, PoweredOn}
   - admin=down → oper in {PoweredDown, OFFLINE, POWERED_DOWN}
5. Call `set_admin_status()` with current value — verify accessible without crash

**Expected Result**:
- Admin status is one of the valid values
- Oper status is consistent with admin status
- set_admin_status is callable

---

### Leak Detection State DB Tests

**File**: `tests/platform_tests/daemon/test_thermalctld.py`

These State DB tests are consolidated into the Thermalctld daemon test file since thermalctld is responsible for writing leak detection data to STATE_DB.

#### Test Case #6: test_leak_state_db_schema

**Test Objective**:
Verify State DB tables exist with correct schema (graceful skip on non-liquid-cooled platforms).

**Test Steps**:
1. Query SYSTEM_LEAK_STATUS:system — verify `device_leak_status` field exists
2. Query LIQUID_COOLING_INFO:<sensor> — log available fields
3. Query LEAK_PROFILE:<type> — log available configuration fields
4. If tables absent, log and continue (non-liquid-cooled platform)

**Expected Result**:
- On liquid-cooled platforms: all tables present with required fields
- On non-liquid-cooled platforms: graceful skip with log message

---

#### Test Case #7: test_leak_state_db_values

**Test Objective**:
Verify State DB values are valid and within expected ranges.

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

### Bmcctld Daemon Integration Tests

**File**: `tests/platform_tests/daemon/test_bmcctld.py`

#### Test Case #8: test_bmcctld_initialization

**Test Objective**:
Verify bmcctld initializes CHASSIS_MODULE_INFO and HOST_STATE tables on startup.

**Test Steps**:
1. Verify bmcctld process is running
2. Query CHASSIS_MODULE_INFO — verify SWITCH-HOST entry with required fields
3. Query HOST_STATE — verify `device_status` field and `timestamp` present
4. Log tables as empty if not present (non-BMC platforms)

**Expected Result**:
- bmcctld is running
- State DB tables initialized with required fields on BMC platforms

---

#### Test Case #9: test_bmcctld_state_db_consistency

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

#### Test Case #10: test_bmcctld_event_handling

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

#### Test Case #11: test_bmcctld_performance

**Test Objective**:
Verify bmcctld State DB queries respond with acceptable latency.

**Test Steps**:
1. Measure latency of HOST_STATE query (target < 1s)
2. Measure latency of CHASSIS_MODULE_INFO query (target < 1s)
3. Read each field 5 times and verify values are stable

**Expected Result**:
- All queries complete within 1 second
- Values stable across repeated reads

---

#### Test Case #12: test_bmcctld_event_log

**Test Objective**:
Verify bmcctld logs critical events to /host/bmc/event.log.

**Test Steps**:
1. Check if /host/bmc/event.log exists — skip gracefully if absent
2. Read last 20 log entries
3. Verify log entries have timestamps
4. Verify log entries contain severity levels (CRITICAL, ERROR, WARN, INFO)
5. Verify log entries contain BMC-relevant event types (leak, power, status, module)

**Expected Result**:
- Event log is present on BMC systems
- Log entries are timestamped and severity-marked
- Empty or absent log is acceptable on new/non-BMC systems

---

#### Test Case #13: test_bmcctld_event_trigger

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
- All injected keys are cleaned up regardless of test outcome
- Platforms without BMC support log info messages and the assertion is skipped

---

### Thermalctld Daemon Tests

**File**: `tests/platform_tests/daemon/test_thermalctld.py`

#### Test Case #14: test_thermalctld_initialization

**Test Objective**:
Verify thermalctld initializes leak monitoring tables on startup.

**Test Steps**:
1. Verify thermalctld process is running in pmon container
2. Query SYSTEM_LEAK_STATUS:system — log if absent (non-liquid-cooled)
3. Query LEAK_PROFILE keys — log count if present

**Expected Result**:
- thermalctld is running
- Leak tables initialized on liquid-cooled platforms
- Graceful skip on non-liquid-cooled platforms

---

#### Test Case #15: test_thermalctld_leak_status

**Test Objective**:
Verify thermalctld tracks leak status per sensor and integrates with bmcctld.

**Test Steps**:
1. Query `SYSTEM_LEAK_STATUS:system device_leak_status` — verify in {MINOR, CRITICAL, None}
2. For each `LIQUID_COOLING_INFO` sensor:
   - `leaking` must be `Yes | No | N/A`
   - `leak_sensor_status` must be `Good | Fault`
   - `severity` must be `MINOR | CRITICAL`
3. Query LEAK_PROFILE `max_minor_duration_sec` — verify positive number
4. Verify CRITICAL leak propagates to `HOST_STATE:switch-host device_status`

**Expected Result**:
- All field values match the schema from LiquidCoolingUpdater._refresh_leak_status
- Severity escalation threshold is configured
- bmcctld coordination is in place

---

#### Test Case #16: test_thermalctld_performance

**Test Objective**:
Verify thermalctld State DB queries respond within acceptable latency.

**Test Steps**:
1. Measure latency of SYSTEM_LEAK_STATUS query (target < 1s)
2. Read status 5 times — verify persistence and stability

**Expected Result**:
- Queries complete within 1 second
- Status persists and is stable across reads

---

#### Test Case #17: test_thermalctld_event_trigger

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

#### Test Case #18: test_thermalctld_faulty_sensor

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

### CLI Command Tests

**File**: `tests/platform_tests/cli/test_show_bmc.py`

#### Test Case #19: test_show_bmc_commands

**Test Objective**:
Verify `show bmc` commands exist and return valid output.

**Test Steps**:
1. Execute `show bmc` — verify rc=0, non-empty output
2. Execute `show bmc status` — verify output contains status fields
3. Skip gracefully on non-BMC systems

**Expected Result**:
- Commands execute successfully
- Output contains BMC status information

---

#### Test Case #20: test_show_leak_commands

**Test Objective**:
Verify leak detection CLI commands exist and return valid output.

**Test Steps**:
1. Execute `show leak-status` — skip gracefully if absent
2. Verify output contains sensor names and status fields
3. Execute `show leak-status --verbose` if supported

**Expected Result**:
- Command exists on liquid-cooled platforms
- Graceful skip on non-liquid-cooled systems

---

#### Test Case #21: test_show_command_output_format

**Test Objective**:
Verify `show chassis module` output format includes SWITCH-HOST with status fields.

**Test Steps**:
1. Execute `show chassis module` — verify rc=0, non-empty output
2. Parse output for SWITCH-HOST entry
3. Verify admin_status and oper_status fields are present
4. Execute `show thermal` — verify temperature sensors are listed

**Expected Result**:
- SWITCH-HOST appears in chassis module listing
- Status fields are populated
- Thermal output includes sensor information

---

#### Test Case #22: test_config_chassis_commands

**Test Objective**:
Verify `config chassis module` command exists with correct syntax.

**Test Steps**:
1. Execute `config chassis module --help` — verify help text returned
2. Verify help includes admin-status subcommand
3. Skip gracefully on non-BMC platforms

**Expected Result**:
- Help text is returned
- Command syntax is documented

---

#### Test Case #23: test_backward_compatibility

**Test Objective**:
Verify existing CLI commands still work after BMC enhancements.

**Test Steps**:
1. Execute `show chassis modules` (plural) — verify still works
2. Execute `show platform summary` — verify non-empty output
3. Execute `show version` — verify non-empty output

**Expected Result**:
- All existing commands continue to function
- No regressions introduced by BMC CLI additions

---

### BMC Watchdog Tests

**File**: `tests/platform_tests/daemon/test_bmc_watchdog.py`

These tests verify watchdog functionality for BMC systems.

#### Test Case #24: test_watchdog_status_and_configuration

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

#### Test Case #25: test_watchdog_bmc_integration

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
