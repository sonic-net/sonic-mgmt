# Test Plan — CPO DOM Extensions and STATE_DB Publication

> **Implementation**: [sonic-mgmt PR #29020](https://github.com/sonic-net/sonic-mgmt/pull/29020).
>
> **Related HLD**: [SONiC PR #2273 — SW-controlled CPO in Joint Mode](https://github.com/sonic-net/SONiC/pull/2273).

## 1. Scope and Preconditions

Verify that xcvrd publishes OE data in `TRANSCEIVER_*` tables and ELS data in separate `TRANSCEIVER_ELS_*` tables.

- NVIDIA Mellanox CPO platform with `port_type: CPO` and `SAI_INDEPENDENT_MODULE_MODE=1`; otherwise skip.
- Pmon must be ready and STATE_DB transceiver records must be populated.
- Select one operationally up CPO first subport; skip if CPO ports exist but none is operationally up.
- All tests are read-only. Required fields are defined in `tests/platform_tests/mellanox/cpo_dom_field_catalog.py` at the referenced revision.

**SimX note**: The reviewed code has no SimX-specific exclusions, despite the exclusions stated in the PR description.

## 2. Test Cases

Implementation: `tests/platform_tests/mellanox/test_cpo_dom_state_db.py` — **6 test functions / 6 pytest items**.

Use one STATE_DB snapshot for table and field checks; read timestamps live for TC-6. Each required `TABLE|<port>` record must be nonempty.

### TC-1: ELS Tables and Setpoints

**Function**: `test_cpo_els_tables_in_state_db`

- Check all eight ELS tables in `CPO_ELS_TABLE_SPEC`: INFO, FIRMWARE_INFO, DOM_SENSOR, DOM_TEMPERATURE, DOM_THRESHOLD, DOM_FLAG, STATUS, and STATUS_FLAG.
- Require all catalog fields, including per-laser monitors and CDB-backed sensor fields.
- Require all 16 setpoint fields (`bias_current_setpoint_lane{n}` and `optical_power_setpoint_lane{n}`, `n=1..8`) together in either `TRANSCEIVER_ELS_DOM_THRESHOLD` or `TRANSCEIVER_ELS_DOM_SENSOR`.

### TC-2: ELS Flag Companion Tables

**Function**: `test_cpo_els_flag_companion_tables_in_state_db`

Check that all six companion records exist: `_CHANGE_COUNT`, `_SET_TIME`, and `_CLEAR_TIME` for both `TRANSCEIVER_ELS_DOM_FLAG` and `TRANSCEIVER_ELS_STATUS_FLAG`.

### TC-3: OE Flag Companion Tables

**Function**: `test_cpo_oe_flag_companion_tables_in_state_db`

Check that all six companion records exist: `_CHANGE_COUNT`, `_SET_TIME`, and `_CLEAR_TIME` for both `TRANSCEIVER_DOM_FLAG` and `TRANSCEIVER_STATUS_FLAG`.

### TC-4: VDM Tables

**Function**: `test_cpo_vdm_tables_in_state_db`

For each type `HALARM`, `LALARM`, `HWARN`, and `LWARN`, require `TRANSCEIVER_VDM_<type>_THRESHOLD`, its corresponding `_FLAG` table, and the flag's three companion tables. All **20 records** must exist.

### TC-5: OE Tables and CPO Identity

**Function**: `test_cpo_oe_tables_in_state_db`

- Check all nine OE tables and required fields in `CPO_OE_TABLE_SPEC`, including standard DOM fields and `laser_age1`–`laser_age8` in `TRANSCEIVER_VDM_REAL_VALUE`.
- Require `TRANSCEIVER_INFO` values: `type=CPO`, `type_abbrv_name=CPO`, and `vdm_supported=True` (string comparison).
- Reject `els_*` fields in OE tables, except `TRANSCEIVER_VDM_REAL_VALUE`, which permits standard CMIS VDM names such as `els_input_power{n}`.

### TC-6: Timestamp Freshness

**Function**: `test_cpo_tables_last_update_time_fresh`

- Read `last_update_time` from the 13 tables in `CPO_REFRESHED_TABLES`.
- Require UTC timestamp age relative to the DUT clock to be **-2 to 60 seconds**; missing or unparsable timestamps fail.
- Retry for up to 30 seconds at 5-second intervals. Static threshold tables are excluded from this check.

## 3. Coverage Limits

Checks cover required-field presence, explicit CPO identity values, table separation, and timestamp freshness on one representative port. They do not validate sensor accuracy, alarm transitions, companion-counter behavior, EEPROM decoding, or module lifecycle recovery. Companion and VDM threshold/flag checks validate record existence only.
