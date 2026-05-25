# Port Configuration Test Plan For Transceivers

## Overview

The Port Configuration Test Plan outlines the testing strategy for validating that per-port configuration in CONFIG_DB (speed, FEC, etc) is consistent with the expected values defined in the transceiver inventory. These tests verify the switch's port configuration layer rather than transceiver EEPROM registers, and are topology-independent.

## Scope

The scope of this test plan includes the following:

- Validation of per-port speed configuration in CONFIG_DB against expected `speed_gbps` from `BASE_ATTRIBUTES`
- Validation of FEC mode configuration in CONFIG_DB for high-speed ports (≥ 200 Gbps)
- Validation of MTU configuration in CONFIG_DB against expected `expected_mtu` from `PORT_CONFIG_ATTRIBUTES`
- Validation of auto-negotiation setting in CONFIG_DB against expected `expected_autoneg` from `PORT_CONFIG_ATTRIBUTES`
- Validation that all transceiver ports are administratively up in CONFIG_DB
- Validation that DOM polling is enabled for all applicable transceiver ports in CONFIG_DB
- Validation that the `subport` field is correctly present or absent in CONFIG_DB based on breakout status

## Optics Scope

All the optics covered in the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology)

## Pre-requisites

Inherits all prerequisites from the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-prerequisites-and-configuration-files), including testbed setup, environment validation, and required configuration files. In addition, this plan requires:

- `dut_info/<dut_hostname>.json` contains `speed_gbps` and `host_lane_mask` in `BASE_ATTRIBUTES` for all ports under test.
- `port_config.json` is present and valid if MTU or autoneg validation is desired; when absent or an attribute is undefined, the corresponding test case skips that port gracefully.

## Attributes

Port configuration tests draw from two attribute sources:

- **BASE_ATTRIBUTES** (from `dut_info/<dut_hostname>.json`): Provides `speed_gbps` and `host_lane_mask`, used by port admin/status, speed, FEC, DOM polling, and subport validation tests. These attributes are always present because `dut_info` is a mandatory input file.
- **PORT_CONFIG_ATTRIBUTES** (from `port_config.json`): Provides `expected_mtu` and `expected_autoneg`, used by MTU validation and autoneg validation tests. When `port_config.json` is absent or an attribute is not defined for a port, the corresponding test cases skip that port gracefully.

The following table summarizes the key attributes used in port configuration testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Source | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|--------|------|---------------|-----------|-----------------|-------------|
| expected_mtu | PORT_CONFIG_ATTRIBUTES | integer | - | O | transceivers or platform | Expected MTU for the port in CONFIG_DB. When absent, the MTU validation test is skipped for that port. |
| expected_autoneg | PORT_CONFIG_ATTRIBUTES | string | off | O | transceivers or platform | Expected auto-negotiation setting (`"on"` or `"off"`). When absent, the autoneg validation tests are skipped for that port. DAC cables typically require `"off"`; value should align with `cable_type` in `BASE_ATTRIBUTES`. |

For information about attribute override hierarchy and precedence, please refer to the [Priority-Based Attribute Resolution](test_plan.md#priority-based-attribute-resolution) documentation.

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the Transceiver Onboarding Test Infrastructure and Framework. This section provides comprehensive examples of all relevant commands.

The primary database queries used in these tests are:

```bash
# CONFIG_DB — configured port parameter
sonic-db-cli CONFIG_DB hgetall 'PORT|<port_name>'

# CONFIG_DB — DOM polling status for a specific port
sonic-db-cli CONFIG_DB hget 'PORT|<port_name>' dom_polling
```

## Test Cases

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.
- This plan inherits the [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks); per the prerequisite matrix, Port Config consumes no session-level prerequisite gates because all tests are read-only DB queries.

### Port Configuration and Status Validation

| TC No. | Test | Steps | Expected Results |
|--------|------|-------|------------------|
| 1 | Port admin status validation in CONFIG_DB | 1. For each port in `port_attributes_dict`, query `sonic-db-cli CONFIG_DB hgetall 'PORT\|<port>'` to retrieve the configured `admin_status`.<br>2. Assert that `admin_status` equals `"up"` for every port.<br>3. Aggregate all failures and report at the end. | All ports in `port_attributes_dict` have `admin_status` set to `"up"` in CONFIG_DB. Any port found admin-down is a misconfiguration that must be identified and logged |
| 2 | Port speed validation in CONFIG_DB | 1. Retrieve the `speed_gbps` attribute from BASE_ATTRIBUTES in `port_attributes_dict` for the port.<br>2. Query the PORT table in CONFIG_DB to retrieve the configured speed for the port.<br>3. Convert the CONFIG_DB speed value to Gbps (e.g., "100000" → 100 Gbps, "400000" → 400 Gbps).<br>4. Compare the converted speed value with the `speed_gbps` attribute.<br>5. Aggregate all mismatches and report at the end. | 1. CONFIG_DB PORT table contains a `speed` field for the port.<br>2. Speed value from CONFIG_DB matches the `speed_gbps` attribute from BASE_ATTRIBUTES.<br>3. Any mismatches between configured and expected speed are identified and logged. |
| 3 | FEC configuration validation in CONFIG_DB | 1. Retrieve the `speed_gbps` attribute from BASE_ATTRIBUTES in `port_attributes_dict` for the port.<br>2. If `speed_gbps` is < 200 Gbps, skip the port.<br>3. Query the PORT table in CONFIG_DB to retrieve the configured FEC mode for the port.<br>4. Verify that FEC is set to `rs` for ports ≥ 200 Gbps.<br>5. Aggregate all mismatches and report at the end. | 1. CONFIG_DB PORT table contains a `fec` field for all ports ≥ 200 Gbps.<br>2. FEC is configured as `rs` for all ports ≥ 200 Gbps.<br>3. Any mismatches are identified and logged. |
| 4 | MTU configuration validation in CONFIG_DB | 1. Retrieve the `expected_mtu` attribute from PORT_CONFIG_ATTRIBUTES in `port_attributes_dict` for the port.<br>2. If `expected_mtu` is absent, skip the port.<br>3. Query `sonic-db-cli CONFIG_DB hgetall 'PORT\|<port>'` to retrieve the configured MTU.<br>4. Compare the actual MTU against `expected_mtu`.<br>5. Aggregate all mismatches and report at the end. | 1. CONFIG_DB PORT table contains an `mtu` field for the port.<br>2. MTU value matches `expected_mtu` from PORT_CONFIG_ATTRIBUTES.<br>3. Any misconfigured MTU values are identified and logged. |
| 5 | Auto-negotiation setting validation in CONFIG_DB | 1. Retrieve the `expected_autoneg` attribute from PORT_CONFIG_ATTRIBUTES in `port_attributes_dict` for the port.<br>2. If `expected_autoneg` is absent, skip the port.<br>3. Query `sonic-db-cli CONFIG_DB hgetall 'PORT\|<port>'` to retrieve the configured `autoneg` setting.<br>4. Compare the actual value against `expected_autoneg` (`"on"` or `"off"`).<br>5. Aggregate all mismatches and report at the end. | 1. CONFIG_DB PORT table contains an `autoneg` field for the port.<br>2. Auto-negotiation setting matches `expected_autoneg` from PORT_CONFIG_ATTRIBUTES.<br>3. Any mismatches (e.g., DAC cables with autoneg incorrectly enabled) are identified and logged. |
| 6 | DOM polling enabled validation in CONFIG_DB | 1. For each port in `port_attributes_dict`, determine whether it is the first subport of its breakout group (i.e., `host_lane_mask` in BASE_ATTRIBUTES indicates it owns the first host lane). Skip the port if it is not the first subport of a breakout group.<br>2. Query `sonic-db-cli CONFIG_DB hget 'PORT\|<port>' dom_polling` to retrieve the DOM polling setting.<br>3. If the field is absent, treat DOM polling as enabled (per SONiC default behaviour) and pass.<br>4. If the field is present and equals `"enabled"`, pass.<br>5. If the field is present and equals `"disabled"`, record a failure.<br>6. Aggregate all failures and report at the end. | 1. For all first subports of breakout groups (and non-breakout ports), the `dom_polling` field in CONFIG_DB PORT table is either absent or set to `"enabled"`.<br>2. Any port with `dom_polling` explicitly set to `"disabled"` is identified and logged as a misconfiguration — DOM data will not be populated in STATE_DB for that port, causing DOM tests to fail. |
| 7 | Subport field validation in CONFIG_DB | 1. For each port in `port_attributes_dict`, determine its physical port index and group logical ports that share the same physical index.<br>2. For each physical port group:<br>   a. If the group contains exactly 1 logical port (non-breakout): verify that the `subport` field is either absent or set to `"0"`. If `subport` is present and set to any other value, record a failure.<br>   b. If the group contains more than 1 logical port (breakout): verify that the `subport` field is present for every logical port in the group. If `subport` is missing for any logical port, record a failure.<br>3. Aggregate all failures and report at the end. | 1. For non-breakout physical ports (1 logical port): `subport` is either absent or `"0"` in CONFIG_DB.<br>2. For breakout physical ports (>1 logical port): `subport` is present for every logical port in the group.<br>3. Any violations are identified and logged with the physical port index, logical port name, and the actual `subport` value (or its absence). |

## Cleanup and Post-Test Verification

The following steps are performed once after **all test cases** in this plan have completed. The [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks) already cover ongoing health monitoring throughout the run.

### Post-Test Checks

1. **Port operational state**: Confirm all ports in `port_attributes_dict` remain operationally up. All tests are read-only DB queries so no link disruptions are expected, but this confirms the assumption.

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each test case.
2. **Mismatch Report**: Summarize all configuration mismatches (speed, FEC, MTU, autoneg, DOM polling, subport presence) with actual vs. expected values and the port where the mismatch was detected.
