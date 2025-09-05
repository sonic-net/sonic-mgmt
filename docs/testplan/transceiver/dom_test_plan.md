# DOM Test Plan For Transceivers

## Overview

The DOM Test Plan for transceivers outlines a comprehensive testing strategy for the Digital Optical Monitoring (DOM) functionality within the transceiver module. This document will cover the objectives, scope, test cases, and resources required for effective testing.

## Scope

The scope of this test plan includes the following:

- Validation of DOM data integrity and consistency for transceiver basic DOM content
- Testing of DOM access times and performance

## Optics Scope

All the optics covered in the parent [transceiver onboarding test plan](../transceiver_onboarding_test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](../transceiver_onboarding_test_plan.md#testbed-topology)

## Pre-requisites

Before executing the system tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](../transceiver_onboarding_test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](../transceiver_onboarding_test_plan.md#test-cases) must be met

### Environment Validation

Before starting tests, verify the following system conditions:

1. **System Health Check**
   - All critical services are running (xcvrd, pmon, swss, syncd)
   - No existing system errors in logs

2. **Transceiver Baseline Verification**
   - All expected transceivers are present and detected
   - All links are in operational state
   - No existing I2C communication errors
   - LLDP neighbors are discovered (if LLDP is enabled)

3. **Configuration Validation**
   - `dom.json` configuration file is properly formatted and accessible
   - All required attributes are defined for the transceivers under test
   - Platform-specific settings are correctly configured
   - DOM monitoring config is enabled for all relevant ports under test

## Attributes

A `dom.json` file is used to define the attributes for the DOM tests for the various types of transceivers the system supports.

**Note on Operational vs. Threshold Ranges:** The DOM test framework uses dual-range validation to provide more nuanced testing. Realistic operational ranges represent the expected values during normal, healthy operation in typical data center environments. These ranges are tighter than the absolute EEPROM threshold ranges and help distinguish between normal operation and edge cases that, while within specification, may indicate environmental stress, aging components, or suboptimal conditions. This approach enables early detection of potential issues before they trigger formal alarms, providing better system health monitoring and preventive maintenance capabilities.

The following table summarizes the key attributes used in DOM testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| temperature_operational_range | dict | {"min": 20.0, "max": 70.0} | ✗ | transceivers | Realistic operational temperature range in Celsius during normal operation (typical: room temp to moderate heat) |
| temperature_threshold_range | dict | {"lowalarm": -40.0, "lowwarning": -10.0, "highwarning": 75.0, "highalarm": 85.0} | ✗ | transceivers | Absolute threshold temperature range in Celsius (alarm/warning limits from EEPROM) |
| voltage_operational_range | dict | {"min": 3.20, "max": 3.40} | ✗ | transceivers | Realistic operational voltage range in volts during normal operation (typical: 3.3V ±3%) |
| voltage_threshold_range | dict | {"lowalarm": 2.97, "lowwarning": 3.135, "highwarning": 3.465, "highalarm": 3.63} | ✗ | transceivers | Absolute threshold voltage range in volts (alarm/warning limits: 3.3V ±10%) |
| laser_temperature_operational_range | dict | {"min": 20.0, "max": 70.0} | ✗ | transceivers | Realistic operational laser temperature range in Celsius during normal operation |
| laser_temperature_threshold_range | dict | {"lowalarm": -40.0, "lowwarning": -10.0, "highwarning": 75.0, "highalarm": 85.0} | ✗ | transceivers | Absolute threshold laser temperature range in Celsius (alarm/warning limits) |
| txLANE_NUMbias_operational_range | dict | {"min": 50.0, "max": 180.0} | ✗ | transceivers | Realistic operational TX bias current range in mA for lane LANE_NUM during normal operation |
| tx_bias_threshold_range | dict | {"lowalarm": 0.0, "lowwarning": 10.0, "highwarning": 190.0, "highalarm": 200.0} | ✗ | transceivers | Absolute threshold TX bias current range in mA (alarm/warning limits from EEPROM) |
| txLANE_NUMpower_operational_range | dict | {"min": -3.0, "max": 3.0} | ✗ | transceivers | Realistic operational TX power range in dBm for lane LANE_NUM during normal operation |
| tx_power_threshold_range | dict | {"lowalarm": -10.0, "lowwarning": -6.0, "highwarning": 6.0, "highalarm": 8.0} | ✗ | transceivers | Absolute threshold TX power range in dBm (alarm/warning limits from EEPROM) |
| rxLANE_NUMpower_operational_range | dict | {"min": -8.0, "max": 2.0} | ✗ | transceivers | Realistic operational RX power range in dBm for lane LANE_NUM during normal operation |
| rx_power_threshold_range | dict | {"lowalarm": -15.0, "lowwarning": -12.0, "highwarning": 4.0, "highalarm": 5.0} | ✗ | transceivers | Absolute threshold RX power range in dBm (alarm/warning limits from EEPROM) |
| max_update_time_sec | integer | 60 | ✗ | platform | Maximum expected time in seconds between DOM data updates for continuous monitoring validation |
| consistency_check_poll_count | integer | 3 | ✗ | transceivers or platform | Number of polling cycles to perform when validating DOM data consistency and variation patterns |
| shutdown_tx_bias_threshold | float | 1.0 | ✗ | transceivers | Maximum TX bias current in mA expected when interface is shutdown |
| shutdown_tx_power_threshold | float | -30.0 | ✗ | transceivers | Minimum TX power in dBm expected when interface is shutdown |
| consistency_check_enabled | boolean | True | ✗ | platform | Whether to verify DOM data consistency between STATE_DB and CLI interfaces |
| data_max_age_min | integer | 5 | ✗ | platform | Maximum age in minutes for DOM data to be considered fresh (last_update_time validation) |

## Dynamic Field Mapping Algorithm

The DOM test framework uses an attribute-driven approach to dynamically determine which fields to validate based on the configuration present in `dom.json`. This eliminates the need for hardcoded field lists and provides flexible, maintainable test execution.

### Algorithm Steps

1. **Attribute Discovery**: Scan `dom.json` for all attributes ending with `_operational_range` or `_threshold_range`

2. **Base Field Extraction**: Remove the suffix (`_operational_range` or `_threshold_range`) to get the base field name

3. **Lane Expansion Logic**:
   - If the attribute name contains `LANE_NUM` placeholder: Expand for all available lanes (1 to N) by replacing `LANE_NUM` with actual lane numbers
   - If no `LANE_NUM` placeholder is present: Expect a single field with the base name

4. **Special Field Mappings**: Apply any platform-specific field name mappings as needed

5. **Field Validation**: Validate presence and values of all dynamically determined fields in STATE_DB

### Example Mappings

| Attribute Name | Base Field | Lane Expansion | Expected STATE_DB Fields |
|----------------|------------|----------------|-------------------------|
| `temperature_operational_range` | `temperature` | No | `temperature` |
| `txLANE_NUMbias_operational_range` | `txLANE_NUMbias` | Yes | `tx1bias`, `tx2bias`, `tx3bias`, `tx4bias` (for 4-lane) |
| `rxLANE_NUMpower_operational_range` | `rxLANE_NUMpower` | Yes | `rx1power`, `rx2power`, `rx3power`, `rx4power` (for 4-lane) |
| `voltage_threshold_range` | `voltage` | No | `vcchighalarm`, `vcclowalarm`, `vcchighwarning`, `vcclowwarning` |
| `tx_power_threshold_range` | `tx_power` | No | `txpowerhighalarm`, `txpowerlowalarm`, `txpowerhighwarning`, `txpowerlowwarning` |

This algorithm ensures that test validation is automatically aligned with the configured attributes, providing comprehensive coverage while maintaining flexibility for different transceiver types and platform configurations.

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](../transceiver_onboarding_test_plan.md#cli-commands) in the transceiver onboarding test plan. This section provides comprehensive examples of all relevant commands

## Test Cases

**Test Execution Prerequisites:**

The following tests from the [Transceiver Onboarding Test Plan](../transceiver_onboarding_test_plan.md#test-cases) will be run prior to executing the system tests:

- Transceiver presence check
- Ensure active firmware is gold firmware (for non-DAC CMIS transceivers)
- Link up verification
- LLDP verification (if enabled)
- Ensure DOM monitoring is enabled for all relevant ports under test

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.

## Basic DOM Functionality Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | DOM data availability verification | 1. Access DOM data from `TRANSCEIVER_DOM_SENSOR` table in STATE_DB for each port.<br>2. Verify `last_update_time` is within `data_max_age_min` minutes of current time to ensure data freshness.<br>3. Dynamically determine expected DOM fields based on attributes present in `dom.json` using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>4. Validate presence of all dynamically determined expected fields in STATE_DB.<br>5. Skip validation for fields whose corresponding attributes are absent from `dom.json`. | All DOM fields corresponding to configured attributes are present and accessible from STATE_DB. DOM data is successfully retrieved without errors for all attribute-driven fields. Lane-specific fields are automatically expanded for all available lanes (1 to N) based on the `LANE_NUM` placeholder. Field expectations are dynamically derived using the mapping algorithm. Data freshness is confirmed with recent `last_update_time` timestamp. |
| 2 | DOM sensor operational range validation | 1. Retrieve DOM sensor data from STATE_DB.<br>2. Verify `last_update_time` is within `data_max_age_min` minutes of current time to ensure data freshness.<br>3. For each attribute ending with `_operational_range` present in `dom.json`, validate the corresponding field(s) in STATE_DB using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>4. Check that sensor values fall within the configured operational range.<br>5. Fail the test case if any values fall outside their respective operational ranges.<br>6. Log detailed information about any out-of-range values including actual vs expected ranges.<br>7. Only validate fields derived from attributes present in `dom.json`. | All DOM sensor values fall within their respective operational ranges during normal operation (only for parameters with configured operational range attributes). Test case fails if any sensor values fall outside their configured operational ranges. Data freshness is confirmed before validation. Lane-specific validation automatically performed for all available lanes using the `LANE_NUM` placeholder expansion. Parameter validation is dynamically determined from attribute table. Detailed logging provided for any out-of-range conditions. |
| 3 | DOM threshold validation | 1. Retrieve threshold data from `TRANSCEIVER_DOM_THRESHOLD` table in STATE_DB.<br>2. Dynamically determine expected threshold fields based on attributes ending with `_threshold_range` present in `dom.json` using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>3. For each determined threshold field, validate threshold data completeness by checking for corresponding alarm and warning thresholds (highalarm, lowalarm, highwarning, lowwarning).<br>4. Compare configured threshold ranges via attributes with thresholds values from DB and validate logical hierarchy (lowalarm < lowwarning < highwarning < highalarm).<br>5. For parameters that have both operational and threshold range attributes, validate that operational ranges fall within warning thresholds (lowwarning < operational_min and operational_max < highwarning).<br>6. Only validate threshold fields derived from attributes present in `dom.json`. | All threshold values are present and follow logical hierarchy. EEPROM thresholds align with configured threshold ranges when present. Operational ranges are properly positioned within warning threshold boundaries to ensure appropriate alarm behavior. Threshold data integrity is maintained in STATE_DB. Threshold validation is performed at transceiver level (no lane-specific expansion). Threshold validation is dynamically determined from attribute table. |
| 4 | DOM data consistency verification | 1. Read DOM data `consistency_check_poll_count` times with `max_update_time_sec` intervals between readings.<br>2. Verify data consistency between readings.<br>3. Check that `last_update_time` field is being updated correctly with each polling cycle.<br>4. Validate that sensor readings show expected behavior (e.g., temperature variations within reasonable limits). | DOM data shows consistent and reasonable variations between polling intervals over `consistency_check_poll_count` polling cycles. The `last_update_time` field is properly updated with each polling cycle. No erratic or impossible sensor value changes are observed during the monitoring period. Variation patterns indicate stable DOM monitoring system operation. |

## Advanced DOM Testing

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | DOM data during interface state changes | 1. Record baseline DOM values with interface in operational state and verify `last_update_time` is within `data_max_age_min` minutes of current time.<br>2. Identify remote side port from `sonic_{inv_name}_links.csv` for end-to-end validation.<br>3. Record remote side baseline DOM values including RX power for all lanes and alarm/warning flag states.<br>4. Issue `config interface shutdown <port>` and wait for shutdown completion.<br>5. Validate local DOM data changes for shutdown state:<br>   a. For each available lane: `tx{lane}bias` should be below `shutdown_tx_bias_threshold`<br>   b. For each available lane: `tx{lane}power` should be below `shutdown_tx_power_threshold`<br>   c. `temperature` and `voltage` should remain within normal ranges<br>   d. Verify `last_update_time` is updated within `last_down_time` per the PORT_TABLE of APPL_DB<br>6. Validate remote side DOM reflects link down condition:<br>   a. RX power should drop significantly on remote side for all lanes<br>   b. `rxLANE_NUMpowerLAlarm` and `rxLANE_NUMpowerLWarn` flags should be set<br>   c. Flag change count should increment for low alarm and warning flags<br>   d. Last set time should be updated to reflect link down event timing<br>7. Issue `config interface startup <port>` and wait for startup completion.<br>8. Validate local DOM data returns to operational ranges for all parameters and verify fresh `last_update_time`.<br>9. Validate remote side DOM reflects link up condition:<br>   a. RX power should return to operational range on remote side for all lanes<br>   b. `rxLANE_NUMpowerLAlarm` and `rxLANE_NUMpowerLWarn` flags should be cleared<br> | DOM values accurately reflect interface operational state on both local and remote sides with proper timing correlation. Shutdown state shows expected TX parameter changes locally while remote side shows corresponding RX power drop with appropriate flag management. Startup properly restores all DOM parameters to operational ranges on both sides with flag clearing. Data freshness is confirmed at each state transition within expected timing windows. End-to-end link health is validated through comprehensive DOM correlation including flag lifecycle management. Complete bidirectional validation ensures robust link health monitoring. |
| 2 | DOM polling and data freshness validation | 1. Verify DOM polling is currently enabled and record initial `last_update_time`.<br>2. Disable DOM polling: `config interface transceiver dom <port> disable`.<br>3. Record `last_update_time` after disable command and wait for 2x `max_update_time_sec`.<br>4. Verify that `last_update_time` has not been updated during disabled period.<br>5. Validate that DOM sensor values remain static (no new readings) during disabled period.<br>6. Enable DOM polling: `config interface transceiver dom <port> enable`.<br>7. Wait for `max_update_time_sec` and verify `last_update_time` is updated and within `data_max_age_min` minutes of current time.<br>8. Validate that all DOM sensor values are refreshed and within expected operational ranges.<br>9. Perform consistency check by reading DOM data `consistency_check_poll_count` times to ensure stable polling operation.<br>10. Verify continuous data freshness by monitoring `last_update_time` updates over multiple polling cycles. | DOM polling control works correctly with precise enable/disable functionality. Disabled polling completely prevents data updates while maintaining data integrity. Enabled polling resumes data collection within expected intervals with immediate data refresh. Data freshness is properly maintained through the `last_update_time` field with consistent update patterns. All sensor values return to expected ranges after re-enabling with stable polling behavior. |

## Cleanup and Post-Test Verification

After test completion:

### Immediate Cleanup

1. **DOM State Verification**: Ensure DOM monitoring continues to function normally after testing
2. **System Health**: Check system logs for any DOM-related errors or warnings introduced during testing
3. **Service Status**: Verify xcvrd and pmon services are operating normally with DOM polling active

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each DOM parameter
2. **Sensor Analysis**: Document any sensor values that approached range limits or showed unusual behavior
3. **Performance Metrics**: Report DOM access times and any performance variations observed
4. **Range Validation**: Summary of all DOM parameters with their actual vs. expected ranges
