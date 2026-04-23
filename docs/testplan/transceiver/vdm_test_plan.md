# VDM Test Plan For Transceivers

## Overview

The VDM Test Plan for transceivers outlines a comprehensive testing strategy for the Versatile Diagnostics Monitoring (VDM) functionality within the transceiver module. This document will cover the objectives, scope, test cases, and resources required for effective testing.

## Scope

The scope of this test plan includes the following:

- Validation of VDM data integrity and consistency for transceiver basic VDM content
- Testing of VDM access times and performance

## Optics Scope

All the optics covered in the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology)

## Pre-requisites

Before executing the VDM tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-prerequisites-and-configuration-files) must be met

### Environment Validation

Before starting tests, verify the following system conditions:

1. **System Health Check**
   - All critical services are running (xcvrd, pmon, swss, syncd) for at least 5 minutes
   - No existing system errors in logs (specific error patterns can be added here)

2. **Transceiver Baseline Verification**
   - All expected transceivers are present and detected
   - All links are in operational state
   - No existing I2C communication errors
   - LLDP neighbors are discovered (if LLDP is enabled)

3. **Configuration Validation**
   - `vdm.json` configuration file is properly formatted and accessible
   - All required attributes are defined for the transceivers under test
   - Platform-specific settings are correctly configured
   - VDM monitoring config is enabled for all relevant ports under test

## Attributes

A `vdm.json` file is used to define the attributes for the VDM tests for the various types of transceivers the system supports.

The following table summarizes the key attributes used in VDM testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Mandatory | Override Levels | Description |
|----------------|------|-----------|-----------------|-------------|
| laser_age | integer | O | transceivers | 0% BOL - 100% EOL (Media lane) |
| tec_current | integer | O | transceivers | TEC Current (Module) |
| laser_frequency_error | integer | O | transceivers | Frequency of laser error (MHz) |
| laser_temperatureLANE_NUM | integer | O | transceivers | Temperature of laser (C) |
| snr_media_inputLANE_NUM | integer | O | transceivers | Signal Noise Ratio (dB) of Media Lane |
| snr_host_input | integer | O | transceivers | Signal Noise Ratio (dB) of Host Lane |
| pam4_ltp_media_input | integer | O | transceivers | PAM4 Level Transition Parameter Media Input (dB) |
| pam4_ltp_host_inputLANE_NUM | integer | O | transceivers | PAM4 Level Transition Parameter Host Input Lane (dB) |
| prefec_ber_media_input_statsLANE_NUM | dict | M | transceivers | Pre-FEC BER stats on media side. Format: {"max": \<float\>, "average": \<float\>, "current": \<float\>} — all sub-fields optional; omit any sub-field to skip its validation |
| prefec_ber_host_input_statsLANE_NUM | dict | M | transceivers | Pre-FEC BER stats on host side. Format: {"max": \<float\>, "average": \<float\>, "current": \<float\>} — all sub-fields optional; omit any sub-field to skip its validation |
| ferc_media_input_statsLANE_NUM | dict | O | transceivers | Post-FEC errored frames stats on media side. Format: {"max": \<float\>, "average": \<float\>, "current": \<float\>, "total": \<float\>} — all sub-fields optional; omit any sub-field to skip its validation |
| ferc_host_input_statsLANE_NUM | dict | O | transceivers | Post-FEC errored frames stats on host side. Format: {"max": \<float\>, "average": \<float\>, "current": \<float\>, "total": \<float\>} — all sub-fields optional; omit any sub-field to skip its validation |

The following table below summarizes Data Path Monitors of the VDM. Please note: Unless specified differently, the VDM monitors for a DCO are all associated with a data path. Therefore, the lane or data path identifier of those VDM monitors shall indicate the first lane of the relevant data path

| Monitor Name | Type | Mandatory | Override Levels | Description |
|----------------|------|-----------|-----------------|-------------|
| modulator_bias_xi | integer | O | transceivers | Modulator bias X/I in percentage |
| modulator_bias_xq | integer | O | transceivers | Modulator bias X/Q in percentage |
| modulator_bias_yi | integer | O | transceivers | Modulator bias Y/I in percentage |
| modulator_bias_yq | integer | O | transceivers | Modulator bias Y/Q in percentage |
| modulator_bias_x_phase | integer | O | transceivers | Modulator bias X_phase in percentage |
| modulator_bias_y_phase | integer | O | transceivers | Modulator bias Y_phase in percentage |
| hgranularity_slink_cd | integer | O | transceivers | Chromatic dispersion high granularity, short link in ps/nm. Measure on media side fiber as estimated from DSP compensation. |
| lgranularity_llink_cd | integer | O | transceivers | Chromatic dispersion low granularity, long link in ps/nm |
| DGD | integer | O | transceivers | Differential group delay in ps |
| sopmd_high_granularity | integer | O | transceivers | State-of-polarization mode dispersion high granularity in ps^2 |
| pdl | integer | O | transceivers | Polarization dependent loss in db |
| osnr | integer | O | transceivers | Optical SNR in db |
| esnr | integer | O | transceivers | effective SNR in db |
| cfo | integer | O | transceivers | Carrier frequency offset in MHz |
| evm | integer | O | transceivers | Error vector magnitude in percentage |
| tx_power | integer | O | transceivers | TX power in dbm |
| rx_total_power | integer | O | transceivers | RX total power in dbm |
| rx_signal_power | integer | O | transceivers | Rx signal power in dbm |
| sop_roc | integer | O | transceivers | State-of-polarization rotation rate in krads/s |
| mer | integer | O | transceivers | Modulation error ratio in db |
| clock_recovery_loop | integer | O | transceivers | Clock recovery loop in percentage, will be -100 to 100% with nominal at 0%. Defect thresholds are set by vendor to indicate operation is outside of normal range. |
| sopmd_low_granularity | integer | O | transceivers | State-of-polarization mode dispersion low granularity in ps^2 |
| snr_margin | integer | O | transceivers | SNR margin in db |
| q_factor | integer | O | transceivers | Q factor in db |
| q_margin | integer | O | transceivers | Q margin in db |
| cfo_low_granularity | integer | O | transceivers | Carrier frequency offset low granularity in MHz |

## Example `vdm.json` File

The following example demonstrates a `vdm.json` file with several VDM fields — integer attributes, lane-specific attributes, and dict-based stats — for different transceiver types:

```json
{
  "transceivers": {
    "vendors": {
      "finisar": {
        "part_numbers": {
          "FTLX8571D3BCL-10GSFP": {
            "laser_age": 40,
            "laser_temperature1": 35,
            "prefec_ber_media_input_stats1": {
              "max": 1.0e-3,
              "average": 1.0e-4,
              "current": 2.0e-4
            }
          }
        }
      },
      "mellanox": {
        "part_numbers": {
          "MCP1600-C003-100G": {
            "laser_age": 40,
            "snr_media_input1": 15,
            "prefec_ber_media_input_stats1": {
              "max": 1.0e-3,
              "average": 1.0e-4,
              "current": 2.0e-4
            }
          },
          "MMA1T00-VS-400G": {
            "laser_age": 15,
            "tec_current": 80,
            "snr_media_input1": 20,
            "prefec_ber_media_input_stats1": {
              "max": 1.0e-3,
              "average": 1.0e-4,
              "current": 2.0e-4
            },
          }
        }
      },
      "marvell": {
        "part_numbers": {
          "88X7120-800G": {
            "laser_age": 40,
            "tec_current": 85,
            "snr_media_input1": 25,
            "prefec_ber_media_input_stats1": {
              "max": 1.0e-3,
              "average": 1.0e-4,
              "current": 2.0e-4
            },
          }
        }
      }
    }
  }
}
```

## Dynamic Field Mapping Algorithm

The VDM test framework uses an attribute-driven approach to dynamically determine which fields to validate based on the configuration present in `vdm.json`. This eliminates the need for hardcoded field lists and provides flexible, maintainable test execution.

### Algorithm Steps

1. **Attribute Discovery**: Collect all attributes configured under the matched transceiver entry in `vdm.json` (resolved by vendor and part number). Lane-specific attributes use explicit lane numbers in the key (e.g., `prefec_ber_media_input_stats1` for lane 1); multiple entries with different lane suffixes may be present.

2. **Field Type Classification**: For each attribute:
   - **Scalar** (integer or float value): validate the corresponding STATE_DB field as an upper-bound threshold — the live value must be ≤ the configured value. For example, `"laser_age": 40` means the transceiver must report ≤ 40% EOL.
   - **Dict** (`_stats` attribute, object value): expand into per-sub-field STATE_DB validations

3. **Sub-field Selective Validation**: For dict attributes, only validate the sub-fields explicitly present in the JSON config. Sub-fields omitted from the config (e.g., `min` for error-rate stats where a lower value is always better) are skipped entirely.

4. **STATE_DB Field Name Construction**: Map each JSON attribute key and sub-field to a STATE_DB field name:
   - The lane number is already embedded in the attribute key (e.g., `...stats1` → lane 1)
   - Sub-field abbreviations: `average` → `avg`, `current` → `curr`; `min`, `max`, and `total` are unchanged

5. **Field Validation**: Validate presence and threshold compliance for all derived STATE_DB fields

### Example Mappings

| JSON Attribute Key | Type | Sub-fields Validated | Expected STATE_DB Fields |
|-------------------|------|----------------------|--------------------------|
| `laser_temperature1` | scalar | — | `laser_temperature1` |
| `snr_media_input1` | scalar | — | `snr_media_input1` |
| `prefec_ber_media_input_stats1` | dict | `max`, `average`, `current` | `prefec_ber_max_media_input1`, `prefec_ber_avg_media_input1`, `prefec_ber_curr_media_input1` |
| `ferc_media_input_stats1` | dict | `max`, `average`, `current`, `total` | `ferc_max_media_input1`, `ferc_avg_media_input1`, `ferc_curr_media_input1`, `ferc_total_media_input1` |

This algorithm ensures that test validation is automatically aligned with the configured attributes, providing comprehensive coverage while maintaining flexibility for different transceiver types and platform configurations.

## Test Parameters

The following parameters are referenced throughout the test cases and must be defined in the test configuration before execution:

| Parameter | Description |
|-----------|-------------|
| `data_max_age_min` | Maximum age (in minutes) of VDM data to be considered fresh. VDM data older than this threshold is treated as stale and will fail freshness checks. |
| `consistency_check_poll_count` | Number of successive polling cycles used in consistency checks to confirm stable VDM data updates. |
| `max_update_time_sec` | Maximum expected interval (in seconds) between consecutive VDM data updates. Used as the wait duration between polling cycles in consistency checks. |
| `recovery_time_sec` | Time (in seconds) to wait after restoring normal operating conditions before re-validating sensor values. |

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the Transceiver Onboarding Test Infrastructure and Framework. This section provides comprehensive examples of all relevant commands

## Test Cases

**Test Execution Prerequisites:**

The following tests from the [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-cases-interim) will be run prior to executing the VDM tests:

- Transceiver presence check
- Ensure active firmware is gold firmware (for non-DAC CMIS transceivers)
- Link up verification
- LLDP verification (if enabled)
- Ensure VDM monitoring is enabled for all relevant ports under test

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.

### Basic VDM Functionality Tests

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | VDM data availability verification | 1. Access VDM data from `TRANSCEIVER_VDM` table in STATE_DB for each port.<br>2. Verify `last_update_time` is within `data_max_age_min` minutes of current time to ensure data freshness.<br>3. Dynamically determine expected VDM fields based on attributes present in `vdm.json` using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>4. Validate presence of all dynamically determined expected fields in STATE_DB.<br>5. Skip validation for fields whose corresponding attributes are absent from `vdm.json`. | All VDM fields corresponding to configured attributes are present and accessible from STATE_DB. VDM data is successfully retrieved without errors for all attribute-driven fields. Lane-specific fields are automatically expanded for all available lanes (1 to N) based on the `LANE_NUM` placeholder. Field expectations are dynamically derived using the mapping algorithm. Data freshness is confirmed with recent `last_update_time` timestamp. |
| 2 | VDM scalar threshold validation | 1. Retrieve VDM data from STATE_DB.<br>2. Verify `last_update_time` is within `data_max_age_min` minutes of current time to ensure data freshness.<br>3. For each scalar attribute present in `vdm.json`, retrieve the corresponding field from STATE_DB using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>4. Check that the live STATE_DB value is ≤ the configured threshold (e.g., `laser_age` reported value must not exceed the configured percentage).<br>5. Fail the test case if any value exceeds its configured threshold.<br>6. Log detailed information about any violations including the actual value vs the configured threshold.<br>7. Only validate fields whose corresponding scalar attributes are present in `vdm.json`. | All scalar VDM sensor values are at or below their configured thresholds during normal operation. Test case fails if any sensor value exceeds its threshold. Data freshness is confirmed before validation. Lane-specific validation is automatically performed for all available lanes. Detailed logging is provided for any threshold violations. |
| 3 | VDM warning threshold hierarchy validation | 1. Retrieve Pre-FEC and Post-FEC threshold data from `TRANSCEIVER_VDM_LWARN_THRESHOLD` and `TRANSCEIVER_VDM_HWARN_THRESHOLD` tables in STATE_DB.<br>2. Dynamically determine expected threshold fields based on `prefec_ber_` and `ferc_` attributes present in `vdm.json` using the [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm).<br>3. For each determined field, verify that low-warning threshold values are less than high-warning threshold values, confirming correct threshold hierarchy.<br>4. Only validate fields derived from attributes present in `vdm.json`. | All threshold fields are present in STATE_DB and follow the correct logical hierarchy (LWARN < HWARN). EEPROM thresholds align with configured threshold ranges when present. Threshold data integrity is maintained in STATE_DB. Threshold validation is dynamically determined from the attribute table. |
| 4 | VDM data consistency verification | 1. Read VDM data `consistency_check_poll_count` times with `max_update_time_sec` intervals between readings.<br>2. Verify data consistency between readings.<br>3. Check that `last_update_time` field is being updated correctly with each polling cycle.<br>4. Validate that VDM readings show expected behavior (e.g., temperature variations within reasonable limits). | VDM data shows consistent and reasonable variations between polling intervals over `consistency_check_poll_count` polling cycles. The `last_update_time` field is properly updated with each polling cycle. No erratic or impossible sensor value changes are observed during the monitoring period. Variation patterns indicate stable VDM monitoring system operation. |

### Advanced VDM Testing

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | VDM data persistence during interface state changes | 1. Record baseline VDM data from `TRANSCEIVER_VDM` table in STATE_DB including all sensor values and `last_update_time`.<br>2. Record baseline link flap count for the port.<br>3. Execute interface shutdown: `config interface shutdown <port>`.<br>4. Wait for interface to reach down state (verify with `show interfaces status`).<br>5. Read VDM data from `TRANSCEIVER_VDM` table while interface is down.<br>6. Verify `last_update_time` continues to be updated during shutdown state.<br>7. Validate that VDM sensor values remain accessible and within expected ranges during shutdown.<br>8. Execute interface startup: `config interface startup <port>`.<br>9. Wait for interface to reach up state and link to establish (verify with `show interfaces status`).<br>10. Read VDM data from `TRANSCEIVER_VDM` table after interface comes up.<br>11. Perform consistency check by reading VDM data `consistency_check_poll_count` times with `max_update_time_sec` intervals.<br>12. Validate all dynamically determined VDM fields (per [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)) are present and updated.<br>13. Verify sensor values return to operational ranges after link establishment.<br>14. Compare final link flap count to baseline to confirm exactly 2 flaps occurred (1 down, 1 up). | VDM monitoring continues during interface shutdown with data updates and accessibility maintained. VDM data remains consistent and fresh throughout the shutdown period without data corruption. Interface state transitions do not disrupt VDM data collection or cause service crashes. After interface startup, all sensor values stabilize within operational ranges. Link flap count increases by exactly 2 confirming controlled interface state changes. Critical processes (`xcvrd`, `pmon`, `syncd`) remain stable throughout with no crashes or restarts. |
| 2 | VDM threshold violation detection and recovery | 1. Read baseline VDM data and verify all sensor values are within their configured thresholds.<br>2. Record baseline threshold values from `TRANSCEIVER_VDM_LWARN_THRESHOLD` and `TRANSCEIVER_VDM_HWARN_THRESHOLD` tables in STATE_DB.<br>3. Gradually stress the environment to approach warning thresholds (e.g., reduce cooling or increase traffic load).<br>4. Monitor VDM sensor values at `max_update_time_sec` intervals using `TRANSCEIVER_VDM` table.<br>5. Verify that sensor values approaching or exceeding thresholds are accurately reported and `last_update_time` is continuously updated.<br>6. Check system logs for threshold violation warnings.<br>7. Restore normal operating conditions.<br>8. Wait for `recovery_time_sec` to allow sensors to stabilize.<br>9. Verify all VDM sensor values return within their configured thresholds.<br>10. Perform consistency check by reading VDM data `consistency_check_poll_count` times.<br>11. Verify interface remained operationally up throughout and link flap count is unchanged.<br>12. Confirm no critical process crashes occurred during the stress and recovery period. | VDM monitoring accurately detects and reports sensor values approaching or exceeding thresholds with continuous data freshness. System logs capture threshold violations with clear warning messages. VDM data updates remain consistent during environmental stress with no polling interruptions or data corruption. After restoration of normal conditions, all sensor values return within thresholds within `recovery_time_sec`. Interface stability is maintained throughout with no link flaps. Critical processes (`xcvrd`, `pmon`, `syncd`, `swss`) remain stable with no crashes during stress and recovery. |
| 3 | VDM data integrity during config reload and warm reboot | 1. Verify VDM polling is enabled and record baseline VDM data from `TRANSCEIVER_VDM` table including all sensor values, link flap count, and `last_update_time`.<br>2. Execute config reload: `config reload -y`.<br>3. Wait for config reload to complete and all services to restart (verify with `show system status`).<br>4. Verify interfaces return to operational up state after config reload.<br>5. Read VDM data from `TRANSCEIVER_VDM` table and verify `last_update_time` is within `data_max_age_min` minutes.<br>6. Validate all dynamically determined VDM fields (per [Dynamic Field Mapping Algorithm](#dynamic-field-mapping-algorithm)) are present and populated.<br>7. Perform consistency check by reading VDM data `consistency_check_poll_count` times with `max_update_time_sec` intervals.<br>8. Record link flap count after config reload stabilization.<br>9. Execute warm reboot: `warm-reboot`.<br>10. Wait for warm reboot to complete and system to fully initialize.<br>11. Verify interfaces return to operational up state after warm reboot.<br>12. Read VDM data from `TRANSCEIVER_VDM` table and verify data freshness with recent `last_update_time`.<br>13. Validate all VDM fields are present and sensor values are within their configured thresholds.<br>14. Perform final consistency check with `consistency_check_poll_count` polling cycles.<br>15. Compare final link flap count to baseline and verify only expected flaps from reload/reboot operations occurred. | VDM monitoring resumes automatically after config reload with all data structures properly reinitialized and data fresh. All sensor values return within thresholds after config reload stabilization. Critical processes restart cleanly without crashes and VDM polling resumes normal operation. After warm reboot, VDM data collection resumes quickly with fresh timestamps and accurate sensor readings. Link flap counts reflect only expected flaps from reload/reboot operations, not spurious flaps. All threshold tables (`TRANSCEIVER_VDM_LWARN_THRESHOLD`, `TRANSCEIVER_VDM_HWARN_THRESHOLD`) are properly restored with correct values. |

## Cleanup and Post-Test Verification

After test completion:

### Immediate Cleanup

1. **VDM State Verification**: Ensure VDM monitoring continues to function normally after testing
2. **System Health**: Check alarms for any VDM-related errors or warnings introduced during testing
3. **Service Status**: Verify xcvrd and pmon services are operating normally with VDM polling active

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each VDM parameter
2. **Sensor Analysis**: Document any sensor values that approached range limits or showed unusual behavior
3. **Performance Metrics**: Report VDM access times and any performance variations observed
4. **Range Validation**: Summary of all VDM parameters with their actual vs. expected ranges