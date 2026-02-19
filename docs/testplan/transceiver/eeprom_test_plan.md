# Transceiver EEPROM Test Plan

## Overview

The Transceiver EEPROM Test Plan outlines the testing strategy for the EEPROM functionality within the transceiver module. This document will cover the objectives, scope, test cases, and resources required for effective testing.

## Scope

The scope of this test plan includes the following:

- Verification of EEPROM read and write operations
- Validation of data integrity and consistency for transceiver basic EEPROM content
- Testing of EEPROM access times and performance

## Optics Scope

All the optics covered in the parent [transceiver onboarding test plan](test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology)

## Pre-requisites

Before executing the EEPROM tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](test_plan.md#test-prerequisites-and-configuration-files) must be met

### Environment Validation

Before starting tests, verify the following system conditions:

1. **System Health Check**
   - All critical services are running (xcvrd, pmon, swss, syncd) for at least 5 minutes
   - No existing system errors in logs

2. **Configuration Validation**
   - `eeprom.json` configuration file is properly formatted and accessible
   - All required attributes are defined for the transceivers under test

## Attributes

A `eeprom.json` file is used to define the attributes for the EEPROM tests for the various types of transceivers the system supports.

The following table summarizes the key attributes used in EEPROM testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| dual_bank_supported | boolean | - | M | transceivers | Whether transceiver supports dual bank firmware |
| vdm_supported | boolean | False | O | transceivers | VDM capability support |
| pm_supported | boolean | False | O | transceivers | Performance Monitoring support |
| cdb_background_mode_supported | boolean | - | O | transceivers | CDB background mode support |
| gold_firmware_version | string | - | O | transceivers | Expected gold/reference firmware version for validation. This also represents the active firmware version. This attribute is applicable only for modules with CMIS CDB firmware. |
| inactive_firmware_version | string | - | O | transceivers | Expected inactive bank firmware version for dual-bank CMIS CDB modules during validation |
| cmis_revision | string | - | O | transceivers | CMIS revision for CMIS based transceivers |
| sff8024_identifier | string | - | M | transceivers | SFF-8024 identifier for the transceiver |
| is_non_dac_and_cmis | boolean | False | O | transceivers | Whether the transceiver is a non-DAC CMIS transceiver |
| breakout_serial_number_pattern | string | - | O | transceivers | Regex pattern to validate serial number format for breakout leaf port transceivers (e.g., ".*-A$", ".*-B$", ".*-C$" for suffix validation, or any other pattern for different placements). Used to validate that leaf-side ports on breakout modules have correctly formatted serial numbers |
| breakout_stem_serial_number_pattern | string | - | O | transceivers | Regex pattern to validate serial number format for breakout stem (main) port transceivers. Typically validates that the serial number does NOT contain leaf suffixes (e.g., "^(?!.*-[A-Z]$).*$" to ensure no suffix like -A, -B, -C). Used to validate that stem-side ports on breakout modules have correctly formatted serial numbers without leaf identifiers |
| eeprom_dump_timeout_sec | integer | 5 | O | transceivers or platform | Default EEPROM dump timeout in seconds |

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the transceiver onboarding test plan. This section provides comprehensive examples of all relevant commands

## Test Cases

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.

### Generic Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Transceiver presence verification (sfputil) | 1. Use the `sfputil show presence -p <port>` command to check for transceiver presence.<br>2. Verify the output for each connected transceiver. | All connected transceivers should be listed as "Present" in the output. |
| 2 | Transceiver presence verification (show CLI) | 1. Use the `show interfaces transceiver presence` CLI to check for transceiver presence.<br>2. Verify the output for each connected transceiver. | All connected transceivers should be listed as "Present" in the output. |
| 3 | Basic EEPROM content verification via sfputil | 1. Retrieve the BASE_ATTRIBUTES and EEPROM_ATTRIBUTES from `port_attributes_dict`.<br>2. Use `sfputil show eeprom -p <port>` to dump EEPROM data.<br>3. Compare key fields (vendor name, part number, serial number, cmis revision, module hardware revision) with expected values. | 1. All key EEPROM fields match expected values from `port_attributes_dict`.<br>2. EEPROM dump completes within `eeprom_dump_timeout_sec`. |
| 4 | Basic EEPROM content verification via show CLI | 1. Retrieve the BASE_ATTRIBUTES and EEPROM_ATTRIBUTES from `port_attributes_dict`.<br>2. Use `show interfaces transceiver info <port>` CLI.<br>3. Verify key fields against expected values. | All key EEPROM fields from CLI output match expected values from `port_attributes_dict`. |
| 5 | Firmware version validation | 1. For transceivers with `gold_firmware_version` attribute, use `sfputil show fwversion <port>`.<br>2. If `dual_bank_supported` is true, verify both active and inactive firmware versions.<br>3. Compare with expected values from attributes. | Active and inactive firmware versions match corresponding values in attributes dictionary. |
| 6 | EEPROM hexdump CLI verification | 1. Use `sfputil show eeprom-hexdump -p <port> -n 0` to retrieve lower page hexdump.<br>2. Parse hexdump for vendor name and part number.<br>3. For non-DAC CMIS transceivers (`is_non_dac_and_cmis` = true), use `sfputil show eeprom-hexdump -p <port> -n 0x11` to dump page 0x11. | 1. Hexdump contains expected vendor name and part number.<br>2. Non-DAC CMIS transceivers show DPActivated state in page 0x11. |
| 7 | sfputil read-eeprom CLI verification | 1. Use `sfputil read-eeprom -p <port> -n 0 -o 0 -s 1` to retrieve the identifier byte from lower page offset 0 (or use `--wire-addr A0h` for SFF-8472 transceivers). | Retrieved data matches the value of `sff8024_identifier` from `port_attributes_dict`. |
| 8 | Error handling - Missing transceiver | 1. Attempt EEPROM operations on ports without transceivers.<br>2. Verify error messages.<br>3. Test both sfputil and show CLI commands. | Commands return appropriate messages indicating transceiver absence. |
| 9 | Serial number pattern validation for breakout ports | 1. Check if `breakout_serial_number_pattern` or `breakout_stem_serial_number_pattern` attribute is defined for the transceiver in `port_attributes_dict`.<br>2. If neither attribute is defined, skip this test for the port.<br>3. If `breakout_serial_number_pattern` is defined (leaf port):<br>   a. Use `sfputil show eeprom -p <port>` to retrieve the serial number.<br>   b. Log the retrieved serial number for debugging purposes.<br>   c. Based on the leaf or stem side, validate that the serial number matches the regex pattern from `breakout_serial_number_pattern` or `breakout_stem_serial_number_pattern` attribute.<br> | 1. Test is executed only when `breakout_serial_number_pattern` or `breakout_stem_serial_number_pattern` attribute is present.<br>2. Serial number is successfully retrieved and logged.<br>3. For leaf ports: Serial number matches the expected regex pattern (e.g., `".*-A$" for leaf A, ".*-B$" for leaf B`)<br>4. For stem ports: Serial number matches the stem pattern (typically validates absence of leaf suffixes like -A, -B, -C).<br>5. Test is skipped gracefully for ports without either attribute defined. |
| 10 | Port speed validation in CONFIG_DB | 1. Retrieve the `speed_gbps` attribute from BASE_ATTRIBUTES in `port_attributes_dict` for the port.<br>2. Query the PORT table in CONFIG_DB to retrieve the configured speed for the port.<br>3. Convert the CONFIG_DB speed value to Gbps (e.g., "100000" → 100 Gbps, "400000" → 400 Gbps).<br>4. Compare the converted speed value with the `speed_gbps` attribute.<br> | 1. CONFIG_DB PORT table contains speed configuration for the port.<br>2. Speed value from CONFIG_DB matches the `speed_gbps` attribute from BASE_ATTRIBUTES.<br>3. Any mismatches between configured and expected speed are identified and logged. |
| 11 | FEC configuration validation in CONFIG_DB | 1. Retrieve the `speed_gbps` attribute from BASE_ATTRIBUTES in `port_attributes_dict` for the port.<br>2. Query the PORT table in CONFIG_DB to retrieve the configured FEC mode for the port.<br>3. If port speed >= 200 Gbps, verify that FEC is set to `rs`.<br>| 1. For ports with speed >= 200 Gbps, FEC is configured as RS-FEC.<br> |

### CMIS transceiver specific test cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | CDB background mode support test | 1. Verify prerequisites: Ensure `is_non_dac_and_cmis` = True and `cdb_background_mode_supported` attribute exists in configuration.<br>2. Read EEPROM page 1, byte 0x163, bit 5 to determine hardware CDB background mode capability.<br>3. Validate bit value against expected configuration:<br>   a. If `cdb_background_mode_supported` = True: EEPROM bit 5 should be 1<br>   b. If `cdb_background_mode_supported` = False: EEPROM bit 5 should be 0 | CDB background mode support is accurately confirmed and matches configuration. Hardware capability aligns with configured expectations. Any mismatches between configuration and hardware are identified and logged for analysis. Module capabilities are properly documented. |
| 2 | CDB background mode stress test | 1. For transceivers with `cdb_background_mode_supported` = True, issue API to read CMIS CDB firmware version in a loop for 10 times.<br>2. Concurrently, keep accessing EEPROM using API and ensure that the kernel has no error logs until the 10th iteration. | CDB background mode operations complete successfully for supported transceivers without I2C errors in kernel logs. |

## Cleanup and Post-Test Verification

After test completion:

1. Verify all transceivers are in original operational state
2. Check system logs for any unexpected errors or kernel messages
3. Verify xcvrd daemon `pid` has not changed (no crashes/restarts)
4. Check for new core files that may indicate crashes
5. Document any failed tests with detailed error information and system state
