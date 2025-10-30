# Transceiver EEPROM Test Plan

## Overview

The Transceiver EEPROM Test Plan outlines the testing strategy for the EEPROM functionality within the transceiver module. This document will cover the objectives, scope, test cases, and resources required for effective testing.

## Scope

The scope of this test plan includes the following:

- Verification of EEPROM read and write operations
- Validation of data integrity and consistency for transceiver basic EEPROM content
- Testing of EEPROM access times and performance

## Optics Scope

All the optics covered in the parent [transceiver onboarding test plan](../transceiver_onboarding_test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](../transceiver_onboarding_test_plan.md#testbed-topology)

## Pre-requisites

Before executing the EEPROM tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](../transceiver_onboarding_test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](../transceiver_onboarding_test_plan.md#test-cases) must be met

## Attributes

A `eeprom.json` file is used to define the attributes for the EEPROM tests for the various types of transceivers the system supports.

The following table summarizes the key attributes used in EEPROM testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| dual_bank_supported | boolean | - | ✓ | transceivers | Whether transceiver supports dual bank firmware |
| vdm_supported | boolean | False | ✗ | transceivers | VDM capability support |
| cdb_background_mode_supported | boolean | - | ✗ | transceivers | CDB background mode support |
| gold_firmware_version | string | - | ✗ | transceivers | Expected gold/reference firmware version for validation. This also represents the active firmware version. This attribute is applicable only for modules with CMIS CDB firmware. |
| inactive_firmware_version | string | - | ✗ | transceivers | Expected inactive bank firmware version for dual-bank CMIS CDB modules during validation |
| cmis_revision | string | - | ✗ | transceivers | CMIS revision for CMIS based transceivers |
| sff8024_identifier | string | - | ✓ | transceivers | SFF-8024 identifier for the transceiver |
| is_non_dac_and_cmis | boolean | False | ✗ | transceivers | Whether the transceiver is a non-DAC CMIS transceiver |
| eeprom_dump_timeout_sec | integer | 5 | ✗ | transceivers or platform | Default EEPROM dump timeout in seconds |

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](../transceiver_onboarding_test_plan.md#cli-commands) in the transceiver onboarding test plan. This section provides comprehensive examples of all relevant commands

## Test Cases

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.

### Generic Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Transceiver presence verification (sfputil) | 1. Use the `sfputil show presence` command to check for transceiver presence.<br>2. Verify the output for each connected transceiver. | All connected transceivers should be listed as "Present" in the output. |
| 2 | Transceiver presence verification (show CLI) | 1. Use the `show interfaces transceiver presence` CLI to check for transceiver presence.<br>2. Verify the output for each connected transceiver. | All connected transceivers should be listed as "Present" in the output. |
| 3 | Basic EEPROM content verification via sfputil | 1. Retrieve the BASE_ATTRIBUTES and EEPROM_ATTRIBUTES from `port_attributes_dict`.<br>2. Use `sfputil show eeprom <port>` to dump EEPROM data.<br>3. Compare key fields (vendor name, part number, serial number, cmis revision, module hardware revision) with expected values. | 1. All key EEPROM fields matches expected values from `port_attributes_dict`.<br>2. EEPROM dump completes within `eeprom_dump_timeout_sec`. |
| 4 | Basic EEPROM content verification via show CLI | 1. Retrieve the BASE_ATTRIBUTES and EEPROM_ATTRIBUTES from `port_attributes_dict`.<br>2. Use `show interfaces transceiver info <port>` CLI.<br>3. Verify key fields against expected values. | All key EEPROM fields from CLI output match expected values from `port_attributes_dict`. |
| 5 | Firmware version validation | 1. For transceivers with `gold_firmware_version` attribute, use `sfputil show firmware version <port>`.<br>2. If `dual_bank_supported` is true, verify both active and inactive firmware versions.<br>3. Compare with expected values from attributes. | Active and inactive firmware versions match corresponding values in attributes dictionary. |
| 6 | EEPROM hexdump CLI verification | 1. Use `sfputil show eeprom-hexdump <port>` to retrieve hexdump.<br>2. For non-DAC CMIS transceivers (`is_non_dac_and_cmis` = true), dump page 0x11.<br>3. Parse hexdump for vendor name and part number. | 1. Hexdump contains expected vendor name and part number.<br>2. Non-DAC CMIS transceivers show DPActivated state in page 0x11. |
| 7 | sfputil read-eeprom CLI verification | 1. Use the `sfputil read-eeprom` to retrieve data from offset 0 from lower page or A0h (SFF-8472 transceivers) | Retrieved data matches the value of `sff8024_identifier` from `port_attributes_dict`. |
| 8 | Error handling - Missing transceiver | 1. Attempt EEPROM operations on ports without transceivers.<br>2. Verify error messages.<br>3. Test both sfputil and show CLI commands. | Commands return appropriate messages indicating transceiver absence. |

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
