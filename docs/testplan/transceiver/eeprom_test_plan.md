# Transceiver EEPROM Test Plan

## Overview

The Transceiver EEPROM Test Plan outlines the testing strategy for the EEPROM functionality within the transceiver module. This document will cover the objectives, scope, test cases, and resources required for effective testing.

## Scope

The scope of this test plan includes the following:

- Verification of transceiver presence via sfputil and show CLI
- Validation of data integrity and consistency for transceiver basic EEPROM content
- Validation of EEPROM raw byte access via hexdump and read-eeprom CLI
- Validation of serial number format for breakout port transceivers
- Validation of VDM capability flag consistency between configured attributes and STATE_DB
- Error handling for EEPROM operations on ports without transceivers

## Optics Scope

All the optics covered in the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope)

## Testbed Topology

Please refer to the [Testbed Topology](test_plan.md#testbed-topology)

## Pre-requisites

Before executing the EEPROM tests, ensure the following pre-requisites are met:

### Setup Requirements

- The testbed is set up according to the [Testbed Topology](test_plan.md#testbed-topology)
- All the pre-requisites mentioned in [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#test-prerequisites-and-configuration-files) must be met
- `eeprom.json` is properly formatted and accessible; required attributes are defined for the transceivers under test

System health (running daemons, fresh logs, transceiver baseline) is covered by the parent's [Common Session-Level Prerequisites](test_plan.md#common-session-level-prerequisites) and [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks); see the prerequisite matrix for which gates EEPROM consumes.

## Attributes

A `eeprom.json` file is used to define the attributes for the EEPROM tests for the various types of transceivers the system supports.

The following table summarizes the key attributes used in EEPROM testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|----------------|------|---------------|-----------|-----------------|-------------|
| vdm_supported | boolean | - | O | transceivers | VDM capability support. Non-CMIS transceivers should not have this attribute present at all |
| cdb_background_mode_supported | boolean | - | O | transceivers | CDB background mode support |
| cmis_revision | string | - | O | transceivers | CMIS revision for CMIS based transceivers |
| sff8024_identifier | string | - | M | transceivers | SFF-8024 identifier for the transceiver |
| cmis_active_optical | boolean | False | O | transceivers | Whether the transceiver is a CMIS module with active optical components (i.e., not a passive DAC cable). Derived from the combination of having a CMIS management interface and active optics |
| breakout_serial_number_pattern | string | - | O | transceivers | Regex pattern to validate serial number format for breakout leaf port transceivers (e.g., ".*-A$", ".*-B$", ".*-C$" for suffix validation, or any other pattern for different placements). Used to validate that leaf-side ports on breakout modules have correctly formatted serial numbers |
| breakout_stem_serial_number_pattern | string | - | O | transceivers | Regex pattern to validate serial number format for breakout stem (main) port transceivers. Typically validates that the serial number does NOT contain leaf suffixes (e.g., "^(?!.*-[A-Z]$).*$" to ensure no suffix like -A, -B, -C). Used to validate that stem-side ports on breakout modules have correctly formatted serial numbers without leaf identifiers |
| eeprom_dump_timeout_sec | integer | 5 | O | transceivers or platform | Default EEPROM dump timeout in seconds |
| cdb_stress_iteration_count | integer | 10 | O | transceivers or platform | Number of CDB firmware version read iterations for the CDB background mode stress test |

## CLI Commands Reference

For detailed CLI commands used in the test cases below, please refer to the [CLI Commands section](test_plan.md#cli-commands) in the Transceiver Onboarding Test Infrastructure and Framework. This section provides comprehensive examples of all relevant commands.

The primary database query used in these tests is:

```bash
# STATE_DB - transceiver capability flags as parsed by xcvrd from EEPROM
sonic-db-cli STATE_DB hget 'TRANSCEIVER_INFO|<port_name>' vdm_supported
```

## Test Cases

**Assumptions for the Below Tests:**

- All the below tests will be executed for all the transceivers connected to the DUT (the port list is derived from the `port_attributes_dict`) unless specified otherwise.
- This plan inherits the [Common Session-Level Prerequisites](test_plan.md#common-session-level-prerequisites) and [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks); no additional category-wide setup or teardown is required (all EEPROM tests are read-only).

### Generic Test Cases

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Transceiver presence verification (sfputil) | 1. Use the `sfputil show presence -p <port>` command to check for transceiver presence.<br>2. Verify the output for each connected transceiver. | All connected transceivers should be listed as "Present" in the output. |
| 2 | Transceiver presence verification (show CLI) | 1. Use the `show interfaces transceiver presence` CLI to check for transceiver presence.<br>2. Verify the output for each connected transceiver. | All connected transceivers should be listed as "Present" in the output. |
| 3 | Basic EEPROM content verification via sfputil | 1. Retrieve the BASE_ATTRIBUTES and EEPROM_ATTRIBUTES from `port_attributes_dict`.<br>2. Use `sfputil show eeprom -p <port>` to dump EEPROM data.<br>3. Compare key fields (vendor name, part number, serial number, cmis revision, module hardware revision) with expected values. | 1. All key EEPROM fields match expected values from `port_attributes_dict`.<br>2. EEPROM dump completes within `eeprom_dump_timeout_sec`. |
| 4 | Basic EEPROM content verification via show CLI | 1. Retrieve the BASE_ATTRIBUTES and EEPROM_ATTRIBUTES from `port_attributes_dict`.<br>2. Use `show interfaces transceiver info <port>` CLI.<br>3. Verify key fields against expected values. | All key EEPROM fields from CLI output match expected values from `port_attributes_dict`. |
| 5 | EEPROM hexdump CLI verification | 1. Use `sfputil show eeprom-hexdump -p <port> -n 0` to retrieve lower page hexdump.<br>2. Parse hexdump for vendor name and part number.<br>3. For CMIS active optical transceivers (`cmis_active_optical` = true), use `sfputil show eeprom-hexdump -p <port> -n 0x11` to dump page 0x11.<br>4. Parse page 0x11 byte 128-133 (DataPathState for relevant lanes ranging 1 through 8) and verify all active data paths report `DataPathActivated` (value 0x55 for a 4-lane module, i.e., each 2-bit lane field = 01b). | 1. Hexdump contains expected vendor name and part number.<br>2. For non-DAC CMIS transceivers: all active data paths in page 0x11 byte 128 are in `DataPathActivated` state. Any lane not in this state is logged as a failure. |
| 6 | sfputil read-eeprom lower page verification | 1. For all transceivers, use `sfputil read-eeprom -p <port> -n 0 -o 0 -s 1` to retrieve the identifier byte from lower page offset 0 (use `--wire-addr A0h` instead of `-n 0` for SFF-8472 transceivers).<br>2. Verify the retrieved byte matches `sff8024_identifier` from `port_attributes_dict`.<br>3. Aggregate all mismatches and report at the end. | Identifier byte from lower page matches `sff8024_identifier` from `port_attributes_dict` for all transceivers. No I2C or access errors are observed. |
| 7 | sfputil read-eeprom upper page verification for non-CMIS transceivers | 1. Skip CMIS transceivers (`cmis_revision` is defined) and DAC cables (`cable_type` = "DAC"). For the remaining non-CMIS transceivers, attempt a non-zero upper page read to verify upper page access, subject to a per-family capability gate:<br>   a. For SFF-8472 transceivers: use `sfputil read-eeprom -p <port> --wire-addr A0h -o 0x5C -s 1` to read byte 92 (Diagnostic Monitoring Type). If bit 6 is `0`, DOM is not implemented - skip the upper page read for this port and log it. Otherwise, use `sfputil read-eeprom -p <port> --wire-addr A2h -o 0x60 -s 2` to read the real-time temperature (bytes 96–97 of the A2h diagnostic page) and verify the returned 2 bytes are non-zero.<br>   b. For QSFP+ non-CMIS transceivers (SFF-8436/SFF-8636): use `sfputil read-eeprom -p <port> -n 0 -o 2 -s 1` to read byte 2 (Status Indicators). If bit 2 (Flat Memory) is `1`, upper pages 1–3 are not implemented - skip the upper page read for this port and log it. Otherwise, use `sfputil read-eeprom -p <port> -n 3 -o 128 -s 2` to read the temperature high alarm threshold (SFF-8636 Table 46, Page 03h, bytes 128–129) and verify the returned 2 bytes are non-zero.<br>2. Aggregate all failures and report at the end. | 1. For SFF-8472 transceivers with DOM capability (byte 92 bit 6 = 1): 2-byte real-time temperature read from A2h offset 0x60 completes successfully and returns a non-zero value. Ports without DOM capability are skipped gracefully.<br>2. For QSFP+ non-CMIS transceivers with paged memory (byte 2 bit 2 = 0): 2-byte temperature high alarm threshold read from page 3 offset 128 (`-n 3 -o 128 -s 2`) completes successfully and returns a non-zero value. Flat-memory ports (byte 2 bit 2 = 1) are skipped gracefully.<br>3. No I2C or access errors are observed. |
| 8 | Error handling - Missing transceiver | 1. Query all physical ports from the CONFIG_DB PORT table.<br>2. Subtract ports present in `port_attributes_dict` to identify empty ports (no transceiver installed). If no empty ports exist, skip this test.<br>3. For each empty port, attempt EEPROM operations (`sfputil show eeprom -p <port>`, `show interfaces transceiver presence`, `sfputil show presence -p <port>`).<br>4. Verify each command returns an appropriate error or "Not present" message without crashing or hanging. | 1. Empty ports are correctly identified by subtracting `port_attributes_dict` from CONFIG_DB PORT table.<br>2. `sfputil show presence` reports "Not present" for each empty port.<br>3. `sfputil show eeprom` returns an error message (not a crash or timeout) for each empty port.<br>4. No I2C errors or core files are generated by operations on empty ports. |
| 9 | Serial number pattern validation for breakout ports | 1. Check if `breakout_serial_number_pattern` or `breakout_stem_serial_number_pattern` attribute is defined for the transceiver in `port_attributes_dict`.<br>2. If neither attribute is defined, skip this test for the port.<br>3. If `breakout_serial_number_pattern` is defined (leaf port):<br>   a. Use `sfputil show eeprom -p <port>` to retrieve the serial number.<br>   b. Log the retrieved serial number for debugging purposes.<br>   c. Based on the leaf or stem side, validate that the serial number matches the regex pattern from `breakout_serial_number_pattern` or `breakout_stem_serial_number_pattern` attribute.<br> | 1. Test is executed only when `breakout_serial_number_pattern` or `breakout_stem_serial_number_pattern` attribute is present.<br>2. Serial number is successfully retrieved and logged.<br>3. For leaf ports: Serial number matches the expected regex pattern (e.g., `".*-A$" for leaf A, ".*-B$" for leaf B`)<br>4. For stem ports: Serial number matches the stem pattern (typically validates absence of leaf suffixes like -A, -B, -C).<br>5. Test is skipped gracefully for ports without either attribute defined. |
| 10 | VDM support flag consistency between attribute and STATE_DB | 1. Retrieve the `vdm_supported` attribute from EEPROM_ATTRIBUTES in `port_attributes_dict` for the port.<br>2. If `vdm_supported` is absent, skip the port.<br>3. Query `sonic-db-cli STATE_DB hget 'TRANSCEIVER_INFO\|<port>' vdm_supported` to retrieve the value parsed by xcvrd from the transceiver EEPROM.<br>4. Compare the configured attribute value against the STATE_DB value.<br>5. Aggregate all mismatches and report at the end. | 1. STATE_DB TRANSCEIVER_INFO table contains a `vdm_supported` field for the port.<br>2. The `vdm_supported` value in STATE_DB matches the configured attribute, confirming that xcvrd correctly parsed and published the VDM capability from the transceiver EEPROM.<br>3. Any mismatches between the configured attribute and STATE_DB are identified and logged wherein a mismatch indicates either a misconfigured attribute or a transceiver that is misreporting its VDM capability. |

### CMIS transceiver specific test cases

> **Note:** CMIS TC 2 performs concurrent EEPROM reads in a loop. The framework's post-test log inspection is especially important here — kernel I2C errors during that test indicate a CDB background mode failure.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | CDB background mode support test | 1. Verify prerequisites: Ensure `cmis_active_optical` = True and `cdb_background_mode_supported` attribute exists in configuration.<br>2. Read EEPROM page 1, byte 0x163, bit 5 to determine hardware CDB background mode capability.<br>3. Validate bit value against expected configuration:<br>   a. If `cdb_background_mode_supported` = True: EEPROM bit 5 should be 1<br>   b. If `cdb_background_mode_supported` = False: EEPROM bit 5 should be 0 | CDB background mode support is accurately confirmed and matches configuration. Hardware capability aligns with configured expectations. Any mismatches between configuration and hardware are identified and logged for analysis. Module capabilities are properly documented. |
| 2 | CDB background mode stress test | 1. For transceivers with `cdb_background_mode_supported` = True, issue API to read CMIS CDB firmware version in a loop for `cdb_stress_iteration_count` iterations (default: 10).<br>2. Concurrently, keep accessing EEPROM using API and ensure that the kernel has no error logs throughout all iterations. | CDB background mode operations complete successfully for all `cdb_stress_iteration_count` iterations for supported transceivers without I2C errors in kernel logs. |

## Cleanup and Post-Test Verification

The following steps are performed once after **all test cases** in this plan have completed. The [Common Per-Test Health Checks](test_plan.md#common-per-test-health-checks) already cover ongoing health monitoring throughout the run.

### Post-Test Report Generation

1. **Test Summary**: Generate comprehensive test results including pass/fail status for each test case.
2. **EEPROM Access Analysis**: Document any EEPROM read errors, I2C failures, or timeout violations (against `eeprom_dump_timeout_sec`) observed during the test run.
3. **Mismatch Report**: Summarize all attribute mismatches detected (sff8024_identifier, vdm_supported, serial number patterns) with actual vs. expected values and the port where the mismatch occurred.
