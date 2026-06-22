# CMIS CDB Firmware Upgrade Test Plan

## Overview

The CMIS CDB Firmware Upgrade Test Plan outlines the testing strategy for firmware upgrade and downgrade operations on CMIS-compliant transceivers in SONiC. This document covers the scope, pre-requisites, test cases, and attributes for firmware testing. The future goal is to automate all the tests in this document.

## Scope

The scope of this test plan includes the following:

- Firmware download, run, and commit validation
- Firmware version verification against expected gold and inactive versions
- Firmware download interruption and CDB abort handling
- EEPROM static field integrity during firmware operations
- Firmware download, activation, and read stress testing
- Validating invalid firmware binary rejection

**Optics Scope:**

All the optics covered in the parent [Transceiver Onboarding Test Infrastructure and Framework](test_plan.md#scope).

**Optics Specifications:**

Tests will cover optics compliant with:

- CMIS
- C-CMIS

**Module Bank Support:**

This test plan covers both **dual-bank** and **single-bank** transceivers. For single-bank transceivers, inactive firmware image checks are not applicable.

## Testbed Topology

Please refer to the [Testbed Topology](./test_plan.md#testbed-topology) section in the parent transceiver onboarding test plan.

## Pre-requisites

1. All the pre-requisites mentioned in [Transceiver Onboarding Test Infrastructure and Framework](./test_plan.md#test-prerequisites-and-configuration-files) must be met.

2. A `cdb_firmware_binaries.json` file (located in `ansible/files/transceiver/inventory` directory) should exist if a transceiver being tested supports CMIS CDB firmware upgrade. This file will capture the firmware binary metadata for the transceiver. Each transceiver should have at least 2 firmware binaries so that firmware upgrade can be tested. The file should follow this format:

```json
{
    "<NORMALIZED_VENDOR_NAME>": {
        "<NORMALIZED_VENDOR_PN>": {
            "<fw_version_1>": {
                "fw_binary_name": "<firmware_binary_filename_1>",
                "md5sum": "<md5sum_1>"
            },
            "<fw_version_2>": {
                "fw_binary_name": "<firmware_binary_filename_2>",
                "md5sum": "<md5sum_2>"
            }
        }
    }
}
```

The JSON structure is keyed by:

- **Top-level key** (`normalized_vendor_name`): The normalized vendor name, created by applying the normalization rules described in the [Vendor Name and Part Number Normalization Rules](./test_plan.md#vendor-name-and-part-number-normalization-rules) section of the parent test plan.
- **Second-level key** (`normalized_vendor_pn`): The normalized vendor part number, created by applying the normalization rules described in the [Vendor Name and Part Number Normalization Rules](./test_plan.md#vendor-name-and-part-number-normalization-rules) section of the parent test plan.
- **Third-level key** (`fw_version`): The version of the firmware.
- **`fw_binary_name`**: The filename of the firmware binary.
- **`md5sum`**: The MD5 checksum of the firmware binary.

3. A `cdb_firmware_base_url.json` file (located in `ansible/files/transceiver/inventory` directory) should be present to define the base URL for downloading CMIS CDB firmware binaries. The file should follow this format:

```json
{
    "<inv_name>": "<fw_base_url>"
}
```

- **Key** (`inv_name`): The name of the inventory file that contains the definition of the target DUTs. For further details, please refer to the [Inventory File](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.new.testbed.Configuration.md#inventory-file). The `inv_name` allows DUTs to be grouped based on their inventory file, enabling the test framework to fetch the correct base URL for firmware downloads.
- **Value** (`fw_base_url`): The base URL from which the CMIS CDB firmware binaries can be downloaded. This URL should point to the directory where the firmware binaries are stored. e.g., `http://1.2.3.4/cmis_cdb_firmware`.

Example of the file:

```json
{
    "lab": "http://1.2.3.4/cmis_cdb_firmware"
}
```

## Attributes

A `cdb_firmware_upgrade.json` file is used to define the attributes for the CDB firmware upgrade tests for the various types of transceivers the system supports. The category attributes are stored under `attributes/cdb_firmware_upgrade/`. Per-PN body contains transceiver specific defaults, while DUT specific overrides are defined in the category-level shard; see [File Organization](test_plan.md#file-organization) for the shard contract.

The following table summarizes the key attributes used in CDB firmware upgrade testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|-----------|------|---------|-----------|-------------|-------------|
| port_under_test | List | All | O | dut | A list under `dut.dut_name` containing the ports to be tested for CMIS FW upgrade test only. This attribute must exist only under `dut` field. |
| firmware_versions | List | None | M | transceivers | A list containing firmware versions to be tested. The last value in the list represents the final active firmware version after the test is completed. |
| firmware_download_timeout_minutes | Int | 30 | O | transceivers | Maximum time in minutes to wait for a firmware download to complete. |
| restore_initial_inactive_firmware | Bool | False | O | dut | A flag indicating whether to restore the initial inactive firmware version after testing is completed. |
| firmware_download_stress_iterations | Int | 5 | O | dut | The number of iterations to stress test the firmware download process. |
| firmware_activation_stress_iterations | Int | 5 | O | dut | The number of iterations to stress test the firmware activation process. |
| firmware_read_stress_iterations | Int | 5 | O | dut | The number of iterations to stress test the firmware read process. |
| firmware_download_interrupt_method | String | "sigkill" | O | transceivers | The method used to interrupt the firmware download process. Must be one of the following: "sigkill", "sfputil_reset". |
| firmware_download_interrupt_percentage | List | [10, 30, 50, 90] | O | transceivers | The percentage of download progress at which the firmware download should be interrupted. |
| firmware_download_cdb_abort_support | Bool | - | O | transceivers | A flag indicating whether the transceiver supports CDB abort during firmware download. |
| sleep_after_dom_disable_sec | Int | 5 | O | transceivers | The number of seconds to sleep after disabling DOM monitoring before proceeding with the test. |
| thermalctld_disabling_required | Bool | False | O | transceivers or Platform-level | A flag indicating whether to disable `thermalctld` during the test. |
| dual_bank_supported | Bool | True | O | transceivers | Whether the transceiver supports dual-bank firmware. Used to determine if both active and inactive firmware versions should be validated. |
| gold_firmware_version | String | - | M | transceivers | The expected active/gold firmware version for modules. Used as the baseline reference for firmware version validation. |
| inactive_firmware_version | String | - | O | transceivers | The expected inactive bank firmware version for dual-bank modules. Mandatory only when `dual_bank_supported` is true. |

> **Note:** The `transceiver_reset_i2c_recover_sec` and `port_startup_wait_sec` attributes are defined in the [System test attributes](system_test_plan.md#attributes) and are reused here for I2C recovery wait after reset and link-up timeout after firmware activation respectively. The `cdb_background_mode_supported` and `firmware_download_cdb_abort_support` attributes are CMIS feature-advertisement flags and are always **auto-detected from the EEPROM at runtime**. If either attribute is also set in the per-PN shard and the value differs from the EEPROM register, the test fails with an error. `cdb_background_mode_supported` is also defined in the [EEPROM test attributes](eeprom_test_plan.md#attributes), where the EEPROM test cross-validates the configured value against EEPROM.

> **Attribute invariants:** `gold_firmware_version` must equal `firmware_versions[-1]`, and (when `dual_bank_supported` is true) `inactive_firmware_version` must equal `firmware_versions[-2]`. Validated by the per-category prerequisite check at session start (see [Cross-Category Prerequisite Tests and Health Checks](./test_plan.md#cross-category-prerequisite-tests-and-health-checks)); a mismatch skips the CDB firmware test suite with a clear configuration error.

## CMIS CDB Firmware Binary Management

### Firmware Binary Naming Guidelines

CMIS CDB firmware binaries must follow strict naming conventions to ensure compatibility across different filesystems and automation tools.

**Filename Requirements:**

1. **Character Restrictions:**
   - **Must not** contain spaces or special characters except hyphens (`-`), dots (`.`), and underscores (`_`)
   - Must be valid filenames for Windows, Linux, and macOS filesystems
   - Avoid reserved characters: `< > : " | ? * \ /`
   - Ensure that the filename does not start or end with special characters

2. **File Extension:**
   - Use `.bin` extension

### Vendor Name and Part Number Normalization

The `<NORMALIZED_VENDOR_NAME>` and `<NORMALIZED_VENDOR_PART_NUMBER>` segments used in the directory layout and binary filenames below are produced by the shared normalization rules defined in the parent test plan (see [Vendor Name and Part Number Normalization Rules](./test_plan.md#vendor-name-and-part-number-normalization-rules)). All firmware-binary paths and filenames in this document must use values produced by those rules.

## Firmware Binary Storage on SONiC Device

The CMIS CDB firmware binaries are stored under `/tmp/cmis_cdb_firmware/` on the SONiC device, organized by normalized vendor name, part number and firmware version number.

**Directory Structure Requirements:**

```text
/tmp/cmis_cdb_firmware/
├── <NORMALIZED_VENDOR_NAME>/
│   └── <NORMALIZED_VENDOR_PART_NUMBER>/
│       └── <FIRMWARE_VERSION_NUMBER>/
│           └── FIRMWARE_BINARY_1.bin
└── ...
```

**Requirements:**

- All directory and file names **must be uppercase** and follow the [Vendor Name and Part Number Normalization Rules](./test_plan.md#vendor-name-and-part-number-normalization-rules)
- Use the `GENERIC_N_END` placeholder for cable lengths as described in the normalization rules

**Example Directory Structure:**

```text
/tmp/cmis_cdb_firmware/
├── ACME_CORP/
│   └── QSFP-100G-AOC-GENERIC_2_ENDM/
│       └── 1.2.3/
│           └── ACME_CORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.3.bin
│       └── 1.2.4/
│           └── ACME_CORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
├── EXAMPLE_INC/
│   └── QSFP_200G_LR4/
│       └── 2.0.1/
│           └── EXAMPLE_INC_QSFP_200G_LR4_2.0.1.bin
└── ...
```

## Firmware Binary Storage on Remote Server

The CMIS CDB firmware binaries must be stored on a remote server with the following requirements:

**Server Organization:**

- Directory structure should mirror the SONiC device structure described above
- Server must be accessible via HTTP/HTTPS protocols
- Base URL configuration is defined in `cdb_firmware_base_url.json`

**Base URL Configuration:**
The `cdb_firmware_base_url.json` file contains the mapping between inventory files and their corresponding firmware download URLs:

```json
{
    "lab": "http://firmware-server.example.com/cmis_cdb_firmware",
    "production": "https://secure-firmware.example.com/cmis_cdb_firmware"
}
```

> Note: The `fw_base_url` should not end with a trailing slash (`/`). The test framework will append the necessary path components based on the normalized vendor name, part number and firmware version number.

**Download URL Format:**

Firmware binaries are accessed using the following URL pattern:

```text
<fw_base_url>/<NORMALIZED_VENDOR_NAME>/<NORMALIZED_VENDOR_PART_NUMBER>/<FIRMWARE_VERSION_NUMBER>/<FIRMWARE_BINARY_NAME>
```

**Example:**

```text
http://firmware-server.example.com/cmis_cdb_firmware/ACME_CORP/QSFP-100G-AOC-GENERIC_2_ENDM/1.2.4/ACME_CORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
```

## CMIS CDB Firmware Copy to DUT via sonic-mgmt Infrastructure

This section describes the automated process for copying firmware binaries to the DUT, ensuring only the required firmware versions are present for testing.

**Firmware Selection Algorithm:**

To ensure only the necessary firmware binaries are present for each transceiver:

1. **Use `port_attributes_dict`** (built from `dut_info/<dut_hostname>.json`) to identify the transceivers present on the DUT. If `port_under_test` attribute is specified, only those ports are considered. The normalized vendor name and part number are available in `BASE_ATTRIBUTES`.
2. **Parse `firmware_versions` test attribute** from `CDB_FIRMWARE_UPGRADE_ATTRIBUTES` to get the firmware versions to download for the transceiver type.
3. **Parse `cdb_firmware_binaries.json`** to obtain the firmware binary metadata (filename, md5sum) for each version specified in step 2. If the firmware version exists for the normalized vendor name and part number from step 1:
   - Copy the selected firmware binaries to the target directory structure on the DUT.
   - Validate firmware binary integrity using MD5 checksums after copying.

Fail the test if the specified firmware version doesn't exist in `cdb_firmware_binaries.json`.

## Test Cases

**Requirements for firmware upgrade tests:**

1. **DOM polling must be disabled** to prevent race conditions between I2C transactions and the CDB mode for modules that do not support CDB background mode. The test should wait for `sleep_after_dom_disable_sec` seconds after disabling DOM to avoid the race condition.
2. **Platform-specific processes:** On some platforms, `thermalctld` or similar user processes that perform I2C transactions with the module may need to be stopped if the `thermalctld_disabling_required` flag is set.
3. **Firmware requirements:**
   - The firmware version specified by `firmware_versions` test attribute must be available.
   - All firmware versions must support the CDB protocol for proper testing.
4. **Module capabilities:** The module must support CMIS CDB firmware operations. For dual-bank specific checks, `dual_bank_supported` must be true.
5. **Network connectivity:** The DUT must have network access to the firmware server specified in `cdb_firmware_base_url.json` for downloading firmware binaries.
6. **Link state:** The port should be operationally up before firmware download starts and should remain operationally up during and after the firmware download/commit with no link flaps observed during the process.

**Common Verification Procedures:**

These tests rely on the shared transceiver test infrastructure checks for test case verification:

1. **Process health and core files** are covered by the autouse [Common Per-Test Health Checks](./test_plan.md#common-per-test-health-checks) fixture, which runs before and after every transceiver test. It verifies `xcvrd` is `RUNNING` with an unchanged PID and scans `/var/core/` for new core files.
2. **Kernel and I2C errors in syslog** are covered by the `loganalyzer` fixture used by the transceiver test suite, which scans syslog per test and fails on unexpected matches. Individual CDB firmware tests should only add `ignore_regex` entries for *expected* noise produced by their specific firmware operation.
3. **I2C error treatment is gated by `cdb_background_mode_supported`**. Tests must apply the following truth table when configuring `loganalyzer` for the firmware-operation window:

| cdb_background_mode_supported | Expected Behaviour | Treatment |
|---|---|---|
| True | EEPROM should remain accessible while CDB is active | Any I2C error match then test fails. |
| False | Expected transient noise while DOM polling is disabled and CDB is active | Add `ignore_regex` for the known I2C error patterns. Patterns outside the window remain a failure. |

**Timing Requirements:**

For firmware download, run, and commit operations, the test framework must report the command execution time to the test logs/report. This enables performance tracking across firmware versions and transceiver types.

**Composite test case recovery:** TC #7, TC #10, and TC #11 do multiple sub-operations. On any sub step failure the test case fails immediately, and the framework restores the module to gold so the next test case starts from a known state.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Firmware download validation | 1. Start firmware download of the next firmware specified in `firmware_versions` using `sfputil firmware download <port>`.<br>2. Wait until CLI execution completes. | 1. The CLI command should complete within `firmware_download_timeout_minutes` minutes and return 0.<br>2. Active FW version should remain unchanged.<br>3. If `dual_bank_supported` is true, inactive FW version should reflect the downloaded firmware version.<br>4. Running image remains the same.<br>5. Committed image remains the same.<br>6. No link flap should be seen. |
| 2 | Firmware run validation | 1. Shut down all interfaces that are part of the physical port.<br>2. Execute firmware run.<br>3. Reset the transceiver and wait for `transceiver_reset_i2c_recover_sec` seconds.<br>4. Startup all the interfaces in Step 1. | 1. Firmware run command should finish within 60 seconds and the return code should be 0 (Return code 0 indicates success).<br>2. If `dual_bank_supported` is true, active firmware version should now match the previous inactive firmware version.<br>3. If `dual_bank_supported` is true, inactive firmware version should now match the previous active firmware version.<br>4. If `dual_bank_supported` is false, active firmware version should match the firmware selected for activation and inactive firmware checks are not applicable.<br>5. Link should be up within `port_startup_wait_sec` seconds.<br>6. `sfputil show fwversion <port>` CLI should now show the "Running Image" as the current active bank.<br>7. If `dual_bank_supported` is true, previous active firmware should show up in the inactive bank. |
| 3 | Firmware commit validation | 1. Execute firmware commit for an interface. | 1. Firmware commit command should finish within 60 seconds and the return code should be 0.<br>2. Active firmware version remains unchanged.<br>3. If `dual_bank_supported` is true, inactive firmware version remains unchanged.<br>4. Committed image is updated to the running/active firmware image.<br>5. No link flap is seen. |
| 4 | Firmware download validation with invalid firmware binary | Download an invalid firmware binary (e.g., a zero-filled or truncated file not released by the vendor). | 1. The CLI command should return a non-zero exit code.<br>2. The active firmware version does not change.<br>3. If `dual_bank_supported` is true, the inactive firmware version remains unchanged or is set to `0.0.0` or `N/A`.<br>4. No change in "Committed Image".<br>5. Running image remains unchanged.<br>6. No link flap should be seen. |
| 5 | Abrupt firmware download interruption | 1. Start the firmware download and interrupt at the percentages specified by `firmware_download_interrupt_percentage`.<br>2. Use the method specified in `firmware_download_interrupt_method` to interrupt the process.<br><br>**Note:** This test runs regardless of `firmware_download_cdb_abort_support`. After SIGKILL on a non-abort module, explicit recovery (e.g. `sfputil reset`) is required before the next download. | 1. Active firmware version remains unchanged.<br>2. If `dual_bank_supported` is true, inactive firmware version is invalid i.e. N/A or 0.0.0.<br>3. No change in "Committed Image".<br>4. Running image remains unchanged.<br>5. No link flap should be seen. |
| 6 | Graceful CDB abort of firmware download |1. Start the firmware download and, mid-download, issue the CMIS CDB abort command. | 1. Advertisement register for CDB abort is set (sanity check of the gating attribute).<br>2. CDB abort command should be successful.<br>3. Active firmware version remains unchanged.<br>4. If `dual_bank_supported` is true, inactive firmware version is invalid i.e. N/A or 0.0.0.<br>5. No change in "Committed Image".<br>6. Running image remains unchanged.<br>7. No link flap should be seen. |
| 7 | Successful firmware download after interruption | 1. Perform steps in TC #5 to leave the module in a post-interrupt state.<br>2. If `firmware_download_cdb_abort_support` is set, run the CDB abort command to clear any residual CDB state.<br>3. If `firmware_download_cdb_abort_support` is not set, recover the module from the post-interrupt state via `sfputil reset <port>` (and wait `transceiver_reset_i2c_recover_sec` seconds) so the CDB state machine returns to idle.<br>4. Perform steps in TC #1. | 1. All expectations of TC #5 must be met after step 1.<br>2. If executed, the CDB abort command (step 2) should be successful.<br>3. If executed, the `sfputil reset` command (step 3) should succeed and the module should be reachable after the recovery wait.<br>4. All expectations of TC #1 must be met after step 4. |
| 8 | Firmware download validation post reset | 1. Perform steps in TC #1.<br>2. Execute `sfputil reset <port>` and wait `transceiver_reset_i2c_recover_sec` seconds for it to finish. | All expectations of TC #1 must be met. |
| 9 | Ensure static fields of EEPROM remain unchanged | 1. Perform steps in TC #1.<br>2. Perform steps in TC #2. | 1. All the expectations of TC #1 and #2 must be met.<br>2. Ensure after each step 1 and 2 that the static fields of EEPROM (e.g., vendor name, part number, serial number, vendor date code, OUI, and hardware revision) remain unchanged. |
| 10 | Firmware download stress test | 1. Perform steps in TC #1 `firmware_download_stress_iterations` number of times. | 1. All the expectations of TC #1 must be met for each iteration. |
| 11 | Firmware activation stress test | 1. Perform steps in TC #1, #2, and #3 `firmware_activation_stress_iterations` number of times. | 1. All the expectations of TC #1, #2, and #3 must be met for each iteration. |
| 12 | Firmware read stress test | 1. Perform `sfputil show fwversion <port>` CLI command `firmware_read_stress_iterations` number of times. | 1. The return code is 0.<br>2. All reported fields remain unchanged across iterations.<br>3. Active firmware version is consistent across all iterations.<br>4. If `dual_bank_supported` is true, inactive firmware version is consistent across all iterations. |
| 13 | Firmware version baseline validation | **Runs first** in the CDB firmware test sequence as a baseline check that the module starts on gold. <br><br>1. Use `sfputil show fwversion <port>`.<br>2. If `dual_bank_supported` is true, read both active and inactive firmware versions.<br>3. Compare with expected values from attributes. | 1. Active firmware version matches `gold_firmware_version` attribute value.<br>2. If `dual_bank_supported` is true, inactive firmware version matches `inactive_firmware_version` attribute value. |

### Cleanup

- If `restore_initial_inactive_firmware` is true, the inactive firmware version recorded before testing began is restored via firmware download only if it is present in `cdb_firmware_binaries.json`.
- The firmware binary folder on the DUT (`/tmp/cmis_cdb_firmware/`) will be deleted after the test module run is complete to ensure a clean state for subsequent tests
- Cleanup includes removing both the directory structure and any temporary files created during the process

## CLI Commands Reference

Refer to [CLI commands](./test_plan.md#cli-commands) section for the CLI commands used in the above test cases.
