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

2. A `transceiver_firmware_info.json` file (located in `ansible/files/transceiver/inventory` directory) should exist if a transceiver being tested supports CMIS CDB firmware upgrade. This file will capture the firmware binary metadata for the transceiver. Each transceiver should have at least 2 firmware binaries so that firmware upgrade can be tested. The file should follow this format:

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

- **Top-level key** (`normalized_vendor_name`): The normalized vendor name, created by applying the normalization rules described in the [Normalization Rules for Vendor Name and Part Number](#normalization-rules-for-vendor-name-and-part-number) section.
- **Second-level key** (`normalized_vendor_pn`): The normalized vendor part number, created by applying the normalization rules described in the [Normalization Rules for Vendor Name and Part Number](#normalization-rules-for-vendor-name-and-part-number) section.
- **Third-level key** (`fw_version`): The version of the firmware.
- **`fw_binary_name`**: The filename of the firmware binary.
- **`md5sum`**: The MD5 checksum of the firmware binary.

3. A `cmis_cdb_firmware_base_url.json` file (located in `ansible/files/transceiver/inventory` directory) should be present to define the base URL for downloading CMIS CDB firmware binaries. The file should follow this format:

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
| firmware_download_interrupt_method | String | "sfputil_reset" | O | transceivers | The method used to interrupt the firmware download process. Must be one of the following: "ctrl_c", "sfputil_reset". |
| firmware_download_interrupt_percentage | List | [10, 30, 50, 90] | O | transceivers | The percentage of download progress at which the firmware download should be interrupted. |
| firmware_download_cdb_abort_support | Bool | - | O | transceivers | A flag indicating whether the transceiver supports CDB abort during firmware download. |
| sleep_after_dom_disable_sec | Int | 5 | O | transceivers | The number of seconds to sleep after disabling DOM monitoring before proceeding with the test. |
| monitor_kernel_errors | Bool | False | O | transceivers | A flag indicating whether to monitor kernel errors during the test. |
| thermalctld_disabling_required | Bool | False | O | transceivers | A flag indicating whether to disable `thermalctld` during the test. |
| dual_bank_supported | Bool | True | O | transceivers | Whether the transceiver supports dual-bank firmware. Used to determine if both active and inactive firmware versions should be validated. |
| gold_firmware_version | String | - | M | transceivers | The expected active/gold firmware version for modules. Used as the baseline reference for firmware version validation. |
| inactive_firmware_version | String | - | O | transceivers | The expected inactive bank firmware version for dual-bank modules. Mandatory only when `dual_bank_supported` is true. |

> **Note:** The `transceiver_reset_i2c_recover_sec` and `port_startup_wait_sec` atttributes are defined in the [System test attributes](system_test_plan.md#attributes) and are reused here for I2C recovery wait after reset and link-up timeout after firmware activation respectivelty. The `cdb_background_mode_supported` attribute is defined in the [EEPROM test attributes](eeprom_test_plan.md#attributes) and is read at runtime to determine whether I2C error checks should be performed during firmware operations. The `firmware_download_cdb_abort_support` attribute is always read from the EEPROM at runtime. If the attribute is also set in the per-PN shard and the value differs from the EEPROM register, the test fails with an error.

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

#### Normalization Rules for Vendor Name and Part Number

To ensure compatibility and uniqueness across filesystems and automation tools, the following normalization rules should be applied to vendor names and part numbers:

> **Important Note:** These normalization rules are designed for test framework consumption and firmware binary storage organization. They are **not** applied to the actual transceiver EEPROM data, which remains unchanged.

**Core Normalization Rules:**

1. **Character Replacement:**
   - Preserve hyphens (`-`) and underscores (`_`) as they are filesystem-safe
   - Replace all other non-alphanumeric characters (spaces, `/`, `.`, `&`, `#`, `@`, `%`, `+`, etc.) with underscores (`_`)
   - Handle consecutive special characters by replacing sequences with a single underscore

2. **Cable Length Normalization:**
   - **Purpose:** Standardize part numbers that differ only by cable length to enable firmware sharing across length variants
   - **Replacement Format:** `GENERIC_N_END<UNIT>` where `N` = number of digits in the original length
   - **Preservation:** Non-unit suffixes after length are preserved (e.g., `10YY` → `GENERIC_2_ENDYY`)

   **Cable Length Examples:**

   | Original Part Number         | Normalized Part Number                  | Explanation |
   |-----------------------------|-----------------------------------------|-------------|
   | QSFP-100G-AOC-15M           | QSFP-100G-AOC-GENERIC_2_ENDM            | 15 has 2 digits, M unit preserved |
   | QSFP-100G-AOC-10YY          | QSFP-100G-AOC-GENERIC_2_ENDYY           | 10 has 2 digits, YY suffix preserved |
   | QSFP-100G-AOC-100           | QSFP-100G-AOC-GENERIC_3_END             | 100 has 3 digits, no unit |
   | QSFP-100G-AOC-3M            | QSFP-100G-AOC-GENERIC_1_ENDM            | 3 has 1 digit, M unit preserved |
   | SFP-1000M                   | SFP-GENERIC_4_ENDM                      | 1000 has 4 digits, M unit preserved |

3. **Cleanup and Formatting:**
   - Remove leading and trailing underscores
   - Replace multiple consecutive underscores with a single underscore
   - Convert the entire result to uppercase for consistency

4. **Usage:**
   - Use normalized names for directory structures and firmware binary organization
   - Enable firmware inventory management across cable length variants
   - Ensure cross-platform filesystem compatibility

**Vendor Name Examples:**

| Original Vendor Name    | Normalized Vendor Name | Explanation |
|------------------------|------------------------|-------------|
| ACME Corp.             | ACME_CORP              | Space and dot replaced with underscore |
| Example & Co           | EXAMPLE_CO             | Ampersand and space replaced |
| Vendor/Inc             | VENDOR_INC             | Slash replaced with underscore |
| Multi___Underscore     | MULTI_UNDERSCORE       | Multiple underscores consolidated |

Sample script to normalize vendor name and part number (script assumes that the length is already replaced with `GENERIC_N_END`):

```python
import re
def normalize_vendor_field(field: str) -> str:
    """
    Normalize vendor name or part number according to the rules:
    - Except for '-' and '_', all non-alphanumeric characters are replaced with '_'
    - Replace any sequence of '_' with a single '_'
    - Remove leading/trailing underscores
    - Convert the result to uppercase
    - Hyphens are preserved
    """
    # Replace all non-alphanumeric except '-' and '_' with '_'
    field = re.sub(r"[^\w\-]", "_", field)
    # Replace multiple consecutive '_' with single '_'
    field = re.sub(r"_+", "_", field)
    # Remove leading/trailing underscores
    field = field.strip("_")
    # Convert to uppercase
    return field.upper()
```

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

- All directory and file names **must be uppercase** and follow the [Normalization Rules for Vendor Name and Part Number](#normalization-rules-for-vendor-name-and-part-number)
- Use the `GENERIC_N_END` placeholder for cable lengths as described in the normalization rules

**Example Directory Structure:**

```text
/tmp/cmis_cdb_firmware/
├── ACMECORP/
│   └── QSFP-100G-AOC-GENERIC_2_ENDM/
│       └── 1.2.3/
│           └── ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.3.bin
│       └── 1.2.4/
│           └── ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
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
- Base URL configuration is defined in `cmis_cdb_firmware_base_url.json`

**Base URL Configuration:**
The `cmis_cdb_firmware_base_url.json` file contains the mapping between inventory files and their corresponding firmware download URLs:

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
http://firmware-server.example.com/cmis_cdb_firmware/ACMECORP/QSFP-100G-AOC-GENERIC_2_ENDM/1.2.4/ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
```

## CMIS CDB Firmware Copy to DUT via sonic-mgmt Infrastructure

This section describes the automated process for copying firmware binaries to the DUT, ensuring only the required firmware versions are present for testing.

**Firmware Selection Algorithm:**

To ensure only the necessary firmware binaries are present for each transceiver:

1. **Use `port_attributes_dict`** (built from `dut_info/<dut_hostname>.json`) to identify the transceivers present on the DUT. If `port_under_test` attribute is specified, only those ports are considered. The normalized vendor name and part number are available in `BASE_ATTRIBUTES`.
2. **Parse `firmware_versions` test attribute** from `CDB_FIRMWARE_UPGRADE_ATTRIBUTES` to get the firmware versions to download for the transceiver type.
3. **Parse `transceiver_firmware_info.json`** to obtain the firmware binary metadata (filename, md5sum) for each version specified in step 2. If the firmware version exists for the normalized vendor name and part number from step 1:
   - Copy the selected firmware binaries to the target directory structure on the DUT.
   - Validate firmware binary integrity using MD5 checksums after copying.

Fail the test if the specified firmware version doesn't exist in `transceiver_firmware_info.json`.

## Test Cases

**Requirements for firmware upgrade tests:**

1. **DOM polling must be disabled** to prevent race conditions between I2C transactions and the CDB mode for modules that do not support CDB background mode. The test should wait for `sleep_after_dom_disable_sec` seconds after disabling DOM to avoid the race condition.
2. **Platform-specific processes:** On some platforms, `thermalctld` or similar user processes that perform I2C transactions with the module may need to be stopped if the `thermalctld_disabling_required` flag is set.
3. **Firmware requirements:**
   - The firmware version specified by `firmware_versions` test attribute must be available.
   - All firmware versions must support the CDB protocol for proper testing.
4. **Module capabilities:** The module must support CMIS CDB firmware operations. For dual-bank specific checks, `dual_bank_supported` must be true.
5. **Network connectivity:** The DUT must have network access to the firmware server specified in `cmis_cdb_firmware_base_url.json` for downloading firmware binaries.
6. **Link state:** The port should be operationally up before firmware download starts and should remain operationally up during and after the firmware download with no link flaps observed during the process.

**Common Verification Procedures:**

The following verification procedures should be performed after each test case:

1. Verify that there are no kernel error messages in syslog if `monitor_kernel_errors` flag is set.
2. Verify that no I2C errors are seen during firmware operations if `cdb_background_mode_supported` flag is set (module supports CDB background mode).
3. Verify that critical processes such as `xcvrd`, `syncd`, and `orchagent` do not crash or restart.

**Timing Requirements:**

For firmware download, run, and commit operations, the test framework must report the command execution time to the test logs/report. This enables performance tracking across firmware versions and transceiver types.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Interruption of firmware download | 1. Start the firmware download and interrupt the command using `firmware_download_interrupt_method` at `firmware_download_interrupt_percentage`.<br>2. Abort the firmware download using CDB abort command if `firmware_download_cdb_abort_support` flag is set. | 1. Check that advertisement register for CDB abort is set if `firmware_download_cdb_abort_support` is set.<br>2. Active firmware version remains unchanged.<br>3. If `dual_bank_supported` is true, inactive firmware version is invalid i.e. N/A or 0.0.0.<br>4. No change in "Committed Image".<br>5. Running image remains unchanged. |
| 2 | Firmware download validation | 1. Run CDB abort command if `firmware_download_cdb_abort_support` flag is set to clear any residual CDB state from prior interrupt operation.<br>2. Download the next firmware specified in `firmware_versions` using the `sfputil firmware download <port>`.<br>3. Wait until CLI execution completes. | 1. If CDB abort command was executed, it should be successful.<br>2. The CLI command should complete within `firmware_download_timeout_minutes` minutes and return 0.<br>3. Active FW version should remain unchanged.<br>4. If `dual_bank_supported` is true, inactive FW version should reflect the downloaded firmware version.<br>5. Running image remains the same.<br>6. Committed image remains the same.<br>7. No link flap should be seen. |
| 3 | Firmware run validation | 1. Shut down all interfaces that are part of the physical port.<br>2. Execute firmware run.<br>3. Reset the transceiver and wait for `transceiver_reset_i2c_recover_sec` seconds.<br>4. Startup all the interfaces in Step 1. | 1. Firmware run command should finish within 60 seconds and the return code should be 0 (Return code 0 indicates success).<br>2. If `dual_bank_supported` is true, active firmware version should now match the previous inactive firmware version.<br>3. If `dual_bank_supported` is true, inactive firmware version should now match the previous active firmware version.<br>4. If `dual_bank_supported` is false, active firmware version should match the firmware selected for activation and inactive firmware checks are not applicable.<br>5. Link should be up within `port_startup_wait_sec` seconds.<br>6. `sfputil show fwversion <port>` CLI should now show the "Running Image" as the current active bank.<br>7. If `dual_bank_supported` is true, previous active firmware should show up in the inactive bank. |
| 4 | Firmware commit validation | 1. Execute firmware commit for an interface. | 1. Firmware commit command should finish within 60 seconds and the return code should be 0.<br>2. Active firmware version remains unchanged.<br>3. If `dual_bank_supported` is true, inactive firmware version remains unchanged.<br>4. Committed image is updated to the running/active firmware image.<br>5. No link flap is seen. |
| 5 | Firmware download validation with invalid firmware binary | Download an invalid firmware binary (e.g., a zero-filled or truncated file not released by the vendor). | 1. The CLI command should return a non-zero exit code.<br>2. The active firmware version does not change.<br>3. If `dual_bank_supported` is true, the inactive firmware version remains unchanged or is set to `0.0.0` or `N/A`.<br>4. No change in "Committed Image".<br>5. Running image remains unchanged.<br>6. No link flap should be seen. |
| 6 | Firmware download interruption | 1. Start the firmware download and interrupt at the percentages specified by `firmware_download_interrupt_percentage`.<br>2. Use the method specified in `firmware_download_interrupt_method` to interrupt the process:<br>- "ctrl_c": Use CTRL+C or kill the download process.<br>- "sfputil_reset": Reset the optic using `sfputil reset`. | 1. Active firmware version remains unchanged.<br>2. If `dual_bank_supported` is true, inactive firmware version is invalid i.e. N/A or 0.0.0.<br>3. No change in "Committed Image".<br>4. No link flap should be seen. |
| 7 | CDB abort of firmware download | 1. Start the firmware download and interrupt using CDB abort command if `firmware_download_cdb_abort_support` flag is set. | 1. CDB abort command should be successful.<br>2. Active firmware version remains unchanged.<br>3. If `dual_bank_supported` is true, inactive firmware version is invalid i.e. N/A or 0.0.0.<br>4. No change in "Committed Image".<br>5. Running image remains unchanged. |
| 8 | Successful firmware download after interruption | 1. Perform steps in TC #6 followed by TC #2. | All expectations of TC #6 and TC #2 must be met. |
| 9 | Firmware download validation post reset | 1. Perform steps in TC #2.<br>2. Execute `sfputil reset <port>` and wait `transceiver_reset_i2c_recover_sec` seconds for it to finish. | All expectations of TC #2 must be met. |
| 10 | Ensure static fields of EEPROM remain unchanged | 1. Perform steps in TC #2.<br>2. Perform steps in TC #3. | 1. All the expectations of TC #2 and #3 must be met.<br>2. Ensure after each step 1 and 2 that the static fields of EEPROM (e.g., vendor name, part number, serial number, vendor date code, OUI, and hardware revision) remain unchanged. |
| 11 | Firmware download stress test | 1. Perform steps in TC #2 `firmware_download_stress_iterations` number of times. | 1. All the expectations of TC #2 must be met for each iteration. |
| 12 | Firmware activation stress test | 1. Perform steps in TC #2, #3, and #4 `firmware_activation_stress_iterations` number of times. | 1. All the expectations of TC #2, #3, and #4 must be met for each iteration. |
| 13 | Firmware read stress test | 1. Perform `sfputil show fwversion <port>` CLI command `firmware_read_stress_iterations` number of times. | 1. The return code is 0.<br>2. All reported fields remain unchanged across iterations.<br>3. Active firmware version is consistent across all iterations.<br>4. If `dual_bank_supported` is true, inactive firmware version is consistent across all iterations. |
| 14 | Firmware version validation | 1. For transceivers with `gold_firmware_version` attribute, use `sfputil show fwversion <port>`.<br>2. If `dual_bank_supported` is true, verify both active and inactive firmware versions.<br>3. Compare with expected values from attributes. | 1. Active firmware version matches `gold_firmware_version` attribute value.<br>2. If `dual_bank_supported` is true, inactive firmware version matches `inactive_firmware_version` attribute value. |

### Cleanup

- If `restore_initial_inactive_firmware` is true, the inactive firmware version recorded before testing began is restored via firmware download only if it is present in `transceiver_firmware_info.json`.
- The firmware binary folder on the DUT (`/tmp/cmis_cdb_firmware/`) will be deleted after the test module run is complete to ensure a clean state for subsequent tests
- Cleanup includes removing both the directory structure and any temporary files created during the process

## CLI Commands Reference

Refer to [CLI commands](./test_plan.md#cli-commands) section for the CLI commands used in the above test cases.
