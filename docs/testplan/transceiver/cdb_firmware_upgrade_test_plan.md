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
- Firmware upgrade across firmware versions differing in major, minor, and point numbers
- Validating invalid firmware binary rejection
- CDB background mode capability verification and stress testing

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

> **Visual Guide**: See the [CDB Firmware Upgrade Flow](diagrams/cdb_firmware_upgrade_flow.md) diagram for an overview of the inventory files and firmware staging flow.

1. All the pre-requisites mentioned in [Transceiver Onboarding Test Infrastructure and Framework](./test_plan.md#test-prerequisites-and-configuration-files) must be met.

2. A per-PN `cdb_firmware_upgrade_manifest.json` file must exist for every transceiver that supports CMIS CDB firmware upgrade. The file lives in the same per-PN directory as the `cdb_firmware_upgrade.json` attribute shard (under `attributes/cdb_firmware_upgrade/transceivers/vendors/<VENDOR>/part_numbers/<PN>/`). The manifest must contain exactly 3 firmware versions (1 gold firmware version plus 2 additional firmware versions) so that upgrade and downgrade paths can be tested. At least one of the 2 additional firmware versions must differ from the gold firmware version in all three of the major, minor, and point numbers. The file should follow this format:

```json
{
    "<fw_version_1>": {
        "fw_binary_name": "<firmware_binary_filename_1>",
        "md5sum": "<md5sum_1>"
    },
    "<fw_version_2>": {
        "fw_binary_name": "<firmware_binary_filename_2>",
        "md5sum": "<md5sum_2>"
    },
    "<fw_version_3>": {
        "fw_binary_name": "<firmware_binary_filename_3>",
        "md5sum": "<md5sum_3>"
    }
}
```

The JSON keys are:

- **Top-level key** (`fw_version`): The version of the firmware.
- **`fw_binary_name`**: The filename of the firmware binary.
- **`md5sum`**: The MD5 checksum of the firmware binary.

The `<NORMALIZED_VENDOR_NAME>` and `<NORMALIZED_VENDOR_PN>` directory names are created by applying the normalization rules described in the [Vendor Name and Part Number Normalization Rules](./test_plan.md#vendor-name-and-part-number-normalization-rules) section.

3. The framework supports two mutually-exclusive transports for getting binaries onto the DUT and only one must be configured per inventory:

- **Download mode** — a `cdb_firmware_upgrade_url.json` file (located in `attributes/cdb_firmware_upgrade/` directory) is present and defines the base URL for downloading CMIS CDB firmware binaries. The file should follow this format:

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

- **Pre-staged mode** — `cdb_firmware_upgrade_url.json` is absent, and the binaries listed in the per-PN `cdb_firmware_upgrade_manifest.json` files are already present on the DUT under `/host/cmis_cdb_firmware/` (see [Pre-staged Firmware Binaries on the DUT](#pre-staged-firmware-binaries-on-the-dut) below).

The framework picks the mode at session start based on whether `cdb_firmware_upgrade_url.json` exists for the current inventory. In both modes the test sequence is identical once the binaries are present under `/tmp/cmis_cdb_firmware/`. MD5 validation against the per-PN manifest is performed in **both** modes so a stale or wrong binary is caught regardless of how it got there.

## Attributes

A `cdb_firmware_upgrade.json` file is used to define the attributes for the CDB firmware upgrade tests for the various types of transceivers the system supports. The category attributes are stored under `attributes/cdb_firmware_upgrade/`. Per-PN body contains transceiver specific defaults, while DUT specific overrides are defined in the category-level shard; see [File Organization](test_plan.md#file-organization) for the shard contract.

The following table summarizes the key attributes used in CDB firmware upgrade testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

**Legend:** M = Mandatory, O = Optional

| Attribute Name | Type | Default Value | Mandatory | Override Levels | Description |
|-----------|------|---------|-----------|-------------|-------------|
| ports_under_test | List | All | O | dut | A list of physical port names (e.g., `[1, 2, 6]`) under `dut.dut_name` containing the ports to be tested for CMIS FW upgrade test only. This attribute must exist only under the `dut` field. |
| firmware_versions | List | None | M | transceivers | A list containing firmware versions to be tested. The last value in the list represents the final active firmware version after the test is completed. |
| firmware_download_timeout_minutes | Int | 30 | O | transceivers | Maximum time in minutes to wait for a firmware download to complete. |
| firmware_download_stress_iterations | Int | 5 | O | dut | The number of iterations to stress test the firmware download process. |
| firmware_activation_stress_iterations | Int | 1 | O | dut | The number of iterations to stress test the firmware activation process. |
| firmware_upgrade_stress_iterations | Int | 5 | O | dut | The number of iterations to stress test the firmware upgrade process. |
| firmware_read_stress_iterations | Int | 5 | O | dut | The number of iterations to stress test the firmware read process. |
| firmware_download_interrupt_method | String | "sigkill" | O | transceivers | The method used to interrupt the firmware download process. |
| firmware_download_interrupt_percentage | List | [10, 30, 50, 90] | O | transceivers | The percentage of download progress at which the firmware download should be interrupted. |
| firmware_download_cdb_abort_support | Bool | True | O | transceivers | A flag indicating whether the transceiver supports CDB abort during firmware download. |
| firmware_run_timeout_sec | Int | 20 | O | transceivers | Maximum time in seconds to wait for a firmware run command to complete. |
| firmware_commit_timeout_sec | Int | 10 | O | transceivers | Maximum time in seconds to wait for a firmware commit command to complete. |
| sleep_after_dom_disable_sec | Int | 5 | O | transceivers | The number of seconds to sleep after disabling DOM monitoring before proceeding with the test. |
| thermalctld_disabling_required | Bool | False | O | transceivers or Platform-level | A flag indicating whether to disable `thermalctld` during the test. |
| dual_bank_supported | Bool | True | O | transceivers | Whether the transceiver supports dual-bank firmware. Used to determine if both active and inactive firmware versions should be validated. |
| gold_firmware_version | String | - | M | transceivers | The expected active/gold firmware version for modules. Used as the baseline reference for firmware version validation. |
| inactive_firmware_version | String | - | M | transceivers | The expected inactive bank firmware version for dual-bank modules. Optional only when `dual_bank_supported` is false. |
| cdb_background_mode_supported | Bool | - | O | transceivers | CDB background mode support. |

> **Note:** The `transceiver_reset_i2c_recover_sec`, `port_startup_wait_sec`, and `low_power_mode_supported` attributes are defined in the [System test attributes](system_test_plan.md#attributes) and are reused here. The `cmis_active_optical` attribute is defined in the [EEPROM test attributes](eeprom_test_plan.md#attributes).

> **Attribute invariants:** `firmware_versions` must contain exactly 3 entries (1 gold plus 2 additional firmware versions). `gold_firmware_version` must equal `firmware_versions[-1]`, and `inactive_firmware_version` must equal `firmware_versions[-2]`. Additionally, at least one of the entries in `firmware_versions` must differ from `gold_firmware_version` in all three of the major, minor, and point numbers. A mismatch skips the CDB firmware test suite with a clear configuration error. The actual module firmware state is verified at runtime.

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
│       ├── 1.2.3/
│       │   └── ACME_CORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.3.bin
│       └── 1.2.4/
│           └── ACME_CORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
├── EXAMPLE_INC/
│   └── QSFP_200G_LR4/
│       └── 2.0.1/
│           └── EXAMPLE_INC_QSFP_200G_LR4_2.0.1.bin
└── ...
```

## Firmware Binary Storage on Remote Server

> **Note:** This section applies only to **download mode** (i.e., when `cdb_firmware_upgrade_url.json` is present). If using pre-staged mode, skip to [Pre-staged Firmware Binaries on the DUT](#pre-staged-firmware-binaries-on-the-dut).

The CMIS CDB firmware binaries must be stored on a remote server with the following requirements:

**Server Organization:**

- Directory structure should mirror the SONiC device structure described above
- Server must be accessible via HTTP/HTTPS protocols
- Base URL configuration is defined in `cdb_firmware_upgrade_url.json`

**Base URL Configuration:**
The `cdb_firmware_upgrade_url.json` file contains the mapping between inventory files and their corresponding firmware download URLs:

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

## Pre-staged Firmware Binaries on the DUT

When `cdb_firmware_upgrade_url.json` is absent, the framework expects every firmware binary listed in the per-PN `cdb_firmware_upgrade_manifest.json` files to already exist under `/host/cmis_cdb_firmware/` on the DUT, using the **same normalized directory structure** as the remote server:

```text
/host/cmis_cdb_firmware/
├── ACME_CORP/
│   └── QSFP-100G-AOC-GENERIC_2_ENDM/
│       ├── 1.2.3/
│       │   └── ACME_CORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.3.bin
│       └── 1.2.4/
│           └── ACME_CORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
├── EXAMPLE_INC/
│   └── QSFP_200G_LR4/
│       └── 2.0.1/
│           └── EXAMPLE_INC_QSFP_200G_LR4_2.0.1.bin
└── ...
```

**Requirements:**

- The directory structure under `/host/cmis_cdb_firmware/` must follow the same normalized layout as the remote server: `<NORMALIZED_VENDOR>/<NORMALIZED_PN>/<VERSION>/<fw_binary_name>`.
- The test framework resolves each `(normalized_vendor, normalized_pn, version)` it needs from the corresponding per-PN `cdb_firmware_upgrade_manifest.json`, locates the binary at `/host/cmis_cdb_firmware/<NORMALIZED_VENDOR>/<NORMALIZED_PN>/<VERSION>/<fw_binary_name>`, validates its MD5 against the manifest, and copies it into `/tmp/cmis_cdb_firmware` for the test run.
- If any required binary is missing from `/host/cmis_cdb_firmware/` or its MD5 does not match the manifest, the framework fails fast with a clear configuration error and skips the CDB firmware test suite.

## CMIS CDB Firmware Copy to DUT via sonic-mgmt Infrastructure

This section describes the automated process for copying firmware binaries to the DUT, ensuring only the required firmware versions are present for testing.

**Firmware Selection Algorithm:**

To ensure only the necessary firmware binaries are present for each transceiver:

1. **Resolve transport mode** based on Pre-requisite: if `cdb_firmware_upgrade_url.json` exists for the current inventory, use download mode; otherwise use pre-staged mode (binaries under `/host/cmis_cdb_firmware/`).
2. **Use `port_attributes_dict`** (built from `dut_info/<dut_hostname>.json`) to identify the transceivers present on the DUT. If `ports_under_test` attribute is specified, only those ports are considered. The normalized vendor name and part number are available in `BASE_ATTRIBUTES`.
3. **Parse `firmware_versions` test attribute** from `CDB_FIRMWARE_UPGRADE_ATTRIBUTES` to get the firmware versions needed for the transceiver type.
4. **Load the per-PN `cdb_firmware_upgrade_manifest.json`** to obtain the firmware binary metadata for each version specified in step 3. If the firmware version exists in the manifest:
   - **Download mode:** fetch the binary from `<fw_base_url>/<NORMALIZED_VENDOR>/<NORMALIZED_PN>/<VERSION>/<fw_binary_name>` into the target directory structure on the DUT (`/tmp/cmis_cdb_firmware/...`).
   - **Pre-staged mode:** copy the binary from `/host/cmis_cdb_firmware/<NORMALIZED_VENDOR>/<NORMALIZED_PN>/<VERSION>/<fw_binary_name>` into the target directory structure on the DUT (`/tmp/cmis_cdb_firmware/...`).
   - Validate firmware binary integrity using MD5 checksums after staging, in both modes.

Fail the test if the per-PN manifest file is missing, the specified firmware version doesn't exist in `cdb_firmware_upgrade_manifest.json`, or if a binary listed in the manifest is missing from the configured source.

## Test Cases

**Requirements for firmware upgrade tests:**

1. **DOM polling must be disabled** to prevent race conditions between I2C transactions and the CDB mode for modules that do not support CDB background mode. The test should wait for `sleep_after_dom_disable_sec` seconds after disabling DOM to avoid the race condition.
2. **Platform-specific processes:** On some platforms, `thermalctld` or similar user processes that perform I2C transactions with the module may need to be stopped if the `thermalctld_disabling_required` flag is set.
3. **Firmware requirements:**
   - The firmware version specified by `firmware_versions` test attribute must be available.
   - All firmware versions must support the CDB protocol for proper testing.
4. **Module capabilities:** The module must support CMIS CDB firmware operations. For dual-bank specific checks, `dual_bank_supported` must be true.
5. **Network connectivity:** In download mode, the DUT must have network access to the firmware server specified in `cdb_firmware_upgrade_url.json` for downloading firmware binaries. Not required in pre-staged mode.
6. **Link state:** The port should be operationally up before firmware download starts and should remain operationally up during and after the firmware download with no link flaps observed during the process.
7. **CDB abort before download:** If `firmware_download_cdb_abort_support` is true, the framework must issue a CDB abort command before every firmware download to ensure the module is not in a stale CDB state from a previous interrupted operation. 

**Note:** When the abort is issued as a pre-download safeguard (i.e. the test is not validating the abort behavior itself), the framework ignores the command's return value, since the module may return an error when there is no incomplete download to abort.

**Common Verification Procedures:**

These tests rely on the shared transceiver test infrastructure checks for test case verification:

1. **Process health and core files** are covered by the autouse [Common Per-Test Health Checks](./test_plan.md#common-per-test-health-checks) fixture, which runs before and after every transceiver test. It verifies `xcvrd` is `RUNNING` with an unchanged PID and scans `/var/core/` for new core files.
2. **Kernel and I2C errors** are detected using the `dmesg` kernel-ring-buffer scanner (see `tests/transceiver/common/dmesg_helpers.py`) during the firmware-operation window. The scanner checks for I2C errors that may indicate communication failures with the module during CDB operations.
3. **I2C error treatment is gated by `cdb_background_mode_supported`**. Tests must apply the following truth table when configuring the dmesg scanner for the firmware-operation window:

| cdb_background_mode_supported | Expected Behaviour | Treatment |
|---|---|---|
| true | EEPROM should remain accessible while CDB is active | Any I2C error match then test fails. |
| false | Expected transient noise while DOM polling is disabled and CDB is active | Add a pattern for the known I2C errors. Patterns outside the window remain a failure. |

### Verification Bundles

The Expected Results column in the Test Cases table references the following named verification bundles. Each bundle is a fixed set of assertions performed in addition to any test case specific checks.

#### Firmware State Unchanged Verification

Firmware state is unchanged after a failed or aborted operation:

1. Active firmware version remains unchanged.
2. If `dual_bank_supported` is true, inactive firmware version is invalid (i.e. `N/A` or `0.0.0`).
3. Committed Image remains unchanged.
4. Running Image remains unchanged.
5. No link flap should be seen.

#### Firmware Downloaded Verification

Firmware download succeeded and inactive bank holds the new image:

1. CLI command should complete within `firmware_download_timeout_minutes` minutes and return 0.
2. Active firmware version remains unchanged.
3. If `dual_bank_supported` is true, inactive firmware version reflects the downloaded firmware version.
4. Running Image remains unchanged.
5. Committed Image remains unchanged.
6. No link flap should be seen.
7. Static EEPROM fields (vendor name, part number, hardware revision, etc.) remain unchanged.

#### Firmware Activation Verification

Firmware run and commit succeeded, the bank swap took effect, and the committed Image points to the active image:

1. Firmware run command finishes within `firmware_run_timeout_sec` seconds and returns 0.
2. Firmware commit command finishes within `firmware_commit_timeout_sec` seconds and returns 0.
3. If `dual_bank_supported` is true, active firmware version now matches the previous inactive firmware version.
4. If `dual_bank_supported` is true, inactive firmware version now matches the previous active firmware version.
5. If `dual_bank_supported` is false, active firmware version matches the firmware selected for activation and inactive firmware checks are not applicable.
6. Committed Image is updated to the active firmware image.
7. `sfputil show fwversion <port>` CLI shows the "Running Image" as the current active bank.
8. Link is up within `port_startup_wait_sec` seconds and no link flap is seen.
9. Static EEPROM fields (vendor name, part number, hardware revision, etc.) remain unchanged.

**Timing Requirements:**

For firmware download, run, and commit operations, the test framework must report the command execution time to the test logs/report. This enables performance tracking across firmware versions and transceiver types.

**Composite test case recovery:** If any of the sub steps fail, the test case fails immediately, and the framework restores the module to gold so the next test case starts from a known state.

**CDB abort for failure tests:** Test cases that intentionally fail or interrupt a firmware download (TC #6, TC #7, and TC #8) run only on modules where `firmware_download_cdb_abort_support` is true. On modules without CDB abort support, these test cases fail immediately.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Firmware version baseline validation | **Runs first** in the CDB firmware test sequence as a baseline check that the module starts on gold. <br><br>1. Use `sfputil show fwversion <port>`.<br>2. If `dual_bank_supported` is true, read both active and inactive firmware versions.<br>3. Compare with expected values from attributes. | 1. Active firmware version matches `gold_firmware_version` attribute value.<br>2. If `dual_bank_supported` is true, inactive firmware version matches `inactive_firmware_version` attribute value. |
| 2 | CDB abort support test | 1. Read the EEPROM CDB abort advertisement register to determine the CDB abort capability.<br>2. Compare the advertisement against the default `firmware_download_cdb_abort_support` value. | 1. For default value, page 9Fh byte 137 bit 0 reads 1.<br>2. For `firmware_download_cdb_abort_support` = false, page 9Fh byte 137 bit 0 reads 0.<br>3. Any mismatch between the configured attribute and EEPROM is logged and reported as a failure. |
| 3 | Firmware download validation | 1. Start firmware download of the next firmware specified in `firmware_versions` using `sfputil firmware download <port>`.<br>2. Wait until CLI execution completes.<br><br>**Note:** Version selection cycles through `firmware_versions` in round-robin order, skipping the version already present in the target bank (inactive bank for dual-bank modules, active bank for single-bank modules). | **Firmware Downloaded Verification** must hold. |
| 4 | Firmware activation validation | 1. Shut down all interfaces that are part of the physical port.<br>2. Execute firmware run.<br>3. Execute firmware commit.<br>4. Reset the transceiver and wait for `transceiver_reset_i2c_recover_sec` seconds.<br>5. Startup all the interfaces in Step 1. | **Firmware Activation Verification** must hold. |
| 5 | Firmware upgrade to a fully distinct version | 1. From `firmware_versions`, select the version that differs from the gold firmware version in all three of the major, minor, and point numbers.<br>2. Perform steps in TC #3 followed by TC #4 using that firmware version. | All expectations of TC #3 and TC #4 must be met. |
| 6 | Firmware download with invalid binary | **TC 6a:**<br>1. Generate a zero-filled `.bin` file on the DUT that has no valid firmware header.<br>2. Start firmware download using `sfputil firmware download <port>`. <br><br>**TC 6b:**<br>1. Take a good firmware binary for this module and flip a few bytes in the payload region of the binary. <br>2. Start firmware download using `sfputil firmware download <port>`. | **TC 6a:**<br>1. `sfputil firmware download <port>` returns a non-zero return code.<br>2. If `dual_bank_supported` is true, inactive firmware version remains unchanged. <br>3. **Firmware State Unchanged Verification** must hold (except for inactive firmware version).<br><br>**TC 6b:**<br>1. `sfputil firmware download <port>` returns a non-zero return code.<br>2. **Firmware State Unchanged Verification** must hold. |
| 7 | Firmware download interruption | 1. Start the firmware download and interrupt at the percentages specified by `firmware_download_interrupt_percentage`.<br>2. Use the method specified in `firmware_download_interrupt_method` to interrupt the process. | **Firmware State Unchanged Verification** must hold. |
| 8 | Firmware download after interruption | 1. Perform steps in TC #7 to leave the module in a post-interrupt state.<br>2. Run the CDB abort command to recover the module.<br>3. Perform steps in TC #3. | 1. After step 1, **Firmware State Unchanged Verification** must hold.<br>2. The CDB abort command must be successful.<br>3. After step 3, **Firmware Downloaded Verification** must hold. |
| 9 | Firmware download validation post reset | 1. Perform steps in TC #3.<br>2. Execute `sfputil reset <port>` and wait `transceiver_reset_i2c_recover_sec` seconds for it to finish. | All expectations of TC #3 must be met. |
| 10 | Firmware download in low-power mode | 1. Put the transceiver into low-power mode using CLI command. <br>2. Wait for `transceiver_reset_i2c_recover_sec` and confirm via CLI that the module is in low-power mode.<br>3. Perform steps in TC #3 with the module still in low-power mode.<br>4. After the download completes, read the module power state via CLI.<br>5. Restore the module to high-power mode. | 1. **Firmware Downloaded Verification** must hold after step 3.<br>2. The module remains in low-power mode after the firmware download completes.<br>3. After step 5 the module returns to high-power mode and the port is operationally up. |
| 11 | Firmware download with port in admin-down state | 1. Shutdown all interfaces that are part of the physical port using `config interface shutdown <port>`.<br>2. Verify the port is operationally down.<br>3. Perform steps in TC #3.<br>4. Verify the port remains operationally down after download completes.<br>5. Startup all interfaces using `config interface startup <port>`. | 1. After step 2, the port is operationally down.<br>2. **Firmware Downloaded Verification** must hold after step 3.<br>3. After step 5, link comes up within `port_startup_wait_sec`. |
| 12 | Firmware download stress test | 1. Perform steps in TC #3 `firmware_download_stress_iterations` number of times. | 1. All the expectations of TC #3 must be met for each iteration. |
| 13 | Firmware activation stress test | 1. Perform steps in TC #4 `firmware_activation_stress_iterations` number of times. | 1. All the expectations of TC #4 must be met for each iteration. |
| 14 | Firmware upgrade stress test | 1. Perform steps in TC #3 and #4 `firmware_upgrade_stress_iterations` number of times. | 1. All the expectations of TC #3 and #4 must be met for each iteration. |
| 15 | CDB background mode support test | **Skip if `cmis_active_optical` is false or `cdb_background_mode_supported` is not defined.**<br><br>1. Read EEPROM page 01h, byte 163 (0xA3), bit 5 to determine hardware CDB background mode capability.<br>2. Compare the hardware bit against the configured `cdb_background_mode_supported` value. | 1. For `cdb_background_mode_supported` = true, EEPROM page 01h byte 163 bit 5 reads 1.<br>2. For `cdb_background_mode_supported` = false, EEPROM page 01h byte 163 bit 5 reads 0.<br>3. Any mismatch between the configured attribute and EEPROM is logged and reported as a failure. |
| 16 | Firmware read and CDB background mode stress test | **This test runs only if TC #15 passes.**<br><br>1. Perform `sfputil show fwversion <port>` CLI command `firmware_read_stress_iterations` number of times.<br>2. For transceivers with `cdb_background_mode_supported` = true, concurrently keep accessing EEPROM throughout the loop and ensure the kernel has no error logs across all iterations.<br><br>**Note:** This test performs concurrent EEPROM reads while the CDB is active and any kernel I2C errors during this test indicate a CDB background mode failure. | 1. The return code is 0.<br>2. All reported fields remain unchanged across iterations.<br>3. Active firmware version is consistent across all iterations.<br>4. If `dual_bank_supported` is true, inactive firmware version is consistent across all iterations.<br>5. The read operation completes for all iterations without I2C errors in kernel logs. |

### Cleanup

- After the test suite completes, the module is restored to its original firmware state before testing began:
  - The gold firmware version in the active bank.
  - For dual-bank modules, the original inactive firmware version in the inactive bank.
- The firmware binary folder on the DUT (`/tmp/cmis_cdb_firmware/`) will be deleted after the test module run is complete to ensure a clean state for subsequent tests.
- Cleanup includes removing both the directory structure and any temporary files created during the process.

## CLI Commands Reference

Refer to [CLI commands](./test_plan.md#cli-commands) section for the CLI commands used in the above test cases.
