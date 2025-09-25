# CMIS CDB Firmware Upgrade Test Plan

## Scope

This test plan outlines a comprehensive framework for testing the firmware upgrade/downgrade of CMIS compliant transceivers being onboarded to SONiC. The goal is to automate all tests listed in this document.

**Optics Scope**:
The test plan includes various optics types, such as:

- Active Optical Cables (AOC)
- Active Electrical Cables (AEC)
- DR8 optics
- Direct Attach Cables (DAC)
- Short Range/Long Range (SR/LR) optics
- SONiC-supported breakout cables

**Optics Specifications**:
Tests will cover optics compliant with:

- CMIS
- C-CMIS

## Testbed Topology

Please refer to the [Testbed Topology](./transceiver_onboarding_test_plan.md#testbed-topology) section.

## Test Cases

**Pre-requisites for the Below Tests:**

1. All the pre-requisites mentioned in [Transceiver Onboarding Test Plan](./transceiver_onboarding_test_plan.md#test-cases) must be met.

2. A `transceiver_firmware_info.csv` file (located in `ansible/files/transceiver/inventory` directory) should exist if a transceiver being tested supports CMIS CDB firmware upgrade. This file will capture the firmware binary metadata for the transceiver. Each transceiver should have at least 2 firmware binaries (in addition to the gold firmware binary) so that firmware upgrade can be tested. Following should be the format of the file

    ```csv
    normalized_vendor_name,normalized_vendor_pn,fw_version,fw_binary_name,md5sum
    <normalized_vendor_name_1>,<normalized_vendor_pn_1>,<firmware_version_1>,<firmware_binary_1>,<md5sum_1>
    <normalized_vendor_name_1>,<normalized_vendor_pn_1>,<firmware_version_2>,<firmware_binary_2>,<md5sum_2>
    <normalized_vendor_name_1>,<normalized_vendor_pn_1>,<firmware_version_3>,<firmware_binary_3>,<md5sum_3>
    # Add more vendor part numbers as needed
    ```

    For each firmware binary, the following metadata should be included:

    - `normalized_vendor_name`: The normalized vendor name, created by applying the normalization rules described in the [CMIS CDB Firmware Binary Management](#111-cmis-cdb-firmware-binary-management) section.
    - `normalized_vendor_pn`: The normalized vendor part number, created by applying the normalization rules described in the [CMIS CDB Firmware Binary Management](#111-cmis-cdb-firmware-binary-management) section.
    - `fw_version`: The version of the firmware.
    - `fw_binary_name`: The filename of the firmware binary.
    - `md5sum`: The MD5 checksum of the firmware binary.

3. A `cmis_cdb_firmware_base_url.csv` file (located in `ansible/files/transceiver/inventory` directory) should be present to define the base URL for downloading CMIS CDB firmware binaries. The file should follow this format:

    ```csv
    inv_name,fw_base_url
    <inventory_file_name>,<base_url>
    ```

    - `inv_name`: The name of the inventory file that contains the definition of the target DUTs. For further details, please refer to the [Inventory File](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.new.testbed.Configuration.md#inventory-file). The `inv_name` allows DUTs to be grouped based on their inventory file, enabling the test framework to fetch the correct base URL for firmware downloads.
    - `fw_base_url`: The base URL from which the CMIS CDB firmware binaries can be downloaded. This URL should point to the directory where the firmware binaries are stored. e.g., `http://1.2.3.4/cmis_cdb_firmware/`.

    Example of the file:

    ```csv
    inv_name,fw_base_url
    lab,http://1.2.3.4/cmis_cdb_firmware/
    ```

**Attributes for  the below tests**

A `cdb_fw_upgrade.json` file is used to define the attributes for the CDB firmware upgrade tests for the various types of transceivers the system supports.

The following table summarizes the key attributes used in CDB firmware upgrade testing. This table serves as the authoritative reference for all attributes and must be updated whenever new attributes are introduced:

| Attribute Name | Type | Default | Mandatory | Override Levels | Description |
|-----------|------|---------|------------|-------------|-------------|
| port_under_test | List | All | No | None | A list under `dut.dut_name` containing the ports to be tested for cmis fw upgrade test only.<br>This attribute must exist only under `dut` field. |
| firmware_versions | List | None | Yes | transceivers | A list containing firmware versions to be tested as its values. |
| firmware_download_timeout_minutes | Int | 30 | No | transceivers |Firmware download timeout value in minutes as the integer value |
| restore_initial_firmwares | Bool | False | No | dut |A flag indicating whether to restore the initial active and inactive firmware versions after testing is completed |
| firmware_download_stress_iterations | Int | 5 | No | dut | The number of iterations to stress test the firmware download process |
| firmware_activation_stress_iterations | Int | 5 | No | dut | The number of iterations to stress test the firmware activation process |
| firmware_read_stress_iterations | Int | 5 | No | dut | The number of iterations to stress test the firmware read process |
| firmware_download_abort_method | String | "sfputil_reset" | No | transceivers | The method to abort the firmware download process. It can be one of the following strings: "ctrl_c", "sfputil_reset", "optic_reinsert" |
| firmware_download_abort_percentage | List | `[10, 50, 90]` | No | transceivers | The percentage of download progress at which the firmware download should be aborted. |
| sleep_after_dom_disable_sec | Int | 5 | No | transceivers | The number of seconds to sleep after disabling DOM monitoring before proceeding with the test. |
| monitor_kernel_errors | Bool | False | No | transceivers | A flag indicating whether to monitor kernel errors during the test. |
| thermalctld_disabling_required | Bool | False | No | transceivers | A flag indicating whether to disable the thermalctld during the test. |


#### 1.1 CMIS CDB Firmware Upgrade Testing

##### 1.1.1 CMIS CDB Firmware Binary Management

###### 1.1.1.1 Firmware Binary Naming Guidelines

CMIS CDB firmware binaries must follow strict naming conventions to ensure compatibility across different filesystems and automation tools.

**Filename Requirements:**

1. **Character Restrictions:**
   - **Must not** contain spaces or special characters except hyphens (`-`), dots (`.`), and underscores (`_`)
   - Must be valid filenames for Windows, Linux, and macOS filesystems
   - Avoid reserved characters: `< > : " | ? * \ /`
   - Ensure that the filename does not start or end with special characters

2. **File Extension:**
   - Use `.bin` extension

###### 1.1.1.2 Normalization Rules for Vendor Name and Part Number

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

###### 1.1.1.3 Firmware Binary Storage on SONiC Device

The CMIS CDB firmware binaries are stored under `/tmp/cmis_cdb_firmware/` on the SONiC device, organized by normalized vendor name, part number and firmware version number.

**Directory Structure Requirements:**

```
/tmp/cmis_cdb_firmware/
├── <NORMALIZED_VENDOR_NAME>/
│   └── <NORMALIZED_VENDOR_PART_NUMBER>/
│       └── <FIRMWARE_VERSION_NUMBER>/
│           ├── FIRMWARE_BINARY_1.bin
└── ...
```

**Requirements:**

- All directory and file names **must be uppercase** and follow the normalization rules defined in section 1.1.1.2
- Use the `GENERIC_N_END` placeholder for cable lengths as described in the normalization rules

**Example Directory Structure:**

```
/tmp/cmis_cdb_firmware/
├── ACMECORP/
│   └── QSFP-100G-AOC-GENERIC_2_ENDM/
│       ├── 1.2.3
│           └── ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.3.bin
│       ├── 1.2.4
│            └── ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
├── EXAMPLE_INC/
│   └── QSFP_200G_LR4/
│       ├── 2.0.1
│           └── EXAMPLE_INC_QSFP_200G_LR4_2.0.1.bin
└── ...
```

###### 1.1.1.4 Firmware Binary Storage on Remote Server

The CMIS CDB firmware binaries must be stored on a remote server with the following requirements:

**Server Organization:**

- Directory structure should mirror the SONiC device structure described above
- Server must be accessible via HTTP/HTTPS protocols
- Base URL configuration is defined in `cmis_cdb_firmware_base_url.csv`

**Base URL Configuration:**
The `cmis_cdb_firmware_base_url.csv` file contains the mapping between inventory files and their corresponding firmware download URLs:

```csv
inv_name,fw_base_url
lab,http://firmware-server.example.com/cmis_cdb_firmware
production,https://secure-firmware.example.com/cmis_cdb_firmware
```

> Note: The `fw_base_url` should not end with a trailing slash (`/`). The test framework will append the necessary path components based on the normalized vendor name and part number.

**Download URL Format:**
Firmware binaries are accessed using the following URL pattern:
```
<fw_base_url>/<NORMALIZED_VENDOR_NAME>/<NORMALIZED_VENDOR_PART_NUMBER>/<FIRMWARE_BINARY_NAME>
```

**Example:**
```
http://firmware-server.example.com/cmis_cdb_firmware/ACMECORP/QSFP-100G-AOC-GENERIC_2_ENDM/ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
```

##### 1.1.2 CMIS CDB Firmware Copy to DUT via sonic-mgmt infrastructure

This section describes the automated process for copying firmware binaries to the DUT, ensuring only the required firmware versions are present for testing.

**Firmware Selection Algorithm:**

To ensure only the necessary firmware binaries are present for each transceiver:

1. **Parse `transceiver_dut_info.json`** to identify the transceiver present on the port identified by `port_under_test` test attribute. Generate the normalized vendor name and part number.
2. **Parse `firmware_versions` test attribute** to get the next firmware version to download.
3. **Parse `transceiver_firmware_info.csv`** to obtain the list of available firmware binaries, their versions, and associated vendor and part numbers. If the firmware version specified in step 2 exists for the normalized vendor name and part number from step 1:
   - **Copy only the selected firmware binaries** to the target directory structure on the DUT.
   - **Validate firmware binary integrity** using MD5 checksums after copying.
   
   Fail the test if the specified firmware version doesn't exist.

**Cleanup:**

- The firmware binary folder on the DUT (`/tmp/cmis_cdb_firmware/`) will be deleted after the test module run is complete to ensure a clean state for subsequent tests
- Cleanup includes removing both the directory structure and any temporary files created during the process

##### 1.1.3 CMIS CDB Firmware Upgrade Tests

**Prerequisites:**

1. **DOM polling must be disabled** to prevent race conditions between I2C transactions and the CDB mode for modules that cannot support CDB background mode. Test should wait for `sleep_after_dom_disable_sec` seconds after disabling DOM to avoid the race condition.
2. **Platform-specific processes:** On some platforms, `thermalctld` or similar user processes that perform I2C transactions with the module may need to be stopped if `thermalctld_disabling_required` flag is set.
3. **Firmware requirements:**
   - The firmware version specified  by `firmware_versions` test attribute must be available.
   - All firmware versions must support the CDB protocol for proper testing.
4. **Module capabilities:** The module must support dual banks for firmware upgrade operations.
5. **Network connectivity:** The DUT must have network access to the firmware server specified in `cmis_cdb_firmware_base_url.csv` for downloading firmware binaries.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Firmware download validation | 1. Download the next firmware specified in `firmware_versions` using the sfputil CLI<br>2. Wait until CLI execution completes | 1. CLI execution should finish within `firmware_download_timeout_minutes` minutes and return 0 <br>2. Active FW version should remain unchanged<br>3. Inactive FW version should reflect the downloaded firmware version<br>4. Running image bank, inactive image bank and committed image bank remain the same<br>5. Inactive image bank should show the downloaded fw version<br>6. No link flap should be seen<br>7. The kernel has no error messages in syslog if `monitor_kernel_errors` flag is set<br>8. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Firmware run validation | 1. Shut down all the interfaces part of the physical ports<br>2. Execute firmware run<br><br>3. Reset the transceiver and wait for 5 seconds<br>4. Startup all the interfaces in Step 1 | 1. Firmware run command should finish in 60 seconds and the return code should be 0 (Return code 0 indicates success)<br>2. Active firmware version should now match the previous inactive firmware version<br>3. Inactive firmware version should now match the previous active firmware version<br>4. Link should be up within `port_wait_time_after_startup_sec` seconds.<br>5. `sfputil show fwversion` CLI should now show the “Running Image” to the current active bank<br>6. Previous active firmware should show up in the inactive bank<br>7. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 3 | Firmware commit validation | 1. Execute firmware commit for an interface| 1. Firmware commit command should finish in 60 seconds and the return code should be 0<br>2. Active firmware version and inactive firmware version remain unchanged<br>3. Committed image bank is updated to active image bank<br>4. No link flap is seen<br>5. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 4 | Firmware download validation with invalid firmware binary | Download an invalid firmware binary (any file not released by the vendor) | 1. The active firmware version does not change<br>2. The inactive firmware version remains unchanged or is set to `0.0.0` or `N/A`<br> 3.  No change in "Committed Image"<br>4. No link flap should be seen<br>5. The kernel has no error messages in syslog if `monitor_kernel_errors` flag is set<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 5 | Firmware download abort | 1. Start the firmware download and abort at the percentages specified by `firmware_download_abort_percentage`<br>2. Use the method specified in `firmware_download_abort_method` to abort the process:<br>"ctrl_c": Use CTRL+C or kill the download process<br> "sfputil_reset": reset the optics using sfputil reset<br>"optic_reinsert": remove the optics and re-insert | 1. Active firmware version remains unchanged<br>2. Inactive firmware version is invalid i.e. N/A or 0.0.0<br>3. No change in "Committed Image"<br>4. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 6 | Successful firmware download after aborting | 1. Perform steps in TC #4 followed by TC #1 | All the expectation of test case #4 and case #1 must be met |
| 7 | Firmware download validation post reset | 1. Perform steps in TC #1<br>2. Execute `sfputil reset PORT` and wait for it to finish | All the expectation of test case #1 must be met |
| 8 | Ensure static fields of EEPROM remain unchanged | 1. Perform steps in TC #1<br>2. Perform steps in TC #2 | 1. All the expectations of TC #1 and #2 must be met<br>2. Ensure after each step 1 and 2 that the static fields of EEPROM (e.g., vendor name, part number, serial number, vendor date code, OUI, and hardware revision) remain unchanged |
| 9 | Firmware download stress test | 1. Perform steps in TC #1 `firmware_download_stress_iterations` number of times. | 1. All the expectations of TC #1 must be met |
| 10 | Firmware activation stress test | 1. Perform steps in TC #2 and #3 `firmware_activation_stress_iterations` number of times. | 1. All the expectations of TC #2 and #3 must be met |
| 11 | Firmware read stress test | 1. Perform fw read operation `firmware_read_stress_iterations` number of times. | 1. The return code is 0.<br>2. All the fields remain unchanged across iterations<br>3. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |

> Note: For firmware download, run and commit tests, report the command execution time to the test logs/report.

#### CLI commands

Refer to [CLI commands](./transceiver_onboarding_test_plan.md#cli-commands) section for the CLI commands used in the above test cases.
