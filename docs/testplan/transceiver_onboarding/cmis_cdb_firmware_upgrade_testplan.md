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

A minimum of 1 port of a device with the onboarding transceiver should be connected with a cable and should be operationally up. The port can be connected to the same device or a different device. In the case of a breakout cable, the expectation is to connect all sides of the cable to the DUT.

1. Standalone topology with both ports connected on the same SONiC device (self loopback)

    ```text
    +-----------------+
    |           Port 1|<----+
    |                 |     | Loopback
    |    Device       |     | Connection
    |           Port 2|<----+
    |                 |
    +-----------------+
    ```

2. Point-to-point topology with port connected on different SONiC devices

    ```text

    +-----------------+     +-----------------+
    |           Port 1|<--->|Port 1           |
    |                 |     |                 |
    |    Device 1     |     |     Device 2    |
    |                 |     |                 |
    |                 |     |                 |
    +-----------------+     +-----------------+
    ```

3. Topology with port connected between SONiC device and 2 servers using a Y-cable

    ```text
                               +-----------------+
                               |                 |
                               |     Server 1    |
    +-----------------+        |                 |
    |                 |    +-->| Port            |
    |                 |    |   |                 |
    |   SONiC Device  |    |   +-----------------+
    |                 |<---+   +-----------------+
    |                 |    |   |                 |
    |                 |    |   |     Server 2    |
    +-----------------+    +-->| Port            |
                               |                 |
                               |                 |
                               +-----------------+
    ```

## Test Cases

**Pre-requisites for the Below Tests:**

1. A file `transceiver_dut_info.csv` (located in `ansible/files/transceiver_inventory` directory) should be present to describe the metadata of the transceiver connected to every port of each DUT. The format of the file is defined in [Transceiver DUT Information Format](./transceiver_onboarding_test_plan.md#1-tests-not-involving-traffic)

2. A file named `transceiver_common_attributes.csv` (located in the `ansible/files/transceiver_inventory` directory) must be present to define the common attributes for each transceiver, keyed by normalized vendor part number. The format of the file is defined in [Transceiver DUT Information Format](./transceiver_onboarding_test_plan.md#1-tests-not-involving-traffic)

3. A `transceiver_firmware_info.csv` file (located in `ansible/files/transceiver_inventory` directory) should exist if a transceiver being tested supports CMIS CDB firmware upgrade. This file will capture the firmware binary metadata for the transceiver. Each transceiver should have at least 2 firmware binaries (in addition to the gold firmware binary) so that firmware upgrade can be tested. Following should be the format of the file

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

4. A `cmis_cdb_firmware_base_url.csv` file (located in `ansible/files/transceiver_inventory` directory) should be present to define the base URL for downloading CMIS CDB firmware binaries. The file should follow this format:

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

5. A file (`sonic_{inv_name}_links.csv`) containing the connections of the ports should be present. This file is used to create the topology of the testbed which is required for minigraph generation.

    - `inv_name` - inventory file name that contains the definition of the target DUTs. For further details, please refer to the [Inventory File](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.new.testbed.Configuration.md#inventory-file)

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

The CMIS CDB firmware binaries are stored under `/tmp/cmis_cdb_firmware/` on the SONiC device, organized by normalized vendor name and part number.

**Directory Structure Requirements:**

```
/tmp/cmis_cdb_firmware/
├── <NORMALIZED_VENDOR_NAME>/
│   └── <NORMALIZED_VENDOR_PART_NUMBER>/
│       ├── FIRMWARE_BINARY_1.bin
│       └── FIRMWARE_BINARY_2.bin
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
│       ├── ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.3.bin
│       └── ACMECORP_QSFP-100G-AOC-GENERIC_2_ENDM_1.2.4.bin
├── EXAMPLE_INC/
│   └── QSFP_200G_LR4/
│       └── EXAMPLE_INC_QSFP_200G_LR4_2.0.1.bin
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

1. **Parse `transceiver_firmware_info.csv`** to obtain the list of available firmware binaries, their versions, and associated vendor and part numbers.
2. **Parse `transceiver_dut_info.csv`** to identify the transceivers present on each DUT.
3. **Parse `transceiver_common_attributes.csv`** to get the gold firmware version for each transceiver type.
4. **For each unique combination of normalized vendor name and normalized part number on the DUT**, perform version sorting and selection:
   - Parse firmware versions using semantic versioning (X.Y.Z format)
   - Sort available firmware versions in descending order (most recent first)
   - **Selection criteria:**
     - Always include the gold firmware version (from `transceiver_common_attributes.csv`)
     - Include the two most recent firmware versions in addition to the gold version
     - This ensures at least 2 firmware versions are available for upgrade testing, with the gold version guaranteed to be present as the third firmware binary. If there are fewer than 3 firmware versions available for a transceiver, the entire test will fail.
5. **Copy only the selected firmware binaries** to the target directory structure on the DUT.
6. **Validate firmware binary integrity** using MD5 checksums after copying.

**Cleanup:**

- The firmware binary folder on the DUT (`/tmp/cmis_cdb_firmware/`) will be deleted after the test module run is complete to ensure a clean state for subsequent tests
- Cleanup includes removing both the directory structure and any temporary files created during the process

##### 1.1.3 CMIS CDB Firmware Upgrade Tests

**Prerequisites:**

1. **DOM polling must be disabled** to prevent race conditions between I2C transactions and the CDB mode for modules that cannot support CDB background mode.
2. **Platform-specific processes:** On some platforms, `thermalctld` or similar user processes that perform I2C transactions with the module may need to be stopped during firmware operations.
3. **Firmware requirements:**
   - At least two firmware versions must be available for each transceiver type to enable upgrade testing
   - The gold firmware version (specified in `transceiver_common_attributes.csv`) must be available
   - All firmware versions must support the CDB protocol for proper testing
4. **Module capabilities:** The module must support dual banks for firmware upgrade operations.
5. **Network connectivity:** The DUT must have network access to the firmware server specified in `cmis_cdb_firmware_base_url.csv` for downloading firmware binaries.

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
| 1 | Firmware download validation | 1. Download the gold firmware using the sfputil CLI<br>2. Wait until CLI execution completes | 1. CLI execution should finish within 30 mins and return 0 <br>2. Active FW version should remain unchanged<br>3. Inactive FW version should reflect the gold firmware version<br> 4. No link flap should be seen<br>5. The kernel has no error messages in syslog<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
| 2 | Firmware activation validation | 1. Shut down all the interfaces part of the physical ports<br>2. Execute firmware run<br>3. Execute firmware commit<br>4. Reset the transceiver and wait for 5 seconds<br>5. Startup all the interfaces in Step 1 | 1. The return code on step 2 and 3 is 0 (Return code 0 indicates success)<br>2. Active firmware version should now match the previous inactive firmware version<br>3. Inactive firmware version should now match the previous active firmware version<br>4. `sfputil show fwversion` CLI now should show the “Committed Image” to the current active bank<br>5. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
|3 | Firmware download validation with invalid firmware binary | Download an invalid firmware binary (any file not released by the vendor) | 1. The active firmware version does not change<br>2. The inactive firmware version remains unchanged or is set to `0.0.0` or `N/A`<br> 3.  No change in "Committed Image"<br>4. No link flap should be seen<br>5. The kernel has no error messages in syslog<br>6. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
|4 | Firmware download abort | 1. Start the firmware download and abort at approximately 10%, 40%, 70%, 90%, and 95%<br>2. Use CTRL+C or kill the download process<br>3. OR reset the optics using sfputil reset<br>4. OR remove the optics and re-insert | 1. Active firmware version remains unchanged<br>2. Inactive firmware version is invalid i.e. N/A or 0.0.0<br>3. No change in "Committed Image"<br>4. Critical process such as `xcvrd`, `syncd`  `orchagent` does not crash/restart. |
|5 | Successful firmware download after aborting | 1. Perform steps in TC #4 followed by TC #1 | All the expectation of test case #4 and case #1 must be met |
|6 | Firmware download validation post reset | 1. Perform steps in TC #1<br>2. Execute `sfputil reset PORT` and wait for it to finish | All the expectation of test case #1 must be met |
|7 | Ensure static fields of EEPROM remain unchanged | 1. Perform steps in TC #1<br>2. Perform steps in TC #2 | 1. All the expectations of TC #1 and #2 must be met<br>2. Ensure after each step 1 and 2 that the static fields of EEPROM (e.g., vendor name, part number, serial number, vendor date code, OUI, and hardware revision) remain unchanged |

#### CLI commands

**Note**

1. `<port>` in the below commands should be replaced with the logical port number i.e. EthernetXX

2. `<namespace>` in the below commands should be replaced with the asic of the port.

Issuing shutdown command for a port
```
sudo config interface -n '<namespace>' shutdown <port>
```

Issuing startup command for a port
```
sudo config interface -n '<namespace>' startup <port>
```

Check link status of a port
```
show interface status <port>
```

Enable/disable DOM monitoring for a port

**Note:** For breakout cables, always issue this command for the first subport within the breakout port group, irrespective of the specific subport currently in use.
```
config interface -n '<namespace>' transceiver dom <port> enable/disable

Verification
sonic-db-cli -n '<namespace>' CONFIG_DB hget "PORT|<port>" "dom_polling"

Expected o/p
For enable: "dom_polling" = "enabled" or "(nil)"
For disable: "dom_polling" = "disabled"
```

Restart `xcvrd`

```
docker exec pmon supervisorctl restart xcvrd
```

Get uptime of `xcvrd`

```
docker exec pmon supervisorctl status xcvrd | awk '{print $NF}'
```

Start/Stop `thermalctld` (if applicable)

```
docker exec pmon supervisorctl start thermalctld
OR
docker exec pmon supervisorctl stop thermalctld
```

CLI to get link flap count from redis-db

```
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "flap_count"
```

CLI to get link uptime/downtime from redis-db

```
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "last_up_time"
sonic-db-cli -n '<namespace>' APPL_DB hget "PORT_TABLE:<port>" "last_down_time"
```

Restart `pmon`

```
sudo systemctl restart pmon
```

Restart `swss`

```
sudo systemctl restart swss
```

Restart `syncd`

```
sudo systemctl restart syncd
```

sfputil reset

```
sudo sfputil reset <port>
```

Check if transceiver is present

```
sudo sfputil show presence -p <port>
```

Dump EEPROM of the transceiver

```
sudo sfputil show eeprom -p <port>
```

Check transceiver specific information through CLI relying on redis-db

```
show int transceiver info <port>
```

Check transceiver error-status through CLI relying on redis-db

```
show int transceiver error-status <port>
```

Check transceiver error-status through CLI relying on transceiver HW

```
show int transceiver error-status -hw <port>
```

Check FW version of the transceiver

```
sudo sfputil show fwversion <port>
```

Download firmware

```
sudo sfputil download <port> <fwfile>
```

Run firmware

```
sudo sfputil firmware run <port>
```

Commit firmware

```
sudo sfputil firmware commit <port>
```

Finding I2C errors from dmesg

```
dmesg -T -L -lerr
```
