# Transceiver Onboarding Test Plan

## Scope

This test plan outlines a comprehensive framework for ensuring feature parity for new transceivers being onboarded to SONiC. The goal is to automate all tests listed in this document, covering the following areas:

- **Link Behavior**: Test link behavior using shut/no shut commands and under process crash and device reboot scenarios.
- **Transceiver Information Fields**: Verify transceiver specific fields (Vendor name, part number, serial number) via CLI commands, ensuring values match expectations.
- **Firmware**: Check firmware version readability and compliance with vendor-suggested values, using regex for version pattern matching.
- **DOM Data**: Ensure Digital Optical Monitoring (DOM) data is correctly read and within acceptable ranges.
- **Flags and Alerts**: Confirm no unexpected flags (e.g., Loss of Signal (LOS), Loss of Lock (LOL), DOM warnings) are set.
- **Remote Reseat**: Verify support for remote reseat functionality.

**Transceiver Specific Capabilities** (if available):

- Adjustments to frequency and tx power.
- Configuration of different Forward Error Correction (FEC) modes.
- For breakout cables, ensure specific lanes are correctly modified by shut/no shut or other lane specific commands.

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
- SFF-8636
- SFF-8436
- SFF-8472

## Testbed Topology

A total of 2 ports of a device with the onboarding transceiver should be connected with a cable. Each of these ports can be on the same device or different devices as well. In the case of a breakout cable, the expectation is to connect all sides of the cable to the DUT and test each port individually.

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

### 1. Tests not involving traffic

These tests do not require traffic and are standalone, designed to run on a Device Under Test (DUT) with the transceiver plugged into 2 ports, connected by a cable.

**Breakout Cable Assumptions for the Below Tests:**

- All sides of the breakout cable should be connected to the DUT, and each port should be tested individually starting from subport 1 to subport N. The test should be run in reverse order as well i.e. starting from subport N to subport 1.
- For link toggling tests on a subport, it's crucial to ensure that the link status of remaining subports of the breakout port group remains unaffected.

**Pre-requisites for the Below Tests:**

1. A file `transceiver_dut_info.json` (located in `ansible/files/transceiver/inventory` directory) should be present to describe the metadata of the transceiver connected to every port of each DUT. The file should use the following JSON format:

    ```json
    {
      "normalization_mappings": {
        "vendor_names": {
          "ACME Corp.": "ACME_CORP",
          "Example & Co": "EXAMPLE_CO",
          "Vendor/Inc": "VENDOR_INC"
        },
        "part_numbers": {
          "QSFP-100G-AOC-15M": "QSFP-100G-AOC-GENERIC_2_ENDM",
          "QSFP-100G-AOC-10M": "QSFP-100G-AOC-GENERIC_2_ENDM",
          "QSFP-100G-AOC-3M": "QSFP-100G-AOC-GENERIC_1_ENDM",
          "SFP-1000BASE-LX": "SFP-1000BASE-LX"
        }
      },
      "dut_name_1": {
        "port_1": {
          "vendor_name": "ACME Corp.",
          "vendor_pn": "QSFP-100G-AOC-15M",
          "vendor_sn": "serial_number",
          "vendor_date": "vendor_date_code",
          "vendor_oui": "vendor_oui",
          "vendor_rev": "revision_number"
        },
        "port_2": {
          "vendor_name": "Example & Co",
          "vendor_pn": "SFP-1000BASE-LX"
        }
      },
      "dut_name_2": {
        "port_1": {
          "vendor_name": "Vendor/Inc",
          "vendor_pn": "QSFP-100G-AOC-10M"
        }
      }
    }
    ```

    **Field Definitions:**

    **Global Normalization Mappings:**
    - `normalization_mappings.vendor_names`: Dictionary mapping raw vendor names to their normalized forms using the normalization rules described in the [CMIS CDB Firmware Binary Management](#141-cmis-cdb-firmware-binary-management) section.
    - `normalization_mappings.part_numbers`: Dictionary mapping raw part numbers to their normalized forms using the normalization rules described in the [CMIS CDB Firmware Binary Management](#141-cmis-cdb-firmware-binary-management) section.

    **Per-Port Fields:**

    **Mandatory Fields:**
    - `vendor_name`: The name of the vendor as specified in the transceiver's EEPROM.
    - `vendor_pn`: The vendor part number as specified in the transceiver's EEPROM.

    **Field Handling Rules:**
    - **Normalized values are derived automatically**: The framework will look up `vendor_name` and `vendor_pn` in the `normalization_mappings` section to get the corresponding normalized values.
    - **Default normalization**: If no mapping is found in `normalization_mappings`, the normalized value defaults to the original value (with basic cleanup applied).
    - **Cable length normalization**: For modules such as **AOC cables** (or any module whose part number includes a cable length), it is **mandatory** to provide a mapping in `normalization_mappings.part_numbers` following the cable length normalization rules.

    **Optional Fields:**
    - `vendor_sn`: The vendor serial number.
    - `vendor_date`: The vendor date code.
    - `vendor_oui`: The vendor OUI.
    - `vendor_rev`: The vendor revision number.

    Functionality to parse the above files and store the data in a dictionary should be implemented in the test framework. This dictionary should act as a source of truth for the test cases.  
    The `normalized_vendor_name` and `normalized_vendor_pn` from `transceiver_dut_info.json` file should be used to fetch the common attributes of the transceiver from the appropriate per-category JSON file for a given port.

    Example of a dictionary created by parsing the above files:

    ```python
    {
        "dut_name_1": {
            "port_1": {
                "vendor_name": "ACME Corp.",
                "normalized_vendor_name": "ACME_CORP",  # looked up from normalization_mappings
                "vendor_pn": "QSFP-100G-AOC-15M",
                "normalized_vendor_pn": "QSFP-100G-AOC-GENERIC_2_ENDM",  # looked up from normalization_mappings
                "vendor_sn": "serial_number",
                "vendor_date": "vendor_date_code",
                "vendor_oui": "vendor_oui",
                "vendor_rev": "revision_number"
            },
            "port_2": {
                "vendor_name": "Example & Co",
                "normalized_vendor_name": "EXAMPLE_CO",  # looked up from normalization_mappings
                "vendor_pn": "SFP-1000BASE-LX",
                "normalized_vendor_pn": "SFP-1000BASE-LX",  # looked up from normalization_mappings (same value)
                "vendor_sn": None,  # optional field not provided
                "vendor_date": None,
                "vendor_oui": None,
                "vendor_rev": None
            }
        }
    }
    ```

2. Multiple JSON files based on test category should be present to define the attributes for each transceiver type and the corresponding group of tests. Each JSON file should include a `defaults` section containing default value of the attributes if not overridden and a `transceivers` section for overriding the default values based on specific requirements.

    **Recommended JSON files and grouping:**

    - `eeprom_attributes.json`      (EEPROM tests)
    - `system_test_attributes.json` (System tests)
    - `physical_oir_attributes.json` (Physical OIR)
    - `soft_oir_attributes.json`    (Soft OIR / remote reseat)
    - `cdb_fw_upgrade_attributes.json` (CDB FW Upgrade tests)
    - `dom_attributes.json`         (DOM)
    - `vdm_attributes.json`         (VDM)
    - `pm_attributes.json`          (PM)

    Each file should be located in the `ansible/files/transceiver/inventory` directory and use a similar hierarchical structure, keyed by normalized vendor name and part number, with support for platform/HWSKU overrides as needed.

    **Schema of transceiver attributes JSON files:**

    ```json
    {
      "mandatory": [
        "field_1",
        "field_2", 
        "field_3"
      ],
      "defaults": {
        "field_4": "value_4",
        "field_5": "value_5",
        "field_6": "value_6"
      },
      "platform_specific": {
        "PLATFORM_NAME": {
          "field_4": "platform_override_value"
        }
      },
      "hwsku_specific": {
        "HWSKU_NAME": {
          "field_5": "hwsku_override_value"
        }
      },
      "dut_specific": {
        "DUT_NAME": {
          "field_1": "dut_specific_value_1"
        }
      },
      "transceivers": {
        "NORMALIZED_VENDOR_NAME": {
          "defaults": {
            "field_6": "vendor_default_value"
          },
          "NORMALIZED_VENDOR_PN": {
            "field_1": "specific_value_1",
            "field_2": "specific_value_2",
            "field_3": "specific_value_3",
            "platform_hwsku_overrides": {
              "PLATFORM_NAME+HWSKU_NAME": {
                "field_1": "highest_priority_value"
              }
            }
          }
        }
      }
    }
    ```

    **Key Design Principles:**

    - **Mandatory vs Optional Fields**: Fields listed in `mandatory` must be explicitly provided somewhere in the hierarchy and cannot rely on defaults. Fields in `defaults` are optional and provide fallback values.
    - **No Overlap**: A field should **never** appear in both `mandatory` and `defaults` sections as this creates logical inconsistency.
    - **Validation Order**: The framework should first validate that all mandatory fields can be resolved through the priority hierarchy, then apply defaults for any missing optional fields.
    - **Normalization Integration**: The normalized vendor name and part number are automatically derived from the `normalization_mappings` using the raw vendor name and part number as keys. If no mapping exists, the original value is used with basic cleanup applied.
    - **Category Isolation**: Each category file should only contain attributes relevant to its specific test domain to maintain clear separation of concerns.
    - **Backward Compatibility**: Missing optional sections (platform_specific, hwsku_specific, etc.) are silently ignored to support gradual adoption and legacy configurations.

    **Key Structure Components:**
    - `mandatory`: List of mandatory fields that must be present in the transceiver attributes
    - `defaults`: Default values for the transceiver or test attributes
    - `platform_specific`: Platform-specific overrides (optional)
    - `hwsku_specific`: HWSKU-specific overrides (optional)
    - `dut_specific`: DUT-specific overrides (optional) wherein the `DUT_NAME` is the inventory based hostname of the DUT
    - `transceivers`: Normalized vendor name and part number specific configurations. Also contains transceiver specific attributes (mandatory)
        - `platform_hwsku_overrides`: Highest priority overrides for specific platform+HWSKU combinations within each transceiver configuration (optional)
    > Note: Each sub-section can contain its own `defaults` fields.

    **Priority-based attribute resolution (highest to lowest):**

    1. **DUT-specific**: `dut_specific.<DUT_NAME>`
    2. **Normalized Vendor Name + PN + Platform + HWSKU**: `transceivers.<NORMALIZED_VENDOR_NAME>.<NORMALIZED_PN>.platform_hwsku_overrides.<PLATFORM>+<HWSKU>`
    3. **Normalized Vendor Name + PN**: `transceivers.<NORMALIZED_VENDOR_NAME>.<NORMALIZED_PN>`
    4. **Normalized Vendor Name (defaults)**: `transceivers.<NORMALIZED_VENDOR_NAME>.defaults`
    5. **HWSKU-specific**: `hwsku_specific.<HWSKU>` (if present in the file)
    6. **Platform-specific**: `platform_specific.<PLATFORM>` (if present in the file)
    7. **Global defaults**: `defaults`

    > **Note:** For platform+HWSKU combinations in `platform_hwsku_overrides`, the key format is `"<PLATFORM_NAME>+<HWSKU_NAME>"` where the platform name and HWSKU name are concatenated with a literal `+` symbol.

    **Example structure for a category file (e.g., `eeprom_attributes.json`):**

    ```json
    {
      "mandatory": [
        "vendor_name",
        "normalized_vendor_name",
        "vendor_pn", 
        "normalized_vendor_pn",
        "dual_bank_supported"
      ],
      "defaults": {
        "vdm_supported": false,
        "cdb_backgroundmode_supported": false,
        "sfputil_eeprom_dump_time": 2
      },
      "transceivers": {
        "NORMALIZED_VENDOR_A": {
          "defaults": {
            "vdm_supported": false,
            "cdb_backgroundmode_supported": false
          },
          "NORMALIZED_VENDOR_PN_ABC": {
            "vendor_name": "Vendor A",
            "normalized_vendor_name": "VENDOR_ABC",
            "vendor_pn": "ABC-1234", 
            "normalized_vendor_pn": "NORMALIZED_VENDOR_PN_ABC",
            "dual_bank_supported": true,
            "vdm_supported": true,
            "cdb_backgroundmode_supported": true,
            "platform_hwsku_overrides": {
              "PLATFORM_ABC+VENDOR_HWSKU_ABC": {
                "sfputil_eeprom_dump_time": 5
              }
            }
          }
        }
      }
    }
    ```

    **Example structure for a system tests category file (`system_test_attributes.json`):**

    ```json
    {
      "mandatory": [
        "max_allowed_failures",
        "port_toggle_stress_iterations"
      ],
      "defaults": {
        "verify_lldp_on_link_up": true,
        "port_wait_time_after_shutdown_sec": 2,
        "port_wait_time_after_startup_sec": 2,
        "port_toggle_cycle_delay_sec": 1,
        "port_range_toggle_stress_iterations": 50,
        "port_range_toggle_wait_time_after_startup_sec": 2,
        "transceiver_operation_scaling_time": 5,
        "xcvrd_restart_settle_time": 10,
        "pmon_restart_settle_time": 10,
        "swss_restart_settle_time": 10,
        "expect_pmon_restart": true,
        "syncd_restart_settle_time": 10,
        "config_reload_settle_time": 15,
        "cold_reboot_settle_time": 60,
        "cold_reboot_stress_iterations": 10,
        "warm_reboot_settle_time": 45,
        "fast_reboot_settle_time": 30
      },
      "dut_specific": {
        "DUT_NAME": {
          "ports_to_be_stressed": ["Ethernet0", "Ethernet1"]
        }
      },
      "transceivers": {
        "NORMALIZED_VENDOR_A": {
          "NORMALIZED_VENDOR_PN_ABC": {
            "max_allowed_failures": 1,
            "port_toggle_stress_iterations": 50,
            "cold_reboot_stress_iterations": 5,
            "platform_hwsku_overrides": {
              "PLATFORM_ABC+VENDOR_HWSKU_ABC": {
                "port_toggle_cycle_delay_sec": 2,
                "expect_pmon_restart": false
              }
            }
          }
        }
      }
    }
    ```

    **Guidance:**
      Use the same priority-based override and merging logic as described above for all per-category files.

    - Only include attributes relevant to the specific test category in each file.
    - This modular approach allows teams to update, validate, and extend test parameters for each category independently, and enables more targeted schema validation and review.

    **Attribute Management Infrastructure:**

    The test framework should be designed to load and merge attributes from all relevant category files for each transceiver, using the same hierarchical and override rules as described above. This enables category-specific test logic to access only the attributes it needs, while still supporting platform, HWSKU, and vendor/part number overrides.

    **Core Components:**

    1. **AttributeManager Class**: A central class responsible for loading, merging, and providing access to transceiver attributes
    2. **Category File Loader**: Loads JSON files for each test category
    3. **Priority Resolver**: Implements the 6-level priority hierarchy for attribute resolution
    4. **Validator**: Ensures mandatory fields are present

    **Data Structure Design:**

    A dictionary data structure should be used to store the merged attributes for each port, allowing for efficient access.
    The `transceiver_dut_info.json` file should be used as the source to retrieve the base attributes for each port (such as the basic transceiver information). Using this information, the framework can build a comprehensive view of the transceiver's capabilities and requirements by merging in the attributes from the per-category files on per-port basis for the DUT.  
    The resultant dictionary (`port_attributes_dict`) should be structured as follows keyed by port name:

    ```python
    {
        "PORT_NAME": {
            # Base transceiver information from transceiver_dut_info.json
            "BASE_ATTRIBUTES": {
                "vendor_name": "vendor_name",
                "normalized_vendor_name": "NORMALIZED_VENDOR_NAME",
                "vendor_pn": "vendor_part_number",
                "normalized_vendor_pn": "NORMALIZED_VENDOR_PN",
                "vendor_sn": "serial_number",
                "vendor_date": "vendor_date_code",
                "vendor_oui": "vendor_oui",
                "vendor_rev": "revision_number"
            },
            # Category-specific attributes with merged overrides applied
            "EEPROM_ATTRIBUTES": {
                "attribute_1": "value_1",
                "attribute_2": "value_2",
                ...
            }
            "SYSTEM_TEST_ATTRIBUTES": {
                "attribute_1": "value_1",
                "attribute_2": "value_2",
                ...
            }
            ...
        }
    }
    ```

    **Attribute Merging Algorithm:**

    The `port_attributes_dict` should be built using the following systematic process:

    1. **Initialize port dictionary** from `transceiver_dut_info.json` base attributes for each port
    2. **For each category file** (EEPROM, System, DOM, VDM, PM, etc.), perform priority-based attribute merging:
       - **Step 2a**: Start with global `defaults` section as the base layer
       - **Step 2b**: Apply `platform_specific.<PLATFORM>` overrides (if present and applicable)
       - **Step 2c**: Apply `hwsku_specific.<HWSKU>` overrides (if present and applicable)
       - **Step 2d**: Apply `transceivers.<NORMALIZED_VENDOR_NAME>.defaults` vendor-level defaults (if present)
       - **Step 2e**: Apply `transceivers.<NORMALIZED_VENDOR_NAME>.<NORMALIZED_PN>` specific attributes
       - **Step 2f**: Apply `platform_hwsku_overrides.<PLATFORM>+<HWSKU>` highest priority overrides (if present)
       - **Step 2g**: Apply `dut_specific.<DUT_NAME>` overrides (if present)
    3. **Validate mandatory fields** for the current category using the `mandatory` array - ensure all required fields are resolved
    4. **Store merged category attributes** under the appropriate category key (e.g., `EEPROM_ATTRIBUTES`, `SYSTEM_TEST_ATTRIBUTES`)
    5. **Add categorized attributes** to the `port_attributes_dict` for the current port
    6. **Attach the complete `port_attributes_dict`** to the DUT host object for the selected `enum_rand_one_per_hwsku_hostname`

    **Merging Behavior:**
    - **Dictionary merging**: Later priority levels completely override earlier values for the same key
    - **Missing sections**: If any priority level section is missing, it is silently skipped without error
    - **Key conflicts**: Higher priority levels always win - no merge conflict resolution needed

    **Implementation Requirements:**

    - **Error Handling**: Framework must handle missing files, invalid JSON, missing mandatory fields, and malformed data structures gracefully with descriptive error messages
    - **Logging**: Detailed logging of attribute resolution process for debugging

    **Error Scenarios:**
    - **Missing mandatory fields**: Framework should fail fast with clear identification of missing fields and their expected sources
    - **Invalid JSON schema**: Graceful handling with file path and line number information where possible  

    **How to Use:**

    - **Framework Integration**: The test framework automatically loads all relevant category files during test session initialization
    - **Attribute Resolution**: For each transceiver, the framework merges attributes using the priority hierarchy described above
    - **Category-Specific Access**: Each test category accesses only the attributes it needs, with all overrides pre-applied
    - **Runtime Access Pattern**: Tests access attributes using: `port_attributes_dict[port_name][category_key][attribute_name]` from the duthost for the selected `enum_rand_one_per_hwsku_hostname`
    - **Example Usage**:

      ```python
      port_attributes_dict = duthost.get_port_attributes()
      # Access EEPROM attributes for a specific port
      eeprom_attrs = port_attributes_dict["Ethernet0"]["EEPROM_ATTRIBUTES"]
      dual_bank_supported = eeprom_attrs["dual_bank_supported"]
      
      # Access system test attributes
      system_attrs = port_attributes_dict["Ethernet0"]["SYSTEM_TEST_ATTRIBUTES"] 
      max_failures = system_attrs["max_allowed_failures"]
      ```

    **Benefits:**

    - **Modular Design**: Maintainable and scalable as new test categories or attributes are added
    - **Independent Updates**: Enables independent updates and validation for each test category
    - **Conflict Prevention**: Reduces risk of accidental cross-category changes or conflicts
    - **Override Flexibility**: Comprehensive priority system supports various deployment scenarios
    - **Performance Optimized**: Efficient data structure design for fast attribute lookups

3. A `transceiver_firmware_info.csv` file (located in `ansible/files/transceiver/inventory` directory) should exist if a transceiver being tested supports CMIS CDB firmware upgrade. This file will capture the firmware binary metadata for the transceiver. Each transceiver should have at least 2 firmware binaries (in addition to the gold firmware binary) so that firmware upgrade can be tested. Following should be the format of the file

    ```csv
    normalized_vendor_name,normalized_vendor_pn,fw_version,fw_binary_name,md5sum
    <normalized_vendor_name_1>,<normalized_vendor_pn_1>,<firmware_version_1>,<firmware_binary_1>,<md5sum_1>
    <normalized_vendor_name_1>,<normalized_vendor_pn_1>,<firmware_version_2>,<firmware_binary_2>,<md5sum_2>
    <normalized_vendor_name_1>,<normalized_vendor_pn_1>,<firmware_version_3>,<firmware_binary_3>,<md5sum_3>
    # Add more vendor part numbers as needed
    ```

    For each firmware binary, the following metadata should be included:

    - `normalized_vendor_name`: The normalized vendor name, created by applying the normalization rules described in the [CMIS CDB Firmware Binary Management](#141-cmis-cdb-firmware-binary-management) section.
    - `normalized_vendor_pn`: The normalized vendor part number, created by applying the normalization rules described in the [CMIS CDB Firmware Binary Management](#141-cmis-cdb-firmware-binary-management) section.
    - `fw_version`: The version of the firmware.
    - `fw_binary_name`: The filename of the firmware binary.
    - `md5sum`: The MD5 checksum of the firmware binary.

4. A `cmis_cdb_firmware_base_url.csv` file (located in `ansible/files/transceiver/inventory` directory) should be present to define the base URL for downloading CMIS CDB firmware binaries. The file should follow this format:

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

#### 1.1 Link related tests

The following tests aim to validate the link status and stability of transceivers under various conditions.

| Step | Goal | Expected Results |
|------|------|------------------|
| Issue CLI command to shutdown a port | Validate link status using CLI configuration | Ensure that the link goes down |
| Issue CLI command to startup a port | Validate link status using CLI configuration | Ensure that the link is up and the port appears in the LLDP table. |
| In a loop, issue startup/shutdown command for a port 100 times | Stress test for link status validation | Ensure link status toggles to up/down appropriately with each startup/shutdown command. Verify ports appear in the LLDP table when the link is up |
| In a loop, issue startup/shutdown command for all ports 100 times | Stress test for link status validation | Ensure link status toggles to up/down appropriately for all relevant ports with each startup/shutdown command. Verify ports appear in the LLDP table when the link is up |
| Restart `xcvrd` | Test link and xcvrd stability | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table. Also ensure that xcvrd is up for at least 2 mins |
| Induce I2C errors and restart `xcvrd` | Test link stability in case of `xcvrd` restart + I2C errors | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table |
| Modify xcvrd.py to raise an Exception and induce a crash | Test link and xcvrd stability | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table. Also ensure that xcvrd is up for at least 2 mins |
| Restart `pmon` | Test link stability | Confirm `xcvrd` restarts successfully without causing link flaps for the corresponding ports, and verify their presence in the LLDP table |
| Restart `swss` | Validate transceiver re-initialization and link status post container restart | Ensure `xcvrd` restarts (for Mellanox platform, ensure pmon restarts) and the expected ports link up again, with port details visible in the LLDP table |
| Restart `syncd` | Validate transceiver re-initialization and link status post container restart | Ensure `xcvrd` restarts (for Mellanox platform, ensure pmon restarts) and the expected ports link up again, with port details visible in the LLDP table |
| Perform a config reload | Test transceiver re-initialization and link status | Ensure `xcvrd` restarts and the expected ports link up again, with port details visible in the LLDP table |
| Execute a cold reboot | Validate transceiver re-initialization and link status post-device reboot | Confirm the expected ports link up again post-reboot, with port details visible in the LLDP table |
| In a loop, execute cold reboot 100 times | Stress test to validate transceiver re-initialization and link status with cold reboot | Confirm the expected ports link up again post-reboot, with port details visible in the LLDP table |
| Execute a warm reboot (if platform supports it) | Test link stability through warm reboot | Ensure `xcvrd` restarts and maintains link stability for the interested ports, with their presence confirmed in the LLDP table |
| Execute a fast reboot (if platform supports it) | Validate transceiver re-initialization and link status post-device reboot | Confirm the expected ports link up again post-reboot, with port details visible in the LLDP table |

#### 1.2 `sfputil` Command Tests

The following tests aim to validate various functionalities of the transceiver (transceiver) using the `sfputil` command.

| Step | Goal | Expected Results |
|------|------|------------------|
| Verify if transceiver presence works with CLI | Transceiver presence validation | Ensure transceiver presence is detected |
| Reset the transceiver followed by issuing shutdown and then startup command | Transceiver reset validation | Ensure that the port is linked down after reset and is in low power mode (if transceiver supports it). Also, ensure that the DataPath is in DPDeactivated state and LowPwrAllowRequestHW (page 0h, byte 26.6) is set to 1. The shutdown and startup commands are later issued to re-initialize the port and bring the link up |
| Put transceiver in low power mode (if transceiver supports it) followed by restoring to high power mode | Transceiver low power mode validation | Ensure transceiver is in high power mode initially. Then put the transceiver in low power mode and ensure that the port is linked down and the DataPath is in DPDeactivated state. Ensure that the port is in low power mode through CLI. Disable low power mode and ensure that the link is up now and transceiver is in high power mode now |
| Verify EEPROM of the transceiver using CLI | Transceiver specific fields validation from EEPROM | Ensure transceiver specific fields are matching with the values retrieved from the transceiver dictionary created using the csv files |
| Verify DOM information of the transceiver using CLI when interface is in shutdown and no shutdown state (if transceiver supports DOM) | Basic DOM validation | Ensure the fields are in line with the expectation based on interface shutdown/no shutdown state |
| Verify EEPROM hexdump of the transceiver using CLI | Transceiver EEPROM hexdump validation | Ensure the output shows Lower Page (0h) and Upper Page (0h) for all 128 bytes on each page. Information from the transceiver dictionary created using the csv files can be used to validate contents of page 0h. Also, ensure that page 11h shows the Data Path state correctly |
| Verify firmware version of the transceiver using CLI (requires disabling DOM config) | Firmware version validation | Ensure the active and inactive firmware version is in line with the expectation from the transceiver dictionary created using the csv files |
| Verify different types of loopback | Transceiver loopback validation | Ensure that the various supported types of loopback work on the transceiver. The LLDP neighbor can also be used to verify the data path after enabling loopback (such as host-side input loopback) |

#### 1.3 `sfpshow` Command Tests

The following tests aim to validate various functionalities of the transceiver using the `sfpshow` command.

| Step | Goal | Expected Results |
|------|------|------------------|
| Verify transceiver specific information through CLI | Validate CLI relying on redis-db | Ensure transceiver specific fields match the values retrieved from transceiver dictionary created using the csv files |
| Verify DOM data is read correctly and is within an acceptable range (if transceiver supports DOM) | Validate CLI relying on redis-db | Ensure DOM data is read correctly and falls within the acceptable range |
| Verify transceiver status when the interface is in shutdown and no shutdown state | Validate CLI relying on redis-db | Ensure the fields align with expectations based on the interface being in shutdown or no shutdown state |
| Verify PM information (for C-CMIS transceivers) | Validate CLI relying on redis-db | Ensure that the PM related fields are populated |
| Verify VDM information for CMIS cables | Validate CLI relying on redis-db | Ensure that all the Pre-FEC and FERC media and host related VDM related fields are populated. The acceptable values for Pre-FEC fields are from 0 through 1e-4 and the FERC values should be <= 0|
| Verify transceiver error-status | Validate CLI relying on redis-db | Ensure the relevant port is in an "OK" state |
| Verify transceiver error-status with hardware verification | Validate CLI relying on transceiver hardware | Ensure the relevant port is in an "OK" state |

#### 1.4 CMIS CDB Firmware Upgrade Testing

##### 1.4.1 CMIS CDB Firmware Binary Management

###### 1.4.1.1 Firmware Binary Naming Guidelines

CMIS CDB firmware binaries must follow strict naming conventions to ensure compatibility across different filesystems and automation tools.

**Filename Requirements:**

1. **Character Restrictions:**
   - **Must not** contain spaces or special characters except hyphens (`-`), dots (`.`), and underscores (`_`)
   - Must be valid filenames for Windows, Linux, and macOS filesystems
   - Avoid reserved characters: `< > : " | ? * \ /`
   - Ensure that the filename does not start or end with special characters

2. **File Extension:**
   - Use `.bin` extension

###### 1.4.1.2 Normalization Rules for Vendor Name and Part Number

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

###### 1.4.1.3 Firmware Binary Storage on SONiC Device

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

- All directory and file names **must be uppercase** and follow the normalization rules defined in section 1.4.1.2
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

###### 1.4.1.4 Firmware Binary Storage on Remote Server

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

##### 1.4.2 CMIS CDB Firmware Copy to DUT via sonic-mgmt infrastructure

This section describes the automated process for copying firmware binaries to the DUT, ensuring only the required firmware versions are present for testing.

**Firmware Selection Algorithm:**

To ensure only the necessary firmware binaries are present for each transceiver:

1. **Parse `transceiver_firmware_info.csv`** to obtain the list of available firmware binaries, their versions, and associated vendor and part numbers.
2. **Parse `transceiver_dut_info.json`** to identify the transceivers present on each DUT.
3. **Parse the appropriate per-category attributes file** to get the gold firmware version for each transceiver type.
4. **For each unique combination of normalized vendor name and normalized part number on the DUT**, perform version sorting and selection:
   - Parse firmware versions using semantic versioning (X.Y.Z format)
   - Sort available firmware versions in descending order (most recent first)
   - **Selection criteria:**
   - Always include the gold firmware version (from the per-category attributes file)
     - Include the two most recent firmware versions in addition to the gold version
     - This ensures at least 2 firmware versions are available for upgrade testing, with the gold version guaranteed to be present as the third firmware binary. If there are fewer than 3 firmware versions available for a transceiver, the entire test will fail.
5. **Copy only the selected firmware binaries** to the target directory structure on the DUT.
6. **Validate firmware binary integrity** using MD5 checksums after copying.

**Cleanup:**

- The firmware binary folder on the DUT (`/tmp/cmis_cdb_firmware/`) will be deleted after the test module run is complete to ensure a clean state for subsequent tests
- Cleanup includes removing both the directory structure and any temporary files created during the process

##### 1.4.3 CMIS CDB Firmware Upgrade Tests

**Prerequisites:**

1. **DOM polling must be disabled** to prevent race conditions between I2C transactions and the CDB mode for modules that cannot support CDB background mode.
2. **Platform-specific processes:** On some platforms, `thermalctld` or similar user processes that perform I2C transactions with the module may need to be stopped during firmware operations.
3. **Firmware requirements:**
   - At least two firmware versions must be available for each transceiver type to enable upgrade testing
   - The gold firmware version (specified in the per-category attributes file) must be available
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

#### 1.5 Remote Reseat related tests

The following tests aim to validate the functionality of remote reseating of the transceiver module.
All the below steps should be executed in a sequential manner.

| TC No. | Step | Goal | Expected Results |
|------|------|------|------------------|
|1 | Issue CLI command to disable DOM monitoring | Remote reseat validation | Ensure that the DOM monitoring is disabled for the port |
|2 | Issue CLI command to shutdown the port | Remote reseat validation | Ensure that the port is linked down |
|3 | Reset the transceiver followed by a sleep for 5s | Transceiver reset validation | Ensure reset command executes successfully |
|4 | Put transceiver in low power mode (if LPM supported) | Remote reseat validation | Ensure that the port is in low power mode |
|5 | Put transceiver in high power mode (if LPM supported) | Remote reseat validation | Ensure that the port is in high power mode |
|6 | Issue CLI command to startup the port | Remote reseat validation | Ensure that the port is linked up and is seen in the LLDP table |
|7 | Issue CLI command to enable DOM monitoring for the port | Remote reseat validation | Ensure that the DOM monitoring is enabled for the port |

#### 1.6 Transceiver Specific Capabilities

##### 1.6.1 General Tests

| Step | Goal | Expected Results |
|------|------|------------------|
| Add `"skip_xcvrd": true,` to the `pmon_daemon_control.json` file and reboot the device | Ensure CMIS transceiver is in low power mode upon boot-up | Ensure the transceiver is in low power mode after device reboot. Revert back the file to original after verification |
| Disable the Tx by directly writing to the EEPROM/or by calling `tx_disable` API | Ensure Tx is disabled within the advertised time for CMIS transceivers | Ensure that the DataPath state changes from DPActivated to a different state within the MaxDurationDPTxTurnOff time (page 1h, byte 168.7:4). Issue shut/no shutdown command to restore the link. This can be a stress test |
| Adjust FEC mode | Validate FEC mode adjustment for transceivers supporting FEC | Ensure that the FEC mode can be adjusted to different modes and revert to original FEC mode after testing |
| Validate FEC stats counters | Validate FEC stats counters | Ensure that FEC correctable, uncorrectable and symbol errors have integer values |

##### 1.6.2 C-CMIS specific tests

| Step | Goal | Expected Results |
|------|------|------------------|
| Adjust frequency | Validate frequency adjustment for C-CMIS transceivers | Ensure that the frequency can be adjusted to minimum and maximum supported frequency and revert to original frequency after testing |
| Adjust tx power | Validate tx power adjustment for C-CMIS transceivers | Ensure that the tx power can be adjusted to minimum and maximum supported power and revert to original tx power after testing |

##### 1.6.3 VDM specific tests

**Prerequisites:**

1. DOM polling must be disabled to prevent race conditions between I2C transactions and the CDB mode for modules that cannot support CDB background mode.
2. Python APIs must be available to read the VDM data from the transceiver. The relevant APIs can be found at [sfp_optoe_base.py](https://github.com/sonic-net/sonic-platform-common/blob/cb5564c20ac74694f2391759f9235eee428a97d0/sonic_platform_base/sonic_xcvr/sfp_optoe_base.py#L58-L134)

| TC No. | Test | Steps | Expected Results |
|------|------|------|------------------|
|1 | VDM freeze when all the lanes have Tx enabled | 1. Set `FreezeRequest` = 1<br>2. Sleep for 10ms (`tVDMF` time)<br>3. Wait for `FreezeDone` bit == 1 | 1. Ensure `FreezeDone` is set within 500ms in step 3<br>2. Ensure all the VDM relevant sample groups and flag registers can be read successfully |
|2 | VDM unfreeze when all the lanes have Tx enabled  | 1. Set `FreezeRequest` = 0<br>2. Sleep for 10ms (`tVDMF` time)<br>3. Wait for `UnfreezeDone` bit == 1 | 1. Ensure UnfreezeDone is set within 500ms in step 3 |
|3 | VDM freeze and unfreeze when 1 or more lanes have Tx disabled   | 1. Shutdown the first lane of the physical port<br>2. Repeat the steps of TC #1<br>3. Repeat the steps of TC #2<br>4. Increase the number of lanes shutdown by 1 until all 8 lanes are disabled | 1. For step 2, follow the expectations of TC #1<br>2. For step 3, follow the expectations of TC #2 |
|4| VDM freeze and unfreeze with non sequential lanes Tx disabled | 1. Shutdown all the odd-numbered lanes of the physical port<br>2. Repeat the steps of TC #1<br>3. Repeat the steps of TC #2<br>4. Startup all the odd-numbered lanes and shutdown all the even-numbered lanes of the physical port and repeat step #2 and #3 | 1. For step 2, follow the expectations of TC #1<br>2. For step 3, follow the expectations of TC #2 |

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

show lldp table
```
show lldp table
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

config reload

```
sudo config reload
```

Cold reboot

```
sudo reboot -f
```

Warm reboot

```
sudo warm-reboot
```

sfputil reset

```
sudo sfputil reset <port>
```

Check if the port is in low power mode

```
sudo sfputil show lpmode -p <port>
```

Put port in low power mode

```
sudo sfputil lpmode on <port>
```

Check lpmode status of a port

```
sudo sfputil show lpmode -p <port>
```

Check if transceiver is present

```
sudo sfputil show presence -p <port>
```

Dump EEPROM of the transceiver

```
sudo sfputil show eeprom -p <port>
```

Dump EEPROM DOM information of the transceiver and verify fields based on the below information

```
sudo sfputil show eeprom -d -p <port>

Verification
For a port in shutdown state, following fields need to be verified
TX<lane_id>Bias is 0mA
TX<lane_id>Power is 0dBm


For a port in no shutdown state, following fields need to be verified
TX<lane_id>Bias is non-zero
TX<lane_id>Power is non-zero

```

Dump EEPROM hexdump of the transceiver

```
sudo sfputil show eeprom-hexdump -p <port> -n <PAGE_NUM>
```

Loopback commands

```
sudo sfputil debug loopback <port> <loopback_type>
```

Check transceiver specific information through CLI relying on redis-db

```
show int transceiver info <port>
```

Check DOM data through CLI relying on redis-db

```
show int transceiver dom <port>
```

Check transceiver status through CLI relying on redis-db and verify fields based on the below information

```
show int transceiver status <port>

Verification
For a port in shutdown state, following fields need to be verified
"TX disable status on lane <lane_id>" is True
"Disabled TX channels" is set for the corresponding lanes
"Data path state indicator on host lane <lane_id>" is DataPathInitialized
"Tx output status on media lane <lane_id>" is False
"Tx loss of signal flag on host lane <lane_id>" is True
"Tx clock and data recovery loss of lock on host lane <lane_id>" is True
"CMIS State (SW):" is READY

For a port in no shutdown state, following fields need to be verified
"TX disable status on lane <lane_id>" is False
"Disabled TX channels" is set to 0 for the corresponding lanes
"Data path state indicator on host lane <lane_id>" is DataPathActivated
"Tx output status on media lane <lane_id>" is True
"Tx loss of signal flag on host lane <lane_id>" is False
"Tx clock and data recovery loss of lock on host lane <lane_id> is False
Verify all the fields containing warning/alarm flags are set to False
"CMIS State (SW):" is READY

```

Check PM information (for C-CMIS transceivers) through CLI relying on redis-db

```
show int transceiver pm <port>
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

Get supported min and max frequency from CONFIG_DB

```
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_INFO|<port>" "supported_max_laser_freq"
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_INFO|<port>" "supported_min_laser_freq"
```

Adjust frequency

```
config interface -n '<namespace>' transceiver frequency <port> <frequency>
```

Get frequency from CONFIG_DB

```
sonic-db-cli -n '<namespace>' CONFIG_DB hget "PORT|<port>" "laser_freq"
```

Get current laser frequency

```
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_DOM_SENSOR|<port>" "laser_curr_freq"
```

Get supported min and max tx power from CONFIG_DB

```
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_INFO|<port>" "supported_max_tx_power"
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_INFO|<port>" "supported_min_tx_power"
```

Adjust tx power

```
config interface -n '<namespace>'transceiver tx-power <port> <tx_power>
```

Get tx power from CONFIG_DB

```
sonic-db-cli -n '<namespace>' CONFIG_DB hget "PORT|<port>" "tx_power"
```

Get current tx power

```
sonic-db-cli -n '<namespace>' STATE_DB hget "TRANSCEIVER_DOM_SENSOR|<port>" "tx_config_power"
```

Modify pmon_daemon_control.json file to skip xcvrd upon device boot-up

```
platform=$(show version | grep "Platform" | awk -F': ' '{print $2}')
hwsku=$(show version | grep "HwSKU" | awk -F': ' '{print $2}')
cp /usr/share/sonic/device/$platform/$hwsku/pmon_daemon_control.json /usr/share/sonic/device/$platform/$hwsku/pmon_daemon_control.json.orig
#Add "skip_xcvrd": true, to the pmon_daemon_control.json file
```
