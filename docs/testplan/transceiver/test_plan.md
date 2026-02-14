# Transceiver Onboarding Test Plan

## Scope

This test plan outlines a comprehensive framework for ensuring feature parity for new transceivers being onboarded to SONiC. The goal is to automate all tests listed in this document, covering the following areas:

- **Link Behavior**: Test link behavior using shut/no shut commands and under process crash and device reboot scenarios.
- **Transceiver Information Fields**: Verify transceiver specific fields (Vendor name, part number, serial number) via CLI commands, ensuring values match expectations.
- **Firmware**: Check firmware version readability and compliance with vendor-suggested values, using regex for version pattern matching.
- **DOM Data**: Ensure Digital Optical Monitoring (DOM) data is correctly read and within acceptable ranges.
- **Flags and Alerts**: Confirm no unexpected flags (e.g., Loss of Signal (LOS), Loss of Lock (LOL), DOM warnings) are set.
- **Firmware Management**: Test firmware upgrade under various scenarios.
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

### Test Prerequisites and Configuration Files

The following configuration files must be present to enable comprehensive transceiver testing.

> 📁 **Example Files**: Examples of all configuration files described below are available in the [`examples/inventory/`](examples/inventory/) directory. Use these as templates when creating your own configuration files.

### Test Category Prerequisite Tests

Prerequisite tests provide early readiness validation before a category's main test cases execute. They run after attribute resolution and optional validation, serving as gating checks to verify basic functionality before proceeding with the full test suite for a test category.

**File location:** `ansible/files/transceiver/inventory/prerequisites.json`

**Structure:** Grouped by test category, with each entry specifying a test module and function:

```json
{
  "eeprom": [
    {
      "name": "eeprom_readability",
      "module": "tests/transceiver/eeprom/test_eeprom_basic.py",
      "function": "test_eeprom_pages"
    }
  ],
  "dom": [
    {
      "name": "dom_basic",
      "module": "tests/transceiver/dom/test_dom_basic.py",
      "function": "test_dom_read"
    }
  ]
}
```

**Execution behavior:**

1. Run immediately before each category's main tests (after attribute resolution and optional validation)
2. Only the current category's list is loaded and executed; other categories' lists are deferred
3. Execution order within each category array is preserved
4. Duplicate tests (same module+function) are executed only once per category
5. If the file or category key is absent, no prerequisites run for that category

**Common prerequisite test examples:**

- Verify transceiver presence on the port
- Verify port speed in CONFIG_DB matches expected speed per dut_info.json
- Ensure RS FEC is configured if applicable
- Validate active firmware version matches the expected gold firmware
- Confirm I2C communication functionality via `sfputil`
- Verify link operational status (link-up state)
- Ensure critical system processes (`xcvrd`, `pmon`, `syncd`, `orchagent`) are running

#### 1. DUT Info Files

> 📊 **Visual Guide**: See the [File Organization Diagram](diagrams/file_organization.md) for a visual overview of the file structure and relationships.

Transceiver metadata is organized into per-DUT files located in the `ansible/files/transceiver/inventory/dut_info/` directory. Each file is named after its corresponding DUT hostname (e.g., `sonic-device-01.json`) and contains port-specific transceiver configurations for that device.

Additionally, a shared `normalization_mappings.json` file in the `ansible/files/transceiver/inventory/` directory provides vendor name and part number normalization rules used across all DUTs.

Each per-DUT file supports multiple port specification formats for flexibility and efficiency:

Example of `dut_info/sonic-device-01.json`:

```json
{
  "Ethernet0:7": {
    "vendor_name": "ACME Corp.",
    "vendor_pn": "QSFP-2X100G-AOC-15M",
    "vendor_sn": "serial_number_001",
    "vendor_date": "vendor_date_code",
    "vendor_oui": "vendor_oui",
    "vendor_rev": "revision_number",
    "hardware_rev": "hardware_revision_number"
  },
  "Ethernet0": {"transceiver_configuration": "AOC-200-QSFPDD-2x100G_200G_SIDE-0x1-0x1"},
  "Ethernet1": {"transceiver_configuration": "AOC-200-QSFPDD-2x100G_200G_SIDE-0x2-0x2"},
  "Ethernet2": {"transceiver_configuration": "AOC-200-QSFPDD-2x100G_200G_SIDE-0x4-0x4"},
  "Ethernet3": {"transceiver_configuration": "AOC-200-QSFPDD-2x100G_200G_SIDE-0x8-0x8"},
  "Ethernet4": {"transceiver_configuration": "AOC-100-QSFPDD-2x100G_100G_SIDE-0x10-0x10"},
  "Ethernet5": {"transceiver_configuration": "AOC-100-QSFPDD-2x100G_100G_SIDE-0x20-0x20"},
  "Ethernet6": {"transceiver_configuration": "AOC-100-QSFPDD-2x100G_100G_SIDE-0x40-0x40"},
  "Ethernet16,Ethernet20,Ethernet24": {
    "vendor_name": "Example & Co",
    "vendor_pn": "SFP-1000BASE-LX",
    "transceiver_configuration": "LR-1-SFP-1G_STRAIGHT-0x01-0x01"
  },
  "Ethernet28:33,Ethernet36,Ethernet40:45": {
    "vendor_name": "Vendor/Inc",
    "vendor_pn": "QSFP-100G-AOC-10M",
    "transceiver_configuration": "AOC-100-QSFP-100G_STRAIGHT-0x0F-0x0F"
  }
}
```

##### Normalization Mappings File

**File location:** `ansible/files/transceiver/inventory/normalization_mappings.json`

**Purpose:** Provides a centralized, shared mapping for normalizing vendor names and part numbers across all DUTs.

**Structure:**

- `vendor_names`: Dictionary mapping raw vendor names to their normalized forms using the normalization rules described in the [CMIS CDB Firmware Binary Management](#141-cmis-cdb-firmware-binary-management) section.
- `part_numbers`: Dictionary mapping raw part numbers to their normalized forms using the normalization rules described in the [CMIS CDB Firmware Binary Management](#141-cmis-cdb-firmware-binary-management) section.

Example of `normalization_mappings.json`:

```json
{
  "vendor_names": {
    "ACME Corp.": "ACME_CORP",
    "Example & Co": "EXAMPLE_CO",
    "Vendor/Inc": "VENDOR_INC",
    "Tech-Solutions Ltd.": "TECH_SOLUTIONS_LTD"
  },
  "part_numbers": {
    "QSFP-100G-AOC-15M": "QSFP-100G-AOC-GENERIC_2_ENDM",
    "QSFP-100G-AOC-10M": "QSFP-100G-AOC-GENERIC_2_ENDM",
    "QSFP-100G-AOC-3M": "QSFP-100G-AOC-GENERIC_1_ENDM",
    "QSFP-100G-AOC-25M": "QSFP-100G-AOC-GENERIC_2_ENDM",
    "QSFP-2X100G-AOC-15M": "QSFP-2X100G-AOC-GENERIC_2_ENDM",
    "QSFP-2X100G-AOC-10M": "QSFP-2X100G-AOC-GENERIC_2_ENDM",
    "SFP-1000BASE-LX": "SFP-1000BASE-LX",
    "DAC-400G-5M": "DAC-400G-GENERIC_1_ENDM"
  }
}
```

##### Per-DUT File Structure

**File location:** `ansible/files/transceiver/inventory/dut_info/<dut_hostname>.json`

**Naming convention:** Each file must be named exactly as the DUT's hostname (e.g., `sonic-device-01.json`, `lab-switch-05.json`).

**Discovery:** The framework automatically discovers and loads the appropriate DUT file based on the current testbed's DUT hostname.

##### Per-Port Fields

**Mandatory Fields:**

- `vendor_name`: The name of the vendor as specified in the transceiver's EEPROM.
- `vendor_pn`: The vendor part number as specified in the transceiver's EEPROM.
- `transceiver_configuration`: The transceiver configuration name following the format defined in the **Transceiver Configuration Format** section below. The DEPLOYMENT component of this field is used to reference deployment configurations in the per-category attribute files.

**Optional Fields:**

- `vendor_sn`: The vendor serial number.
- `vendor_date`: The vendor date code.
- `vendor_oui`: The vendor OUI.
- `vendor_rev`: The vendor revision number.
- `hardware_rev`: The hardware revision number.

##### Field Handling Rules

- **Normalized values are derived automatically**: The framework will look up `vendor_name` and `vendor_pn` in the `normalization_mappings.json` file to get the corresponding normalized values.
- **Default normalization**: If no mapping is found in `normalization_mappings.json`, the normalized value defaults to the original value.
- **Cable length normalization**: For modules such as **AOC cables** (or any module whose part number includes a cable length), it is **mandatory** to provide a mapping in `normalization_mappings.json` `part_numbers` section following the cable length normalization rules.
- **Port expansion processing**: Range and list specifications are expanded to individual ports before attribute processing.
- **Overlapping port specifications**: Multiple port specifications can target the same port. Later specifications override attributes from earlier ones, enabling efficient configuration patterns like defining shared attributes in ranges and port-specific attributes individually.
- **Deferred mandatory field validation**: Mandatory fields are validated after all applicable port specifications have been merged for each port, allowing flexible configuration where some fields come from ranges and others from individual port entries.
- **Transceiver configuration format**: The `transceiver_configuration` field uses a mandatory 6-component naming format to fully describe a transceiver's deployment characteristics:

    **Format (Mandatory)**: `{TYPE}-{SPEED}-{FORM_FACTOR}-{DEPLOYMENT}-{MEDIA_LANE_MASK}-{HOST_LANE_MASK}`

    **Note**: The hyphen (`-`) character acts as a delimiter between each component, enabling straightforward parsing by splitting the configuration string on this delimiter.

    **Component Definitions:**

**Physical Port Based Components** (determined by the physical transceiver module):

- **TYPE**: Cable/optics  type - AOC, AEC, LPO, LRO, TRO, CPO, DAC, DR, FR, LR, ZR, Backplane
- **SPEED**: Total aggregate speed in Gbps (e.g., 1, 10, 25, 100, 200, 400, 800, 1600)
- **FORM_FACTOR**: Physical form factor - CPO, OSFP, QSFPDD, QSFP, SFP
- **DEPLOYMENT**: Traffic deployment pattern describing how the speed is distributed (this list is expected to grow in future). This component serves as a means to combine similar attributes for a particular deployment pattern together in test attribute JSON files, grouping required attributes irrespective of the transceiver or platform vendor:
  - `2x100G_200G_SIDE` - 200G side of a 2x100G breakout cable
  - `2x100G_100G_SIDE` - 100G side of a 2x100G breakout cable
  - `4x100G_400G_SIDE` - 400G side of a 4x100G breakout cable
  - `4x100G_100G_SIDE` - 100G side of a 4x100G breakout cable
  - `2x200G_400G_SIDE` - 400G side of a 2x200G breakout cable
  - `2x200G_200G_SIDE` - 200G side of a 2x200G breakout cable
  - `4x200G_800G_SIDE` - 800G side of a 4x200G breakout cable
  - `4x200G_200G_SIDE` - 200G side of a 4x200G breakout cable
  - `8x100G_800G_SIDE` - 800G side of an 8x100G breakout cable
  - `8x100G_100G_SIDE` - 100G side of an 8x100G breakout cable
  - `400G_STRAIGHT` - 400G total as single port (no breakout)
  - `800G_STRAIGHT` - 800G total as single port (no breakout)
  - `1G_STRAIGHT` - 1G total as single port

**Logical Port Based Components** (specific to individual logical interfaces):

- **MEDIA_LANE_MASK**: Hexadecimal bitmask indicating which media/optical lanes are used (e.g., 0x01, 0x0F, 0xFF)
- **HOST_LANE_MASK**: Hexadecimal bitmask indicating which host/electrical lanes are used (e.g., 0x01, 0x0F, 0xFF)

**Configuration Examples:**

- `AOC-200-QSFPDD-2x100G_200G_SIDE-0xF-0xF` - Active Optical Cable, 200G speed, QSFP-DD form factor, 200G side of 2x100G deployment, 4 media lanes (0-3), 4 host lanes (0-3)
- `AOC-100-QSFPDD-2x100G_100G_SIDE-0xF-0xF` - Active Optical Cable, 100G speed, QSFP-DD form factor, 100G side of 2x100G deployment, 4 media lanes (0-3), 4 host lanes (0-3)
- `LR-1-SFP-1G_STRAIGHT-0x01-0x01` - LR specification, 1G total, SFP form factor, straight deployment, 1 media lane, 1 host lane
- `DAC-400-OSFP-400G_STRAIGHT-0x0F-0x0F` - Direct Attach Cable, 400G total, OSFP form factor, straight deployment, 4 media lanes (0-3), 4 host lanes (0-3)
- `DR-800-OSFP-4x200G_800G_SIDE-0xFF-0xFF` - DR specification, 800G speed, OSFP form factor, 800G side of 4x200G deployment, 8 media lanes (all), 8 host lanes (all)
- `DR-200-OSFP-4x200G_200G_SIDE-0xFF-0xFF` - DR specification, 200G speed, OSFP form factor, 200G side of 4x200G deployment, 8 media lanes (all), 8 host lanes (all)

**Purpose**: This standardized format enables:

- Automatic parsing of transceiver characteristics for test frameworks
- Deployment pattern grouping for shared attribute configurations
- Clear identification of lane usage and deployment topology

##### Port Specification Formats

The framework supports multiple flexible port specification formats to reduce configuration overhead:

1. **Individual Port**: `"Ethernet0"` - Single port specification
2. **Range**: `"Ethernet4:13"` - Continuous range from Ethernet4 to Ethernet12 (exclusive of 13, following Python slice convention)
3. **Range with Step**: `"Ethernet0:97:4"` - Range with step size (Ethernet0, Ethernet4, Ethernet8, ..., Ethernet96)
4. **List**: `"Ethernet16,Ethernet20,Ethernet24"` - Comma-separated list of specific ports without spaces
5. **Mixed**: `"Ethernet28:33,Ethernet36,Ethernet40:45"` - Combination of ranges and individual ports

**Requirements:**

- Port numbering must follow SONiC logical port naming convention (e.g., Ethernet0, Ethernet4, Ethernet8...)
- Range format follows Python slice convention (start:stop where stop is exclusive)
- Step size must be > 0 for range with step format

##### Framework Implementation Requirements

The test framework must implement the following core components to process per-DUT files and create a comprehensive `port_attributes_dict` dictionary. All parsed data is stored in `port_attributes_dict["EthernetXX"]["BASE_ATTRIBUTES"]` as the foundation for test operations.
More details on the `port_attributes_dict` structure and usage are provided in the Test Category Attribute Files section.

**File Discovery and Loading:**

1. **Load Normalization Mappings**: Parse `normalization_mappings.json` once at framework initialization.
2. **Discover DUT File**: Determine current DUT hostname from testbed configuration.
3. **Load DUT Data**: Open and parse `dut_info/<dut_hostname>.json`.
4. **Error Handling**: Provide clear error messages if:
   - `normalization_mappings.json` is missing or invalid
   - DUT file for current hostname is not found
   - JSON parsing fails

###### 1. Port Expansion Processing

**Purpose**: Handle various port specification formats and expand them into individual port names.

**Processing Algorithm**:

1. **Parse Port Specifications**: Identify range, list, and individual port formats
2. **Expand to Individual Ports**: Convert all specifications to individual port names  
3. **Merge Overlapping Attributes**: Collect all attributes for each port, with later port specifications overriding earlier ones
4. **Deferred Validation**: Validate mandatory fields after all applicable port specifications have been merged
5. **Generate Final Dictionary**: Create the standard per-port attribute dictionary

###### 2. Transceiver Configuration String Parsing

**Purpose**: Extract all components from the `transceiver_configuration` string during base attributes initialization phase.

**Requirements**:

- Parse the mandatory 6-component format: `{TYPE}-{SPEED}-{FORM_FACTOR}-{DEPLOYMENT}-{MEDIA_LANE_MASK}-{HOST_LANE_MASK}`
- Store all parsed components in `BASE_ATTRIBUTES` for easy access by all test categories
- Handle error cases (invalid format, missing components)

**Implementation Example**:

```python
    def parse_transceiver_configuration(config_string):
        """
        Parse transceiver configuration string into individual components.
        Format: {TYPE}-{SPEED}-{FORM_FACTOR}-{DEPLOYMENT}-{MEDIA_LANE_MASK}-{HOST_LANE_MASK}
        Example: "AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF"
        Returns: dictionary with all parsed components
        """
        if not config_string:
            return {}
        
        parts = config_string.split('-')
        if len(parts) != 6:
            raise ValueError("Invalid transceiver configuration format: {}".format(config_string))

        type_name, speed, form_factor, deployment, media_mask, host_mask = parts

        # Parse lane counts from hexadecimal masks
        media_lane_count = bin(int(media_mask, 16)).count('1')
        host_lane_count = bin(int(host_mask, 16)).count('1')

        return {
            'cable_type': type_name,
            'speed_gbps': int(speed),
            'form_factor': form_factor,
            'deployment': deployment,
            'media_lane_mask': media_mask,
            'host_lane_mask': host_mask,
            'media_lane_count': media_lane_count,
            'host_lane_count': host_lane_count
        }
```

###### 3. Dictionary Management

**Purpose**: Create and maintain the comprehensive port attributes dictionary that serves as the source of truth for test cases.

**Requirements**:

- Load `normalization_mappings.json` for vendor/PN normalization lookup
- Parse per-DUT file (`dut_info/<dut_hostname>.json`) and store data in `port_attributes_dict["EthernetXX"]["BASE_ATTRIBUTES"]` for the current DUT
- Support overlapping port specifications by merging attributes per port (later specs override earlier ones)
- Validate mandatory fields only after all applicable port specifications have been processed and merged
- Include all mandatory and optional fields, along with normalized values and parsed configuration components
- Implement proper error handling and validation

Example of a dictionary created by parsing the above file:

```python
    {
        "Ethernet0": {
            "BASE_ATTRIBUTES": {
                "vendor_name": "ACME Corp.",
                "normalized_vendor_name": "ACME_CORP",  # looked up from normalization_mappings.json
                "vendor_pn": "QSFP-2X100G-AOC-15M",
                "normalized_vendor_pn": "QSFP-2X100G-AOC-GENERIC_2_ENDM",  # looked up from normalization_mappings.json
                "transceiver_configuration": "AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF",  # single string configuration
                # Parsed components from transceiver_configuration
                "cable_type": "AOC",                    # extracted from TYPE
                "speed_gbps": 200,                      # extracted from SPEED
                "form_factor": "QSFPDD",                # extracted from FORM_FACTOR
                "deployment": "2x100G_200G_SIDE",       # extracted from DEPLOYMENT
                "media_lane_mask": "0xFF",              # extracted from MEDIA_LANE_MASK
                "host_lane_mask": "0xFF",               # extracted from HOST_LANE_MASK
                "media_lane_count": 8,                  # derived from media_lane_mask
                "host_lane_count": 8,                   # derived from host_lane_mask
                "vendor_sn": "serial_number_001",
                "vendor_date": "vendor_date_code",
                "vendor_oui": "vendor_oui",
                "vendor_rev": "revision_number",
                "hardware_rev": "hardware_revision_number"
            }
        },
        "Ethernet4": {
            "BASE_ATTRIBUTES": {
                "vendor_name": "ACME Corp.",
                "normalized_vendor_name": "ACME_CORP",
                "vendor_pn": "QSFP-2X100G-AOC-15M",
                "normalized_vendor_pn": "QSFP-2X100G-AOC-GENERIC_2_ENDM",
                "transceiver_configuration": "AOC-100-QSFPDD-2x100G_100G_SIDE-0xFF-0xFF",  # single string configuration
                # Parsed components from transceiver_configuration
                "cable_type": "AOC",                    # extracted from TYPE
                "speed_gbps": 100,                      # extracted from SPEED
                "form_factor": "QSFPDD",                # extracted from FORM_FACTOR
                "deployment": "2x100G_100G_SIDE",       # extracted from DEPLOYMENT
                "media_lane_mask": "0xFF",              # extracted from MEDIA_LANE_MASK
                "host_lane_mask": "0xFF",               # extracted from HOST_LANE_MASK
                "media_lane_count": 8,                  # derived from media_lane_mask
                "host_lane_count": 8,                   # derived from host_lane_mask
                "vendor_sn": "serial_number_range",  # same value for all ports in range
                "vendor_date": "vendor_date_code",
                "vendor_oui": "vendor_oui",
                "vendor_rev": "revision_number",
                "hardware_rev": "hardware_revision_number"
            }
        },
        "Ethernet5": {
            "BASE_ATTRIBUTES": {
                "vendor_name": "ACME Corp.",
                "normalized_vendor_name": "ACME_CORP",
                "vendor_pn": "QSFP-2X100G-AOC-15M",
                "normalized_vendor_pn": "QSFP-2X100G-AOC-GENERIC_2_ENDM",
                "transceiver_configuration": "AOC-100-QSFPDD-2x100G_100G_SIDE-0xFF-0xFF",  # single string configuration
                # Parsed components from transceiver_configuration
                "cable_type": "AOC",                    # extracted from TYPE
                "speed_gbps": 100,                      # extracted from SPEED
                "form_factor": "QSFPDD",                # extracted from FORM_FACTOR
                "deployment": "2x100G_100G_SIDE",       # extracted from DEPLOYMENT
                "media_lane_mask": "0xFF",              # extracted from MEDIA_LANE_MASK
                "host_lane_mask": "0xFF",               # extracted from HOST_LANE_MASK
                "media_lane_count": 8,                  # derived from media_lane_mask
                "host_lane_count": 8,                   # derived from host_lane_mask
                "vendor_sn": "serial_number_range",  # same value for all ports in range
                "vendor_date": "vendor_date_code",
                "vendor_oui": "vendor_oui",
                "vendor_rev": "revision_number",
                "hardware_rev": "hardware_revision_number"
            }
        },
        "Ethernet6": {
            "BASE_ATTRIBUTES": {
                "vendor_name": "ACME Corp.",
                "normalized_vendor_name": "ACME_CORP",
                "vendor_pn": "QSFP-2X100G-AOC-15M",
                "normalized_vendor_pn": "QSFP-2X100G-AOC-GENERIC_2_ENDM",
                "transceiver_configuration": "AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF",  # single string configuration
                # Parsed components from transceiver_configuration
                "cable_type": "AOC",                    # extracted from TYPE
                "speed_gbps": 200,                      # extracted from SPEED
                "form_factor": "QSFPDD",                # extracted from FORM_FACTOR
                "deployment": "2x100G_200G_SIDE",       # extracted from DEPLOYMENT
                "media_lane_mask": "0xFF",              # extracted from MEDIA_LANE_MASK
                "host_lane_mask": "0xFF",               # extracted from HOST_LANE_MASK
                "media_lane_count": 8,                  # derived from media_lane_mask
                "host_lane_count": 8,                   # derived from host_lane_mask
                "vendor_sn": "serial_number_range",  # same value for all ports in range
                "vendor_date": "vendor_date_code",
                "vendor_oui": "vendor_oui",
                "vendor_rev": "revision_number",
                "hardware_rev": "hardware_revision_number"
            }
        },
        "Ethernet16": {
            "BASE_ATTRIBUTES": {
                "vendor_name": "Example & Co",
                "normalized_vendor_name": "EXAMPLE_CO",  # looked up from normalization_mappings.json
                "vendor_pn": "SFP-1000BASE-LX",
                "normalized_vendor_pn": "SFP-1000BASE-LX",  # looked up from normalization_mappings.json (same value)
                "transceiver_configuration": "LR-1-SFP-1G_STRAIGHT-0x01-0x01",  # single string configuration
                # Parsed components from transceiver_configuration
                "cable_type": "LR",                     # extracted from TYPE
                "speed_gbps": 1,                        # extracted from SPEED
                "form_factor": "SFP",                   # extracted from FORM_FACTOR
                "deployment": "1G_STRAIGHT",            # extracted from DEPLOYMENT
                "media_lane_mask": "0x01",              # extracted from MEDIA_LANE_MASK
                "host_lane_mask": "0x01",               # extracted from HOST_LANE_MASK
                "media_lane_count": 1,                  # derived from media_lane_mask
                "host_lane_count": 1                    # derived from host_lane_mask
            }
        },
        "Ethernet20": {
            "BASE_ATTRIBUTES": {
                "vendor_name": "Example & Co",
                "normalized_vendor_name": "EXAMPLE_CO",  # looked up from normalization_mappings.json
                "vendor_pn": "SFP-1000BASE-LX",
                "normalized_vendor_pn": "SFP-1000BASE-LX",  # looked up from normalization_mappings.json
                "transceiver_configuration": "LR-1-SFP-1G_STRAIGHT-0x01-0x01",  # single string configuration
                # Parsed components from transceiver_configuration
                "cable_type": "LR",                     # extracted from TYPE
                "speed_gbps": 1,                        # extracted from SPEED
                "form_factor": "SFP",                   # extracted from FORM_FACTOR
                "deployment": "1G_STRAIGHT",            # extracted from DEPLOYMENT
                "media_lane_mask": "0x01",              # extracted from MEDIA_LANE_MASK
                "host_lane_mask": "0x01",               # extracted from HOST_LANE_MASK
                "media_lane_count": 1,                  # derived from media_lane_mask
                "host_lane_count": 1                    # derived from host_lane_mask
            }
        }
        # Additional ports expanded from ranges and lists...
    }
```

#### 2. Test Category Attribute Files

> 🔄 **Process Flow**: See the [Data Flow Architecture Diagram](diagrams/data_flow.md) for a comprehensive view of how these files are processed and merged.

Multiple JSON files based on test category define the metadata and test-specific attributes required for each type of transceiver.  
**Note:** If a test category attribute file is absent, the corresponding test case will be skipped. This allows for selective test execution and gradual framework adoption.

##### File Organization

**Recommended JSON files:**

- `eeprom.json` (EEPROM tests)
- `system.json` (System tests)  
- `physical_oir.json` (Physical OIR)
- `remote_reseat.json` (remote reseat)
- `cdb_fw_upgrade.json` (CDB FW Upgrade tests)
- `dom.json` (DOM)
- `vdm.json` (VDM)
- `pm.json` (PM)

**Location:** `ansible/files/transceiver/inventory/attributes/` directory

##### JSON Schema Structure

All files follow a consistent schema with these main sections:

```json
{
  "mandatory": ["field_1", "field_2", "field_3"],
  "defaults": {
    "field_4": "value_4",
    "field_5": "value_5"
  },
  "platform": {
    "PLATFORM_NAME": {
      "field_4": "platform_override_value"
    }
  },
  "hwsku": {
    "HWSKU_NAME": {
      "field_5": "hwsku_override_value"
    }
  },
  "dut": {
    "DUT_NAME": {
      "field_1": "dut_specific_value_1"
    }
  },
  "transceivers": {
    "deployment_configurations": {
      "DEPLOYMENT_NAME": {
        "field_2": "deployment_specific_value_2"
      }
    },
    "vendors": {
      "NORMALIZED_VENDOR_NAME": {
        "defaults": {
          "field_6": "vendor_default_value"
        },
        "part_numbers": {
          "NORMALIZED_VENDOR_PN": {
            "field_1": "specific_value_1",
            "platform_hwsku_overrides": {
              "PLATFORM_NAME+HWSKU_NAME": {
                "field_1": "highest_priority_value"
              }
            }
          }
        }
      }
    }
  }
}
```

##### Schema Components

**Main Sections:**

- `mandatory`: List of mandatory fields that must be present in the attributes at some level of the hierarchy (cannot be in `defaults`)
- `defaults`: Default values for the transceiver or test attributes
- `platform`: Platform-specific overrides (optional)
- `hwsku`: HWSKU-specific overrides (optional)
- `dut`: DUT-specific overrides (optional) wherein the `DUT_NAME` is the inventory based hostname of the DUT
- `transceivers`: Contains vendor and deployment-specific configurations organized in a hierarchical structure (mandatory)
  - `deployment_configurations`: Deployment-based attribute definitions using the mandatory naming format (e.g., AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF, AOC-100-QSFPDD-2x100G_100G_SIDE-0xFF-0xFF, DAC-400-OSFP-400G_STRAIGHT-0x0F-0x0F) (optional)
  - `vendors`: Vendor-specific configurations organized by normalized vendor name (optional)
    - `<NORMALIZED_VENDOR_NAME>`: Individual vendor section containing defaults and part number configurations
      - `defaults`: Vendor-level default values (optional)
      - `part_numbers`: Part number-specific configurations organized by normalized part number (optional)
        - `<NORMALIZED_VENDOR_PN>`: Individual part number section with specific attributes and overrides
          - `platform_hwsku_overrides`: Overrides for specific platform+HWSKU combinations (optional)

> Note: Each sub-section can contain its own `defaults` fields.

**Key Design Rules:**

- **No Overlap**: A field should **never** appear in both `mandatory` and `defaults` sections. This creates logical inconsistency because a field cannot simultaneously require explicit specification (mandatory) and have a fallback value (default). The framework would be unable to determine whether to enforce validation or apply defaults when the field is missing.
- **Validation First**: The framework should first validate that all mandatory fields can be resolved through the priority hierarchy, then apply defaults for any missing optional fields.
- **Category Isolation**: Each file contains only relevant test domain attributes
- **Deployment Grouping**: Similar deployment patterns share common attributes via `deployment_configurations`
- **Category Isolation**: Each category file should only contain attributes relevant to its specific test domain to maintain clear separation of concerns.
- **Backward Compatibility**: Missing optional sections (platform, hwsku, etc.) are silently ignored to support gradual adoption and legacy configurations.

##### Deployment Configurations

The `deployment_configurations` feature eliminates attribute duplication by defining common attributes once per deployment type instead of repeating across vendors. The framework automatically extracts the DEPLOYMENT component from the `BASE_ATTRIBUTES` field in `port_attributes_dict` to determine which deployment configuration to apply.

##### Priority-Based Attribute Resolution

Attributes are resolved using this hierarchy (highest to lowest priority):

1. **DUT-specific**: `dut.<DUT_NAME>`
2. **Normalized Vendor Name + PN + Platform + HWSKU**: `transceivers.vendors.<NORMALIZED_VENDOR_NAME>.part_numbers.<NORMALIZED_PN>.platform_hwsku_overrides.<PLATFORM>+<HWSKU>`
3. **Normalized Vendor Name + PN**: `transceivers.vendors.<NORMALIZED_VENDOR_NAME>.part_numbers.<NORMALIZED_PN>`
4. **Normalized Vendor Name (defaults)**: `transceivers.vendors.<NORMALIZED_VENDOR_NAME>.defaults`
5. **Deployment Configuration**: `transceivers.deployment_configurations.<DEPLOYMENT>` (resolved by extracting DEPLOYMENT from the `transceiver_configuration` field in `dut_info/<dut_hostname>.json`)
6. **HWSKU-specific**: `hwsku.<HWSKU>` (if present in the file)
7. **Platform-specific**: `platform.<PLATFORM>` (if present in the file)
8. **Global defaults**: `defaults`

> **Note:** For platform+HWSKU combinations in `platform_hwsku_overrides`, the key format is `"<PLATFORM_NAME>+<HWSKU_NAME>"` where the platform name and HWSKU name are concatenated with a literal `+` symbol.

##### Example Category File

Example `eeprom.json` file:

```json
{
  "mandatory": ["vendor_name", "normalized_vendor_name", "dual_bank_supported"],
  "defaults": {
    "vdm_supported": false,
    "cdb_backgroundmode_supported": false,
    "sfputil_eeprom_dump_sec": 2
  },
  "transceivers": {
    "deployment_configurations": {
      "2x100G_200G_SIDE": {
        "vdm_supported": true,
        "dual_bank_supported": true
      }
    },
    "vendors": {
      "NORMALIZED_VENDOR_A": {
        "defaults": {"vdm_supported": false},
        "part_numbers": {
          "NORMALIZED_VENDOR_PN_ABC": {
            "vendor_name": "Vendor A",
            "dual_bank_supported": true,
            "platform_hwsku_overrides": {
              "PLATFORM_ABC+VENDOR_HWSKU_ABC": {
                "sfputil_eeprom_dump_time": 5
              }
            }
          }
        }
      }
    }
  }
}
```

##### Framework Implementation

The test framework loads and merges attributes from all relevant category files for each transceiver, using hierarchical override rules. This enables category-specific test logic to access only needed attributes while supporting platform, HWSKU, and vendor overrides.

**Core Components:**

1. **AttributeManager**: Central class for loading, merging, and accessing transceiver attributes
2. **Category File Loader**: Loads JSON files for each test category  
3. **Priority Resolver**: Implements the 8-level priority hierarchy
4. **Validator**: Ensures mandatory fields are present

**Data Structure:**
The framework builds a `port_attributes_dict` keyed by logical port name, containing only ports from `dut_info/<dut_hostname>.json`:

```python
{
    "PORT_NAME": {
        # Base transceiver information from dut_info/<dut_hostname>.json
        "BASE_ATTRIBUTES": {
            "vendor_name": "vendor_name",
            "normalized_vendor_name": "NORMALIZED_VENDOR_NAME",
            "vendor_pn": "vendor_part_number",
            "normalized_vendor_pn": "NORMALIZED_VENDOR_PN",
            "vendor_sn": "serial_number",
            "vendor_date": "vendor_date_code",
            "vendor_oui": "vendor_oui",
            "vendor_rev": "revision_number",
            "transceiver_configuration": "AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF",  # original configuration string
            # Parsed components from transceiver_configuration
            "cable_type": "AOC",                    # extracted from TYPE
            "speed_gbps": 200,                      # extracted from SPEED
            "form_factor": "QSFPDD",                # extracted from FORM_FACTOR
            "deployment": "2x100G_200G_SIDE",       # extracted from DEPLOYMENT
            "media_lane_mask": "0xFF",              # extracted from MEDIA_LANE_MASK
            "host_lane_mask": "0xFF",               # extracted from HOST_LANE_MASK
            "media_lane_count": 8,                  # derived from media_lane_mask
            "host_lane_count": 8                    # derived from host_lane_mask
        },
        # Category-specific attributes with merged overrides applied
        "EEPROM_ATTRIBUTES": {
            "attribute_1": "value_1",
            "attribute_2": "value_2",
            ...
        }
        "SYSTEM_ATTRIBUTES": {
            "attribute_1": "value_1",
            "attribute_2": "value_2",
            ...
        }
        ...
    }
}
```

##### Attribute Merging Process

The framework builds `port_attributes_dict` using this systematic process:

1. **Initialize** port dictionary from `dut_info/<dut_hostname>.json` base attributes
2. **For each category file**, perform priority-based merging using the 8-level hierarchy
3. **Validate** mandatory fields for the current category
4. **Store** merged attributes under category key (e.g., `EEPROM_ATTRIBUTES`, `SYSTEM_ATTRIBUTES`)
5. **Expose** the complete dictionary via the session-scoped fixture `port_attributes_dict` (an autouse session fixture logs its contents for traceability).

**Merging Behavior:**

- Higher priority fields completely override earlier values
- Missing sections are silently skipped
- Graceful error handling for missing files and invalid JSON
- The entire `port_attributes_dict` is captured in the log for debugging

##### Usage

Tests access attributes using: `port_attributes_dict[port_name][category_key][attribute_name]`  
The `port_attributes_dict` is provided directly as a session-scoped fixture and is also initialized early for logging.

**Example (inside a test):**

```python
def test_example(port_attributes_dict):
    # Access EEPROM attributes
    eeprom_attrs = port_attributes_dict["Ethernet0"].get("EEPROM_ATTRIBUTES", {})
    dual_bank_supported = eeprom_attrs.get("dual_bank_supported")

    # Access base transceiver configuration (parsed from transceiver_configuration)
    base_attrs = port_attributes_dict["Ethernet0"]["BASE_ATTRIBUTES"]
    cable_type = base_attrs["cable_type"]
    deployment = base_attrs["deployment"]

    assert cable_type in ("AOC", "DAC", "LR", "DR")
```

**Benefits:** Modular design, independent updates per category, conflict prevention, flexible overrides, and performance optimization.

#### 3. Attribute Completeness Validation

> **Process Flow**: See the [Validation Flow Diagram](diagrams/validation_flow.md) for a visual overview of the validation process and pytest integration.

Optional post-processing validation ensures comprehensive attribute coverage for transceiver qualification by comparing the populated `port_attributes_dict` against deployment-specific templates.

##### Template Structure

**Location:** `ansible/files/transceiver/inventory/templates/deployment_templates.json`

**Schema:** Templates define required and optional attributes by deployment type:

```json
{
  "deployment_templates": {
    "2x100G_200G_SIDE": {
      "required_attributes": {
        "BASE_ATTRIBUTES": ["vendor_name", "vendor_pn", "cable_type", "speed_gbps", "deployment"],
        "EEPROM_ATTRIBUTES": ["dual_bank_supported", "vdm_supported"],
        "DOM_ATTRIBUTES": ["temperature", "voltage", "tx_power", "alarm_flags"]
      },
      "optional_attributes": {
        "BASE_ATTRIBUTES": ["hardware_rev", "vendor_rev"],
        "CDB_FW_ATTRIBUTES": ["firmware_upgrade_support"]
      }
    }
  }
}
```

##### Template Components

- `deployment_templates`: Root object containing all deployment templates
  - `<DEPLOYMENT_NAME>`: Individual deployment template (e.g., `2x100G_200G_SIDE`)
    - `required_attributes`: Lists of attributes that must be present for each category
    - `optional_attributes`: Lists of attributes that should be present if available
    - **Note:** Each category (e.g., `BASE_ATTRIBUTES`, `EEPROM_ATTRIBUTES`, `DOM_ATTRIBUTES`) can have its own set of required and optional attributes.

##### Validation Process

1. **Template Selection**: Uses `deployment` field from `BASE_ATTRIBUTES` to select appropriate template
2. **Attribute Comparison**: Compares actual vs required attributes per category  
3. **Gap Analysis**: Identifies missing required/optional attributes
4. **Pytest Integration**: Reports results with standard log levels (INFO/WARNING/ERROR/DEBUG)

##### Configuration Control

The validation feature can also be controlled via passing a test parameters:

- **`--skip_transceiver_template_validation`**: When specified, completely bypasses the attribute completeness validation
  - Use case: Quick test runs during development or when template definitions are incomplete
  - Default: `False` (validation is performed if the deployment_templates.json files exists)
  - Example: `pytest test_transceiver.py --skip_transceiver_template_validation`

**Note:** Even when validation is skipped, all attributes from category files are still loaded and available for test execution. This parameter only affects the post-processing template validation step.

##### Console Output

```python
INFO     PASS: Ethernet0 (2x100G_200G_SIDE) - FULLY_COMPLIANT (19/20 attributes)
WARNING  PARTIAL: Ethernet4 - Missing optional: VDM_ATTRIBUTES.historical_data
ERROR    FAIL: Ethernet8 - Missing required: DOM_ATTRIBUTES.alarm_flags
INFO     Overall Compliance: 87.5% (21/24 ports fully compliant)
```

##### Execution Control

The validation results determine test execution flow:

- **Critical failures**: `pytest.fail()` - stops test execution when required attributes are missing
- **Warnings only**: `pytest.warns()` - continues with warnings for missing optional attributes
- **Fully compliant**: Normal test execution proceeds without validation messages

**Skipping Validation:**

- Use `--skip_transceiver_template_validation` pytest parameter to completely bypass this validation step
- See the "Configuration Control" section above for detailed usage information

#### 4. Transceiver Firmware Info File

A `transceiver_firmware_info.csv` file (located in `ansible/files/transceiver/inventory` directory) should exist if a transceiver being tested supports CMIS CDB firmware upgrade. This file will capture the firmware binary metadata for the transceiver. Each transceiver should have at least 2 firmware binaries (in addition to the gold firmware binary) so that firmware upgrade can be tested. Following should be the format of the file

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

#### 5. CMIS CDB Firmware Base URL File

A `cmis_cdb_firmware_base_url.csv` file (located in `ansible/files/transceiver/inventory` directory) should be present to define the base URL for downloading CMIS CDB firmware binaries. The file should follow this format:

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
2. **Parse `dut_info/<dut_hostname>.json`** to identify the transceivers present on each DUT.
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
