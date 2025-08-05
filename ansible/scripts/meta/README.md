# SONiC Mgmt Metadata Validator

1. [1. Overview](#1-overview)
   1. [1.1. Purpose](#11-purpose)
   2. [1.2. Key Features](#12-key-features)
2. [2. Quick Start](#2-quick-start)
   1. [2.1. Basic Usage](#21-basic-usage)
   2. [2.2. Configuration-Driven Validation](#22-configuration-driven-validation)
   3. [2.3. Advanced Options](#23-advanced-options)
   4. [2.4. Output Formats](#24-output-formats)
3. [3. Architecture](#3-architecture)
   1. [3.1. Core Components](#31-core-components)
   2. [3.2. Validation Flow](#32-validation-flow)
4. [4. Configuration](#4-configuration)
   1. [4.1. Configuration File Format](#41-configuration-file-format)
   2. [4.2. Issue Severities](#42-issue-severities)
   3. [4.3. Validation Options](#43-validation-options)
   4. [4.4. Validator Configuration](#44-validator-configuration)
5. [5. Validation Components](#5-validation-components)
   1. [5.1. Global Validators](#51-global-validators)
      1. [5.1.1. Testbed Validator](#511-testbed-validator)
      2. [5.1.2. IPAddress Validator](#512-ipaddress-validator)
      3. [5.1.3. Console Validator](#513-console-validator)
      4. [5.1.4. PDU Validator](#514-pdu-validator)
      5. [5.1.5. Topology Validator](#515-topology-validator)
   2. [5.2. Group Validators](#52-group-validators)
      1. [5.2.0. Common Group Validator Configuration](#520-common-group-validator-configuration)
      2. [5.2.1. Device Info Validator](#521-device-info-validator)
      3. [5.2.2. Vlan Validator](#522-vlan-validator)
6. [6. Extending the Framework](#6-extending-the-framework)
   1. [6.1. Creating Custom Validators](#61-creating-custom-validators)
      1. [6.1.1. Step 1: Define Issue Definitions](#611-step-1-define-issue-definitions)
      2. [6.1.2. Step 2: Create validator class](#612-step-2-create-validator-class)
      3. [6.1.3. Step 3: Issue Reporting Best Practices](#613-step-3-issue-reporting-best-practices)
      4. [6.1.4. Step 4: Register in configuration](#614-step-4-register-in-configuration)
   2. [6.2. Adding Validation Hooks](#62-adding-validation-hooks)
7. [7. Examples and Use Cases](#7-examples-and-use-cases)
   1. [7.1. Example 1: CI/CD Pipeline Integration](#71-example-1-cicd-pipeline-integration)
   2. [7.2. Example 2: Development Environment Setup](#72-example-2-development-environment-setup)
   3. [7.3. Example 3: Custom Validation Pipeline](#73-example-3-custom-validation-pipeline)

## 1. Overview

### 1.1. Purpose

The SONiC Mgmt metadata validator is a comprehensive validation framework that ensures the integrity and consistency of testbed configurations, network topologies, and inventory data across the SONiC management infrastructure.

The validator ensures that:

- All infrastructure groups have valid connection graphs
- Testbed configurations are consistent
- No duplicate or conflicting configurations exist
- IP addressing schemes are valid and non-overlapping
- VLAN configurations are properly formatted and within valid ranges

### 1.2. Key Features

- **⚙️ Configuration-Driven**: YAML/JSON configuration files for flexible validator setup
- **📊 Rich Error Reporting**: Detailed categorization with severity levels and metadata
- **🔄 Multiple Execution Strategies**: Fail-fast, continue-on-error, warnings-as-errors
- **📈 Performance Monitoring**: Execution timing and comprehensive metrics
- **🔗 Extensible Design**: Easy to add new validators and customize behavior

## 2. Quick Start

### 2.1. Basic Usage

**Run with default configuration:**

```bash
python3 meta_validator.py
```

**Run with verbose output:**

```bash
python3 meta_validator.py --verbose
# or using short name:
python3 meta_validator.py -v
```

**Validate specific groups:**

```bash
# Single group
python3 meta_validator.py --group lab
# or using short name:
python3 meta_validator.py -g lab

# Multiple groups
python3 meta_validator.py --group lab ixia
# or using short name:
python3 meta_validator.py -g lab ixia
```

**List available validators:**

```bash
python3 meta_validator.py --list-validators
# or using short name:
python3 meta_validator.py -l
```

### 2.2. Configuration-Driven Validation

**Create a sample configuration file:**

```bash
python3 meta_validator.py --create-sample-config my_config.yaml
# or using short name:
python3 meta_validator.py -s my_config.yaml
```

**Run with custom configuration:**

```bash
python3 meta_validator.py --config my_config.yaml
# or using short name:
python3 meta_validator.py -c my_config.yaml
```

**Use different validation options:**

```bash
# Stop on first error
python3 meta_validator.py --fail-fast

# Treat warnings as errors
python3 meta_validator.py --warnings-as-errors

# Show full report with all errors and warnings
python3 meta_validator.py --report-level full

# Run only specific validators
python3 meta_validator.py --enable-validators ip_address console pdu

# Run all validators except specific ones
python3 meta_validator.py --disable-validators vlan topology

# Output results in JSON format with quiet mode
python3 meta_validator.py --output-format json --quiet

# Output results in YAML format with full details (no logging)
python3 meta_validator.py -o yaml -r full -q
```

### 2.3. Advanced Options

**Full command reference:**

```bash
# Using long names:
python3 meta_validator.py \
    --config validator_config.yaml \
    --fail-fast \
    --warnings-as-errors \
    --graph-groups ansible/files/graph_groups.yml \
    --testbed-config ansible/testbed.yaml \
    --testbed-nut-config ansible/testbed.nut.yaml \
    --group lab ixia \
    --report-level full \
    --enable-validators testbed ip_address \
    --disable-validators vlan \
    --verbose

# Using short names:
python3 meta_validator.py \
    -c validator_config.yaml \
    --fail-fast \
    --warnings-as-errors \
    -gg ansible/files/graph_groups.yml \
    -t ansible/testbed.yaml \
    -tn ansible/testbed.nut.yaml \
    -g lab ixia \
    -r full \
    -e testbed ip_address \
    -d vlan \
    -v
```

**Available options:**

- `--config` / `-c`: Path to configuration file
- `--group` / `-g`: Validate specific groups only (space-separated list)
- `--verbose` / `-v`: Enable verbose logging
- `--quiet` / `-q`: Suppress logging output and only show the report
- `--testbed-config` / `-t`: Path to testbed configuration file
- `--testbed-nut-config` / `-tn`: Path to NUT testbed configuration file
- `--report-level` / `-r`: Output level (summary, errors, full)
- `--output-format` / `-o`: Output format (text, json, yaml)
- `--enable-validators` / `-e`: Enable only specified validators
- `--disable-validators` / `-d`: Disable specified validators
- `--list-validators` / `-l`: List available validators
- `--create-sample-config` / `-s`: Create sample configuration file
- `--graph-groups` / `-gg`: Path to graph groups file
- `--fail-fast`: Stop on first validation failure
- `--warnings-as-errors`: Treat warnings as errors and stop

### 2.4. Output Formats

The validator supports multiple output formats for different use cases:

**Text output (default):**
```bash
python3 meta_validator.py --verbose
```

**JSON output for programmatic processing:**
```bash
# JSON with quiet mode (no logging)
python3 meta_validator.py --output-format json --quiet

# JSON with full error details
python3 meta_validator.py -o json -r full -q
```

**YAML output for human-readable structured data:**
```bash
# YAML with quiet mode
python3 meta_validator.py --output-format yaml --quiet

# YAML with only errors
python3 meta_validator.py -o yaml -r errors -q
```

**JSON Output Example:**
```json
{
  "summary": {
    "groups_processed": 2,
    "total_validators": 5,
    "total_passed": 3,
    "total_failed": 2,
    "total_errors": 3,
    "total_warnings": 1,
    "success_rate": 60.0,
    "overall_success": false
  },
  "groups": {
    "lab": {
      "validators": [
        {
          "name": "ip_address",
          "success": false,
          "group": "lab",
          "execution_time": 0.125,
          "error_count": 1,
          "warning_count": 0,
          "errors": [
            {
              "issue_id": "E2004",
              "keyword": "inconsistent_ip",
              "description": "Device has inconsistent IP addresses across sources",
              "message": "Device has different IPv4 addresses",
              "severity": "error",
              "source": "ip_address",
              "group": "lab",
              "details": {
                "device": "sonic-s6100-dut",
                "group": "lab",
                "ip_type": "ipv4",
                "connection_graph_ip": "10.1.1.100",
                "ansible_inventory_ip": "10.1.1.101",
                "connection_graph_source": "ManagementIp",
                "ansible_inventory_source": "ansible_host"
              }
            }
          ],
          "metadata": {
            "total_ips": 15,
            "device_ips": 8,
            "testbed_ips": 7
          }
        }
      ]
    }
  }
}
```

**YAML Output Example:**
```yaml
summary:
  groups_processed: 2
  total_validators: 5
  total_passed: 3
  total_failed: 2
  total_errors: 3
  total_warnings: 1
  success_rate: 60.0
  overall_success: false
groups:
  lab:
    validators:
    - name: ip_address
      success: false
      group: lab
      execution_time: 0.125
      error_count: 1
      warning_count: 0
      errors:
      - issue_id: E2004
        keyword: inconsistent_ip
        description: Device has inconsistent IP addresses across sources
        message: Device has different IPv4 addresses
        severity: error
        source: ip_address
        group: lab
        details:
          device: sonic-s6100-dut
          group: lab
          ip_type: ipv4
          connection_graph_ip: 10.1.1.100
          ansible_inventory_ip: 10.1.1.101
          connection_graph_source: ManagementIp
          ansible_inventory_source: ansible_host
      metadata:
        total_ips: 15
        device_ips: 8
        testbed_ips: 7
```

**Use Cases:**
- **Text**: Human-readable output for manual validation and debugging
- **JSON**: Automated processing, CI/CD pipelines, and integration with monitoring tools
- **YAML**: Configuration files, documentation, and human-readable structured reports

## 3. Architecture

### 3.1. Core Components

**BaseValidator**: Abstract base class for all validators

```python
class BaseValidator(ABC):
    def __init__(self, name: str, description: str = "", category: str = "general")
    def validate(self, context: ValidatorContext) -> ValidationResult
    def get_info(self) -> Dict[str, str]
    def requires_global_context(self) -> bool  # Returns False by default
```

**GlobalValidator**: Base class for validators that need access to data from all groups

```python
class GlobalValidator(BaseValidator):
    def requires_global_context(self) -> bool  # Returns True
    def validate(self, context: ValidatorContext) -> ValidationResult
    # Validates that context has global data before running validation
```

**GroupValidator**: Base class for validators that operate on a single group

```python
class GroupValidator(BaseValidator):
    def requires_global_context(self) -> bool  # Returns False
    def validate(self, context: ValidatorContext) -> ValidationResult
    # Validates that context has exactly one group before running validation
```

**ValidationResult**: Comprehensive result object

```python
@dataclass
class ValidationResult:
    validator_name: str
    group_name: str
    success: bool
    issues: List[ValidationIssue]
    metadata: Dict[str, Any]
    execution_time: float
```

**ValidatorContext**: Context object for validation data

```python
class ValidatorContext:
    def __init__(self, group_name: str, testbed_info: List[Dict], all_groups_data: Dict)
    def get_group_name() -> str
    def get_testbeds() -> List[Dict[str, Any]]
    def get_connection_graph() -> Dict[str, Any]  # For single group context
    def get_all_groups_data() -> Dict[str, Dict[str, Any]]  # For global context
    def get_all_connection_graphs() -> Dict[str, Dict[str, Any]]
    def get_all_devices_across_groups() -> Dict[str, Any]  # For global validation
    def is_global_context() -> bool
```

### 3.2. Validation Flow

1. **Configuration Loading**: Load validator configuration from YAML/JSON
2. **Validator Creation**: Use factory pattern to create configured validators
3. **Group Data Loading**: Load connection graph data for all infrastructure groups
4. **Validator Separation**: Separate validators into global vs group-specific categories
5. **Global Validation**: Run global validators once with data from all groups
6. **Group Validation**: Run group validators individually for each group
7. **Result Aggregation**: Collect and summarize validation results from both phases
8. **Reporting**: Generate detailed reports with metrics and categorization

Here is an example of connection graph data structure used by validators:

```json
{
    "devices": {
        "sonic-s6100-dut": {
            "HwSku": "Arista-7060CX-32S-C32",
            "Type": "DevSonic",
            "ManagementIp": "192.168.1.100/24"
        }
    },
    "links": {
        "sonic-s6100-dut": {
            "Ethernet64": {
                "peerdevice": "snappi-sonic",
                "peerport": "Card4/Port1",
                "speed": "100000"
            }
        }
    },
    "port_vlans": {
        "sonic-s6100-dut": {
            "Ethernet64": {
                "mode": "Access",
                "vlanids": "2,100-200",
                "vlanlist": [2, 100, 101, 102, 200]
            }
        }
    }
}
```

## 4. Configuration

### 4.1. Configuration File Format

**Sample YAML configuration:**

```yaml
logging:
  level: INFO
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
issue_severities:
  # Examples: Override specific issue severities
  # 'E2002': 'ignore'    # Ignore reserved IP warnings
  # 'E3008': 'info'      # Convert console server type warnings to info logs
  # 'E3001': 'warning'   # Downgrade console conflicts to warnings
  # 'E4004': 'error'     # Upgrade PDU redundancy warnings to errors
validators:
  - name: testbed
    enabled: true
    config: {}
  - name: ip_address
    enabled: true
    config:
      allow_conflict_list:
        - from: "^(.+)-dut$"          # Match devices ending with "-dut"
          to: "\\1"                   # Remove "-dut" suffix
      exclude_devices:
        - "^test-.*"                  # Exclude test devices
        - ".*-temp$"                  # Exclude temporary devices
  - name: device_info
    enabled: true
    config:
      invalid_chars: [' ', '\t', '\n', '\r']
      max_length: 255
      exclude_groups:
        - "^test.*"      # Skip groups starting with "test"
        - ".*staging.*"  # Skip groups containing "staging"
  - name: vlan
    enabled: true
    config:
      min_vlan_id: 1
      max_vlan_id: 4096
      exclude_groups:
        - "lab-temp-.*"  # Skip temporary lab groups
  - name: console
    enabled: true
    config:
      exclude_devices:
        - "^test-.*"      # Exclude devices starting with "test-"
        - ".*-backup$"    # Exclude devices ending with "-backup"
  - name: pdu
    enabled: true
    config:
      exclude_devices:
        - "^test-.*"      # Exclude devices starting with "test-"
        - ".*-backup$"    # Exclude devices ending with "-backup"
```

### 4.2. Issue Severities

Users can customize the severity of specific validation issues to control validation behavior:

```yaml
issue_severities:
  'E2002': 'ignore'    # Ignore reserved IP warnings completely
  'E3008': 'info'      # Convert console server type warnings to info logs
  'E3001': 'warning'   # Downgrade console conflicts to warnings
  'E4004': 'error'     # Upgrade PDU redundancy warnings to errors
```

**Available severity levels:**

- `ignore`: Skip the issue entirely (not reported)
- `info`: Convert to informational log message (not counted as validation issue)
- `warning`: Treat as warning (reported but doesn't fail validation)
- `error`: Treat as error (fails validation)
- `critical`: Treat as critical error (fails validation)

### 4.3. Validation Options

Validation behavior can be controlled via command-line arguments:

- **Default behavior**:
  - Runs all validators regardless of failures
  - Provides complete validation report
  - Best for comprehensive analysis
- **--fail-fast**: Stops on first validation failure
- **--warnings-as-errors**: Treats warnings as errors

### 4.4. Validator Configuration

Each validator can be configured individually:

```yaml
validators:
  - name: testbed_name
    enabled: true
    config:
      # Runtime configuration options (validator-specific)
  - name: vlan
    enabled: true
    config:
      min_vlan_id: 1
      max_vlan_id: 4096
```

## 5. Validation Components

The validation framework includes two types of validators based on their scope of operation:

- **Global Validators**: Operate across all infrastructure groups to detect conflicts and ensure consistency at the global level
- **Group Validators**: Operate within individual infrastructure groups to validate group-specific configurations

### 5.1. Global Validators

Global validators run once with access to data from all infrastructure groups. They are designed to detect cross-group conflicts and ensure global consistency.

#### 5.1.1. Testbed Validator

**Purpose**: Validates testbed configuration, name uniqueness, and topology file existence.

**Configuration Options:** No configuration options available.

**Validation Rules:**

- Ensures all testbed names (from `conf-name` field) are unique
- Validates testbed names across all groups globally
- Verifies that topology files exist for each testbed's `topo` field
- Checks for topology files in `ansible/vars/` directory with `topo_` prefix

**Issues:**

- `E1001`: bad_config_data_in_graph - Bad testbed configuration data in connection graph - possible infra issue, check conn_graph_facts.py for errors
- `E1002`: missing_conf_name - Testbed configuration missing conf-name field
- `E1003`: duplicate_name - Duplicate testbed name found
- `E1004`: missing_topology_file - Topology file not found for testbed

#### 5.1.2. IPAddress Validator

**Purpose**: Validates that no IP address conflicts exist between devices and testbeds across all infrastructure groups.

**Configuration Options:**

- `allow_conflict_list`: List of conflict resolution rules to ignore specific IP conflicts (default: [])
- `exclude_devices`: List of regex patterns to exclude devices from IP validation (default: [])

**Allow Conflict List Configuration:**

The `allow_conflict_list` allows you to ignore IP conflicts between devices when they represent the same logical entity with different naming conventions. Each rule contains:

- `from`: Regex pattern to match device names
- `to`: Replacement string to normalize device names

If two conflicting devices normalize to the same name after regex replacement, the conflict is ignored.

**Example Configuration:**

```yaml
validators:
  - name: ip_address
    enabled: true
    config:
      allow_conflict_list:
        - from: "^(.+)-dut$"          # Match devices ending with "-dut"
          to: "\\1"                   # Remove "-dut" suffix
        - from: "^lab-(.+)-switch$"   # Match lab switches
          to: "\\1"                   # Keep only the middle part
```

**Example Behavior:**

- `sonic-s6100-dut` and `sonic-s6100` → Both normalize to `sonic-s6100` → Conflict ignored
- `lab-spine1-switch` and `spine1` → Both normalize to `spine1` → Conflict ignored

**Exclude Devices Configuration:**

The `exclude_devices` allows you to completely exclude specific devices from IP validation. Devices matching any of the regex patterns will be ignored entirely during validation.

**Example Configuration:**

```yaml
validators:
  - name: ip_address
    enabled: true
    config:
      exclude_devices:
        - "^test-.*"         # Exclude all devices starting with "test-"
        - ".*-temp$"         # Exclude all devices ending with "-temp"
        - "mgmt-server-.*"   # Exclude management servers
```

**Example Behavior:**
- `test-device-1` → Excluded from all IP validation
- `switch-temp` → Excluded from all IP validation
- `mgmt-server-lab1` → Excluded from all IP validation

**Validation Rules:**

- Ensures no IP conflicts between device management IPs and testbed PTF IPs across all groups
- Validates IP address format and type
- Ensures no reserved and loopback address will be used
- Skips IP conflict detection for shared infrastructure devices, such as PDU and console servers
- Validates IP consistency between connection graph and ansible inventory for the same device
- Validates IPv4/IPv6 address relationships (IPv6 last 4 bytes should match IPv4 address)

**Issues:**

- `E2001`: conflict_ip - IP address conflict detected
- `E2002`: reserved_ip - Reserved IP address found (WARNING)
- `E2003`: invalid_ip_format - Invalid IP address format
- `E2004`: inconsistent_ip - Device has inconsistent IP addresses across sources
- `E2005`: ipv4_ipv6_mismatch - IPv6 address last 4 bytes do not match IPv4 address (INFO)

#### 5.1.3. Console Validator

**Purpose**: Validates that all DevSonic and Fanout devices have console connections configured and checks for conflicts across all infrastructure groups.

**Configuration Options:**

- `exclude_devices`: List of regex patterns to exclude devices from validation (default: [])

**Validation Rules:**

- Ensures all devices below have console connections configured across all groups:
  - Type = "DevSonic"
  - Type starting with "Fanout"
- Validates console connection properties (peer device, port, proxy settings)
- Checks that console server devices exist and are properly configured
- Detects console port conflicts across all infrastructure groups

**Issues:**

- `E3001`: duplicate_config_groups - Device has console configuration in multiple groups (WARNING)
- `E3002`: missing_console - Device has no console connection configured
- `E3003`: bad_console_data_in_graph - Bad console connection data in connection graph - possible infra issue, check conn_graph_facts.py for errors
- `E3004`: missing_console_port - Console connection missing ConsolePort information
- `E3005`: console_port_conflict - Console port is used by multiple devices
- `E3006`: missing_required_field - Console connection missing required field
- `E3007`: invalid_console_server - Console points to non-existent server
- `E3008`: invalid_server_type - Console server has unexpected type (WARNING)
- `E3009`: empty_console_port - Console connection has empty port
- `E3010`: empty_optional_field - Console connection has empty optional field (WARNING)

#### 5.1.4. PDU Validator

**Purpose**: Validates that all DevSonic and Fanout devices have PDU (Power Distribution Unit) connections configured and checks for conflicts across all infrastructure groups.

**Configuration Options:**

- `exclude_devices`: List of regex patterns to exclude devices from validation (default: [])

**Validation Rules:**

- Ensures all devices below have PDU connections configured across all groups:
  - Type = "DevSonic"
  - Type starting with "Fanout"
- Validates PDU connection properties (peer device, port, feed configuration)
- Checks that PDU devices exist and are properly configured
- Verifies power feed redundancy where configured
- Detects PDU port conflicts across all infrastructure groups

**Issues:**

- `E4001`: duplicate_config_groups - Device has PDU configuration in multiple groups (WARNING)
- `E4002`: missing_pdu - Device has no PDU connections configured
- `E4003`: bad_pdu_data_in_graph - Bad PDU connection data in connection graph - possible infra issue, check conn_graph_facts.py for errors
- `E4004`: no_power_redundancy - Device has only one PSU connection - no power redundancy (WARNING)
- `E4005`: bad_psu_data_in_graph - Bad PSU configuration data in connection graph - possible infra issue, check conn_graph_facts.py for errors
- `E4006`: bad_feed_data_in_graph - Bad feed configuration data in connection graph - possible infra issue, check conn_graph_facts.py for errors
- `E4007`: pdu_port_conflict - PDU outlet is used by multiple devices
- `E4008`: missing_required_field - PDU connection missing required field
- `E4009`: invalid_pdu_device - PDU points to non-existent device
- `E4010`: invalid_pdu_type - PDU device has unexpected type (WARNING)
- `E4011`: empty_pdu_port - PDU connection has empty port

#### 5.1.5. Topology Validator

**Purpose**: Validates topology files defined under `ansible/vars` folder to ensure template files exist and configurations are consistent.

**Configuration Options:**

- `includes`: List of regex patterns to include topologies (default: [] - include all)
- `excludes`: List of regex patterns to exclude topologies (default: [] - exclude none)

**Example Configuration:**

```yaml
validators:
  - name: topology
    enabled: true
    config:
      includes:
        - "^tgen.*"    # Include topologies starting with "tgen"
        - ".*ixia.*"   # Include topologies containing "ixia"
      excludes:
        - ".*-64.*"    # Exclude topologies containing "-64"
```

**Validation Rules:**

- Ensures template files for swrole exist in `ansible/roles/eos/templates/`
- Ensure VM and host interface VLAN assignments are unique
- Ensures VM offset values are unique across all VMs
- Validates interface uniqueness within each vlan_config and checks prefix limits
- Verifies all bp_interface IPs live within a single subnet. One for IPv4 and one for IPv6.

**Issues:**

- `E5001`: parse_error - Failed to process topology file
- `E5002`: missing_template - Template file not found for swrole
- `E5003`: duplicate_vm_offset - VM offset is used by multiple VMs
- `E5004`: duplicate_vlan - VLAN ID is used by multiple sources
- `E5005`: duplicate_interface - Interface appears multiple times in vlan_config
- `E5006`: interface_count_exceed - Interface count exceeds prefix capacity
- `E5007`: invalid_prefix_format - Invalid prefix format in vlan_config
- `E5008`: invalid_ip_format - Invalid bp_interface IPv4 address format
- `E5009`: multiple_subnets - bp_interface IPs span multiple subnets
- `E5010`: conflict_ip - bp_interface IP address conflict
- `E5011`: missing_topology_dir - Topology vars directory not found
- `E5012`: yaml_parse_error - Invalid YAML in topology file
- `E5013`: missing_topology_file - Topology file not found
- `E5014`: missing_swrole_template_file - Template file not found for swrole

### 5.2. Group Validators

Group validators run individually for each infrastructure group, operating only on data from a single group. They validate group-specific configurations and constraints.

#### 5.2.0. Common Group Validator Configuration

All group validators support a common `exclude_groups` configuration parameter that allows skipping validation for specific groups based on regex patterns:

**Common Configuration:**

- `exclude_groups`: List of regex patterns to match against group names

Here is an example:

```yaml
validators:
  - name: device_info
    enabled: true
    config:
      exclude_groups:
        - "^test.*"      # Skip groups starting with "test"
        - ".*staging.*"  # Skip groups containing "staging"
        - "lab-[0-9]+"   # Skip groups matching "lab-1", "lab-2", etc.
      # validator-specific config options...
```

#### 5.2.1. Device Info Validator

**Purpose**: Validates that all device info is correct within each infrastructure group.

**Configuration Options:**

- `invalid_chars`: List of invalid characters in device names (default: [])
- `max_length`: Maximum allowed device name length (default: 255)
- `exclude_groups`: List of regex patterns to exclude groups (default: [])

**Validation Rules:**

- Ensures all device names within a group are unique
- Validates device name format and consistency
- Checks that device names are not empty or invalid
- Validates that all devices have non-empty HwSku fields
- Operates on each infrastructure group individually

**Issues:**

- `E6001`: missing_devices_section - No devices section found in connection graph (WARNING)
- `E6002`: bad_devices_data_in_graph - Bad devices section data in connection graph - possible infra issue, check conn_graph_facts.py for errors
- `E6003`: empty_device_name - Empty or invalid device name found
- `E6004`: conflict_device_name - Conflicting device name found
- `E6005`: invalid_characters - Device name contains invalid characters
- `E6006`: device_name_too_long - Device name exceeds maximum length
- `E6007`: empty_hwsku - Device has empty or missing HwSku field

#### 5.2.2. Vlan Validator

**Purpose**: Validates VLAN configurations in connection graphs are valid and within acceptable ranges for each infrastructure group.

**Configuration Options:**

- `min_vlan_id`: Minimum valid VLAN ID (default: 1)
- `max_vlan_id`: Maximum valid VLAN ID (default: 4096)
- `exclude_groups`: List of regex patterns to exclude groups (default: [])

**Validation Approach:**

Operates on each infrastructure group individually. Starting from all DUTs (DevSonic), uses BFS to walk through all connected devices within the group. For each device:

1. Enumerate all non-visited links on the device and find their peer devices and ports. For each peer port:
   1. Validate the VLAN IDs:
      1. Ensure they are within the valid range (min_vlan_id to max_vlan_id)
      2. If a port has multiple VLANs, ensure they are properly formatted (e.g., "100-200,300")
   2. Store the VLAN IDs in a hash table for the peer device
2. Load all stored VLAN IDs for the current device and ensure:
   1. All VLAN IDs are unique across all ports
   2. All VLAN IDs can be uniquely mapped to one of the non-visited peer links above
3. Move to next device and repeat until all devices in the group are visited

**Issues:**

- `E7001`: missing_dut_devices - No DUT devices found in topology
- `E7002`: bad_vlan_data_in_graph - Bad VLAN configuration data in connection graph - possible infra issue, check conn_graph_facts.py for errors
- `E7003`: duplicate_vlan - VLAN IDs are duplicated on multiple ports (reported in range format)
- `E7004`: vlan_mapping_missing - VLAN IDs are not mapped to peer links
- `E7005`: vlan_mapping_extra - VLAN IDs from peer links not configured on device
- `E7006`: invalid_vlan_format - Invalid VLAN format
- `E7007`: invalid_vlan_range_order - Invalid VLAN range - start greater than end
- `E7008`: vlan_out_of_range - VLAN ID not in valid range
- `E7011`: invalid_vlan_list_type - VLAN list must be a list
- `E7012`: invalid_vlan_type - VLAN ID must be an integer

## 6. Extending the Framework

### 6.1. Creating Custom Validators

#### 6.1.1. Step 1: Define Issue Definitions

Before creating a validator, first define your issue definitions with unique IDs. Each validator gets a range of 1000 issue IDs:

**Add to `validators/validation_result.py` in the `register_all_issues()` function:**

```python
# Custom Validator Issues (8000-8999)
_def_issue('my_validator', 'I8000', 'validation_summary', 'Custom validation summary', ValidationSeverity.INFO)
_def_issue('my_validator', 'E8001', 'custom_error', 'Custom validation error occurred')
_def_issue('my_validator', 'E8002', 'configuration_missing', 'Required configuration is missing', ValidationSeverity.WARNING)
_def_issue('my_validator', 'E8003', 'invalid_format', 'Invalid format detected')
```

**Update the validator ranges in `ValidationIssueRegistry`:**

```python
self._validator_ranges: Dict[str, range] = {
    'testbed_name': range(1000, 2000),
    'ip_address': range(2000, 3000),
    'console': range(3000, 4000),
    'pdu': range(4000, 5000),
    'topology': range(5000, 6000),
    'device_info': range(6000, 7000),
    'vlan': range(7000, 8000),
    'my_validator': range(8000, 9000),  # Add your validator range
}
```

#### 6.1.2. Step 2: Create validator class

**For group-specific validation:**

```python
from validators import GroupValidator, ValidatorContext, register_validator

@register_validator("my_group_validator")
class MyGroupValidator(GroupValidator):
    def __init__(self, config=None):
        super().__init__(
            name="my_group_validator",
            description="My group-specific validation logic",
            category="custom"
        )
        self.config = config or {}

    def _validate(self, context: ValidatorContext) -> None:
        # Your validation logic here
        testbeds = context.get_testbeds()
        conn_graph = context.get_connection_graph()  # Single group

        # Add issues with structured details
        if some_condition:
            self.result.add_issue('E8001', {
                'device': device_info,
                'port': port_name,
                'expected': expected_value,
                'actual': actual_value
            })

        # Add summary issue
        if self.result.success:
            self.result.add_issue('I8000', {'device_count': len(devices)})
```

**For global validation across all groups:**

```python
from validators import GlobalValidator, ValidatorContext, register_validator

@register_validator("my_global_validator")
class MyGlobalValidator(GlobalValidator):
    def __init__(self, config=None):
        super().__init__(
            name="my_global_validator",
            description="My global validation logic",
            category="custom"
        )
        self.config = config or {}

    def _validate(self, context: ValidatorContext) -> None:
        # Your validation logic here
        testbeds = context.get_testbeds()
        all_conn_graphs = context.get_all_connection_graphs()  # All groups

        # Add issues with structured details
        if some_condition:
            self.result.add_issue('E8002', {
                'group': group_name,
                'config_type': config_type,
                'required_fields': missing_fields
            })

        # Add summary issue
        if self.result.success:
            self.result.add_issue('I8000', {'group_count': len(all_conn_graphs)})
```

#### 6.1.3. Step 3: Issue Reporting Best Practices

**Use structured details for better reporting:**

```python
# Instead of embedding details in the message:
self.result.add_issue('E8001', f'Device {device} port {port} has invalid VLAN {vlan_id}')

# Use structured details (message comes from issue definition):
self.result.add_issue('E8001', {
    'device': device,
    'port': port,
    'vlan_id': vlan_id,
    'valid_range': '1-4096'
})
```

**Benefits of structured details:**

- **Programmatic processing**: Easy to parse and analyze results
- **Consistent formatting**: Automatic formatting of details in output
- **Better filtering**: Filter results by specific detail fields
- **Rich context**: Include all relevant metadata without cluttering the message

#### 6.1.4. Step 4: Register in configuration

```yaml
validators:
  - name: my_group_validator
    enabled: true
    config:
      custom_setting: value
  - name: my_global_validator
    enabled: true
    config:
      custom_setting: value
  - name: device_info
    enabled: true
    config:
      invalid_chars: [' ', '\t', '\n', '\r']
      max_length: 255
```

### 6.2. Adding Validation Hooks

**Hook into validation events:**

```python
from validators import ValidationOrchestrator

def log_start(validator, context):
    print(f"Starting validation: {validator.name}")

def log_end(validator, result):
    if result.success:
        print(f"✅ {validator.name}: PASSED")
    else:
        print(f"❌ {validator.name}: FAILED")

orchestrator = ValidationOrchestrator()
orchestrator.add_hook('before_validator', log_start)
orchestrator.add_hook('after_validator', log_end)
```

**Available hook events:**

- `before_validation`: Before all validators run
- `after_validation`: After all validators complete
- `before_validator`: Before each validator runs
- `after_validator`: After each validator completes
- `on_error`: When a validator fails
- `on_warning`: When a validator produces warnings

## 7. Examples and Use Cases

### 7.1. Example 1: CI/CD Pipeline Integration

```bash
#!/bin/bash
# CI validation script
python3 meta_validator.py \
    --fail-fast \
    --config ci_config.yaml

if [ $? -eq 0 ]; then
    echo "✅ All validations passed"
else
    echo "❌ Validation failed"
    exit 1
fi
```

### 7.2. Example 2: Development Environment Setup

```bash
# Create development configuration
python3 meta_validator.py --create-sample-config dev_config.yaml

# Edit dev_config.yaml to enable only needed validators
# Run with relaxed settings
python3 meta_validator.py \
    --config dev_config.yaml \
    --warnings-as-errors
```

### 7.3. Example 3: Custom Validation Pipeline

```python
from validators import (
    ValidationOrchestrator, ConfigLoader, ValidatorConfigManager,
    get_default_registry, ValidatorContext
)

# Load configuration
config_loader = ConfigLoader()
config = config_loader.load_from_file("custom_config.yaml")

# Create validators
registry = get_default_registry()
config_manager = ValidatorConfigManager(registry, config_loader)
validators = config_manager.create_validators_from_config(config)

# Setup orchestrator with hooks
orchestrator = ValidationOrchestrator()
orchestrator.add_hook('on_error', lambda v, r: print(f"Validator {v.name} failed"))

# Create context and run validation
context = ValidatorContext(testbeds, conn_graph)
summary = orchestrator.validate(validators, context)

print(f"Validation completed: {summary.success_rate:.1f}% success rate")
```
