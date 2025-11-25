# Data Center Interconnect (DCI) Test Suite

## Overview

The DCI test suite validates VXLAN EVPN-based multi-datacenter connectivity using BGP overlay networks. This test framework supports an 8-device, 3-datacenter topology with comprehensive configuration management, failover testing, and traffic validation.

## Prerequisites

### Environment Setup

1. **Download sonic-mgmt build:**
   ```bash
   wget http://10.29.158.43/builds/keysight-u18070-10-0.tar
   ```

2. **Install required Python packages:**
   ```bash
   pip install monotonic
   pip install retry
   pip install pyopenssl --upgrade
   pip install urllib3 --upgrade
   pip install --upgrade ixnetwork-restpy==1.5.0
   ```

3. **Clear proxy settings:**
   ```bash
   unset https_proxy http_proxy
   ```

## Running Tests

### Environment Variables

The test suite uses environment variables for configuration. Set these before running tests:

```bash
# Required for IXIA-based testing
export DCI_USE_IXIA_FOR_HOSTS="true"
export DCI_IXIA_CONFIG_FILE="ixia_dci_hosts.ixncfg"
export DCI_IXIA_API_KEY="your_api_key_here"

# Optional configuration
export DCI_CONFIG_FILE="dci/device_configs/config_ixia_8D.yaml"  # Default from const.py
export DCI_TOPOLOGY="8d_3dc"                                      # Default: 8d_3dc
export DCI_NO_CONFIG="false"                                      # Default: false
export DCI_CLEANUP="false"                                        # Default: false
export DCI_DEPLOY_LEAF_ON_IXIA="false"                           # Default: false (use for 6D topology)
```

### Basic Test Execution

#### For IXIA-based Traffic Generation (8D topology):
```bash
DCI_USE_IXIA_FOR_HOSTS="true" DCI_IXIA_CONFIG_FILE="ixia_dci_hosts.ixncfg" DCI_IXIA_API_KEY="your_api_key" DCI_CONFIG_FILE="dci/device_configs/config_ixia_8D.yaml" ./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ixia.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

#### For IXIA-based Emulated Leaf and Host (6D topology):
```bash
DCI_DEPLOY_LEAF_ON_IXIA="true" DCI_IXIA_CONFIG_FILE="emulated_leaf_and_host.ixncfg" DCI_IXIA_API_KEY="your_api_key" ./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_6D_linux_ixia_carib.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

#### For Ubuntu Host-based Traffic Generation:
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

## Environment Variables

The following environment variables control test behavior:

### Topology Configuration
- `DCI_TOPOLOGY`: Specify topology type (default: "8d_3dc")
- `DCI_DEPLOY_LEAF_ON_IXIA`: Deploy leaf devices on Ixia (set to "true" for emulated Leaf3/Leaf4)
- `DCI_USE_IXIA_FOR_HOSTS`: Use IXIA for host devices instead of Ubuntu hosts (set to "true")

### Configuration Management
- `DCI_CONFIG_FILE`: Path to DCI configuration file in YAML format (default: from const.py)
- `DCI_NO_CONFIG`: Skip configuration of devices and jump directly to tests (set to "true")
- `DCI_CLEANUP`: Remove existing configuration from setup before running tests (set to "true")

### IXIA Integration (required when using IXIA-based testing)
- `DCI_IXIA_CONFIG_FILE`: IXIA configuration file (.ixncfg) for traffic generation (default: "ixia_dci_hosts.ixncfg")
- `DCI_IXIA_API_KEY`: IXIA API key for authentication with IXIA Web API (required for IXIA-based deployments)

## Topology Details

### 8D_3DC Topology

**IXIA-based Traffic Generation:**
- **File**: `tortuga_spytest_dci_3DC_8D_linux_ixia.yaml`
- **Description**: 8 devices, 3 data centers with IXIA traffic generation
- **Devices**: DC1GW1, DC1GW2, DC2GW1, DC3GW1, Leaf1, Leaf2, Leaf3, Leaf4
- **Traffic Generation**: IXIA T1 device with 6 ports (HOST1-HOST5 emulation)

**Ubuntu Host-based Traffic Generation:**
- **File**: `tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml`
- **Description**: 8 devices, 3 data centers with real Ubuntu hosts
- **Devices**: DC1GW1, DC1GW2, DC2GW1, DC3GW1, Leaf1, Leaf2, Leaf3, Leaf4
- **Hosts**: HOST1, HOST2, HOST3, HOST4, HOST5 (Ubuntu systems with VLAN interfaces)

### 6D_3DC Topology (Emulated Leaf and Host)

**IXIA-based Emulated Leaf and Host:**
- **File**: `tortuga_spytest_dci_3DC_6D_linux_ixia_carib.yaml`
- **Description**: 6 devices, 3 data centers with emulated Leaf3/Host3 and Leaf4/Host4 via IXIA
- **Devices**: DC1GW1, DC1GW2, DC2GW1, DC3GW1, Leaf1, Leaf2
- **Emulated**: Leaf3-Host3, Leaf4-Host4 (via IXIA traffic generator)
- **Required Flag**: `--deploy-leaf-on-ixia`

## Architecture

### Device Roles
- **Gateway Devices**: DC1GW1, DC1GW2, DC2GW1, DC3GW1 - Provide inter-DC connectivity via BGP EVPN
- **Leaf Switches**: Leaf1-4 - Provide intra-DC connectivity and host attachment

### Key Features
- BGP EVPN overlay with VXLAN encapsulation
- Multi-homing with EVPN Ethernet Segments
- Inter-datacenter traffic optimization
- Redundant gateway architecture in DC1

## Core Components

### 1. conftest.py - Test Configuration Framework

**Purpose**: Centralized test setup, device mapping, and configuration management

**Key Functions:**
```python
def testbed_vars(deploy_leaf_on_ixia=False)
    # Maps logical device names to physical testbed devices
    # Returns: tb_vars, nodes dictionary

def setup(command_line_args)
    # Main test setup fixture
    # Handles configuration, traffic validation, Ixia setup
```

### 2. test_config.py - Configuration Tests

**Purpose**: Validates device configuration and reconfiguration scenarios using helper functions

**Test Functions:**
```python
test_configure_devices()       # Initial device configuration + verification
test_deconfigure_devices()     # Complete device cleanup + verification
test_deconfigure_bgp()         # BGP-specific deconfig + verification
test_deconfigure_sonic()       # SONiC-specific deconfig + verification
test_reconfigure_sonic()       # SONiC reconfiguration + verification
```

All test functions now use `verify_dci_remotevtep()` and `verify_dci_remotemac()` helper functions for consistent verification across all gateway nodes.

### 3. sonic_verifiers.py - Verification Functions

**Purpose**: SONiC VXLAN verification functions with TextFSM parsing support

**Key Functions:**
```python
def verify_remotevtep(dut, vtep_data, expected_status="oper_up")
    # Verify remote VTEP entries with tunnel status validation
    # Uses TextFSM template: show_vxlan_remotevtep.tmpl

def verify_remotemac(dut, mac_vtep_vni_list)
    # Verify MAC learning with VTEP/VNI associations
    # Uses TextFSM template: show_vxlan_remotemac_all.tmpl

def verify_dci_remotevtep(nodes, test_name)
    # Helper for DCI gateway VTEP verification

def verify_dci_remotemac(nodes, test_name)
    # Helper for DCI gateway MAC verification
```

### 4. expected_results_sonic.py - Test Data

**Purpose**: Contains expected verification data for remote VTEP and MAC validation

**Data Structures:**
```python
remote_vtep_test_data = {
    "dc1gw1": [("fd27::233:d0c6:feda", "fd27::233:d0c6:fed3"), ...],
    "dc1gw2": [...],
    # Expected (source_vtep, destination_vtep) tuples for each gateway
}

remote_mac_test_data = {
    "dc1gw1": [("00:00:00:00:00:01", "fd27::233:d0c6:fed5", "5010"), ...],
    # Expected (MAC, VTEP, VNI) tuples for each gateway
}
```

### 5. Configuration Framework

**config.py**: Device configuration management
- `configure_devices()`: Orchestrates full device configuration
- `configure_bgp()`: BGP-specific configuration
- `configure_sonic()`: SONiC interface and VXLAN setup

**const.py**: Constants and default paths
- `CONFIG_FILE_PATH_DEFAULT`: Default configuration file path
- `DCI_CLIS`: Common CLI commands

## Configuration File Structure

**Location**: Specified via `--dci-config-file` argument

**Format**: YAML with device-specific sections

**Structure per Device:**
```yaml
device_name:
  pre-sonic-bgp:
    config: |
      # FRRouting commands executed before SONiC setup
    deconfig: |
      # FRRouting cleanup commands
  sonic:
    config: |
      # SONiC interface and VXLAN configuration
    deconfig: |
      # SONiC cleanup commands
  bgp:
    config: |
      # Complete BGP EVPN configuration
    deconfig: |
      # BGP cleanup commands
```

## Usage Examples

**Note**: 
- For IXIA traffic generation (8D): Use `tortuga_spytest_dci_3DC_8D_linux_ixia.yaml` with `DCI_USE_IXIA_FOR_HOSTS="true"`, `DCI_IXIA_CONFIG_FILE`, and `DCI_IXIA_API_KEY`
- For IXIA emulated leaf and host (6D): Use `tortuga_spytest_dci_3DC_6D_linux_ixia_carib.yaml` with `DCI_DEPLOY_LEAF_ON_IXIA="true"`, `DCI_IXIA_CONFIG_FILE`, and `DCI_IXIA_API_KEY`
- For Ubuntu host traffic generation (8D): Use `tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml` (no environment variables needed)

### Standard Test Run (IXIA - 8D Topology)
```bash
DCI_USE_IXIA_FOR_HOSTS="true" DCI_IXIA_CONFIG_FILE="ixia_dci_hosts.ixncfg" DCI_IXIA_API_KEY="your_api_key" DCI_CONFIG_FILE="dci/device_configs/config_ixia_8D.yaml" ./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ixia.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

### Standard Test Run (IXIA - 6D Topology with Emulated Leaf)
```bash
DCI_DEPLOY_LEAF_ON_IXIA="true" DCI_IXIA_CONFIG_FILE="emulated_leaf_and_host.ixncfg" DCI_IXIA_API_KEY="your_api_key" ./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_6D_linux_ixia_carib.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

### Standard Test Run (Ubuntu Hosts)
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

### Cleanup Run (Remove Configuration)
```bash
DCI_CLEANUP="true" ./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ixia.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

### Skip Configuration (Test Only)
```bash
DCI_NO_CONFIG="true" ./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ixia.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --topology-check=skip --skip-init-checks --skip-init-config --port-init-wait=2 /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

### Verification Functions

The test suite uses TextFSM-based verification to validate SONiC VXLAN configuration:

**Remote VTEP Validation**: `verify_remotevtep()`
- Parses `show vxlan remotevtep` output using TextFSM template
- Validates tunnel status (oper_up/oper_down)
- Verifies source and destination VTEP IP addresses

**Remote MAC Validation**: `verify_remotemac()` 
- Parses `show vxlan remotemac all` output using TextFSM template
- Validates MAC address learning with correct VTEP associations
- Verifies VNI (VXLAN Network Identifier) mappings

**DCI Gateway Validation**: Helper functions for multi-node validation
- `verify_dci_remotevtep()`: Validates all gateway VTEP configurations
- `verify_dci_remotemac()`: Validates all gateway MAC learning

### Test Validation Criteria

**Configuration Tests**:
- All BGP sessions in "Established" state
- VXLAN tunnels show "oper_up" status  
- EVPN routes properly exchanged between data centers
- Remote MAC addresses learned with correct VTEP/VNI associations

**Traffic Tests**:
- Zero packet loss for steady-state inter-DC traffic
- Proper load balancing across available paths
- L2 and L3 forwarding working correctly

## Troubleshooting

### Common Issues

**BGP Session Issues**:
```bash
# Check BGP neighbor status
vtysh -c "show bgp l2vpn evpn summary"

# Verify update-source configuration
vtysh -c "show running-config | section bgp"
```

**VXLAN Tunnel Issues**:
```bash  
# Check tunnel status
show vxlan tunnel

# Verify VTEP reachability
ping <remote_vtep_ip>
```

**EVPN Route Issues**:
```bash
# Check EVPN route advertisement
vtysh -c "show bgp l2vpn evpn"

# Verify VNI configuration
show vxlan vni
```

### Debug Commands

**Validation Commands Used by Tests**:
```bash
# Remote VTEP verification (parsed by TextFSM)
show vxlan remotevtep

# Remote MAC verification (parsed by TextFSM)
show vxlan remotemac all

# BGP EVPN status
show bgp l2vpn evpn summary
```

## Notes

- Tests currently support VXR platform only (simulation environment)
- Three traffic generation options supported:
  - IXIA T1 device for host emulation in 8D topology (requires `--use-ixia-for-hosts`, `--ixia-config-file`, and `--ixia-api-key`)
  - IXIA T1 device for emulated Leaf3/Host3 and Leaf4/Host4 in 6D topology (requires `--deploy-leaf-on-ixia`, `--ixia-config-file`, and `--ixia-api-key`)
  - Ubuntu hosts for real Linux-based traffic validation in 8D topology (no additional parameters required)
- IXIA-based deployment requires:
  - Valid IXIA API key for authentication
  - IXIA configuration file (.ixncfg) with traffic patterns
  - Both parameters are mandatory when using `--use-ixia-for-hosts` or `--deploy-leaf-on-ixia`
- TextFSM templates provide structured parsing of SONiC show commands
- Helper functions eliminate code duplication across test scenarios
