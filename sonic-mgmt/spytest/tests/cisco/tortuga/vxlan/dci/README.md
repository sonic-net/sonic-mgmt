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

### Basic Test Execution

#### For Ubuntu Hosts (8D topology):
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml \
              --device-feature-group master \
              --module-init-max-timeout=7200 \
              --tc-max-timeout=7200 \
              --topology-check=skip \
              --skip-init-checks \
              --skip-init-config \
              --port-init-wait=2 \
              /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

#### For Ixia Emulated Hosts (6D topology with emulated Leaf3/Leaf4):
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_6D_linux_ixia_carib.yaml \
              --device-feature-group master \
              --module-init-max-timeout=7200 \
              --tc-max-timeout=7200 \
              --topology-check=skip \
              --skip-init-checks \
              --skip-init-config \
              --port-init-wait=2 \
              /data/tests/cisco/tortuga/vxlan/dci/test_config.py \
              --deploy-leaf-on-ixia \
              --ixia-config-file=emulated_leaf_and_host.ixncfg \
              --ixia-api-key=<your_ixia_api_key>
```

## Command Line Arguments

The following custom command line arguments are available in `conftest.py`:

### Topology Configuration
- `--topology`: Specify topology type (default: "8d_3dc")
- `--deploy-leaf-on-ixia`: Deploy leaf devices on Ixia (required for 6D topology with emulated Leaf3-Host3 and Leaf4-Host4)

### Configuration Management
- `--dci-config-file`: Path to DCI configuration file in YAML format (default: from const.py)
- `--no-config`: Skip configuration of devices and jump directly to tests
- `--cleanup`: Remove existing configuration from setup before running tests

### Ixia Integration (for emulated hosts)
- `--ixia-config-file`: Ixia configuration file (.ixncfg) for traffic generation (default: "emulated_leaf_and_host.ixncfg")
- `--ixia-api-key`: Ixia API key for authentication with Ixia Web API (required when using `--deploy-leaf-on-ixia`)

## Topology Details

### 8D_3DC Topology (Ubuntu Hosts)
- **File**: `tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml`
- **Description**: 8 devices, 3 data centers with real Ubuntu hosts
- **Devices**: DC1GW1, DC1GW2, DC2GW1, DC3GW1, Leaf1, Leaf2, Leaf3, Leaf4
- **Hosts**: Host1, Host2, Host3, Host4 (Ubuntu systems)

### 6D_3DC Topology (Ixia Emulated Hosts)
- **File**: `tortuga_spytest_dci_3DC_6D_linux_ixia_carib.yaml`
- **Description**: 6 devices, 3 data centers with emulated Leaf3-Host3 and Leaf4-Host4 via Ixia
- **Devices**: DC1GW1, DC1GW2, DC2GW1, DC3GW1, Leaf1, Leaf2
- **Emulated**: Leaf3-Host3, Leaf4-Host4 (via Ixia traffic generator)
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

### Standard Test Run (Ubuntu Hosts)
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml \
              --device-feature-group master \
              --module-init-max-timeout=7200 \
              --tc-max-timeout=7200 \
              --topology-check=skip \
              --skip-init-checks \
              --skip-init-config \
              --port-init-wait=2 \
              /data/tests/cisco/tortuga/vxlan/dci/test_config.py
```

### Cleanup Run (Remove Configuration)
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml \
              --device-feature-group master \
              --module-init-max-timeout=7200 \
              --tc-max-timeout=7200 \
              --topology-check=skip \
              --skip-init-checks \
              --skip-init-config \
              --port-init-wait=2 \
              /data/tests/cisco/tortuga/vxlan/dci/test_config.py \
              --cleanup
```

### Skip Configuration (Test Only)
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml \
              --device-feature-group master \
              --module-init-max-timeout=7200 \
              --tc-max-timeout=7200 \
              --topology-check=skip \
              --skip-init-checks \
              --skip-init-config \
              --port-init-wait=2 \
              /data/tests/cisco/tortuga/vxlan/dci/test_config.py \
              --no-config
```

### Ixia Emulated Hosts
```bash
./bin/spytest --testbed /data/tortuga_spytest_dci_3DC_6D_linux_ixia_carib.yaml \
              --device-feature-group master \
              --module-init-max-timeout=7200 \
              --tc-max-timeout=7200 \
              --topology-check=skip \
              --skip-init-checks \
              --skip-init-config \
              --port-init-wait=2 \
              /data/tests/cisco/tortuga/vxlan/dci/test_config.py \
              --deploy-leaf-on-ixia \
              --ixia-config-file=emulated_leaf_and_host.ixncfg \
              --ixia-api-key=<api_key>
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
- Ixia integration requires valid API key and configuration file
- TextFSM templates provide structured parsing of SONiC show commands
- Helper functions eliminate code duplication across test scenarios
