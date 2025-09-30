# DCI Configuration Deployment Scripts

## Overview
This directory contains comprehensive scripts for deploying Data Center Interconnect (DCI) configurations across SONiC devices and HOST systems in a multi-datacenter EVPN-VXLAN topology.

## Directory Structure
```
dci/
├── scripts/                      # Deployment and utility scripts
│   ├── deploy_dci.sh            # Main deployment script
│   ├── tmux_ssh_connect.sh      # tmux session manager
│   └── README.md                # This documentation
├── configs/                      # Topology-specific configurations
│   ├── 6d_2dc/                  # 6-Device 2-DC topology configs
│   │   ├── SD1-complete-config.txt
│   │   ├── SD2-complete-config.txt
│   │   ├── SD3-complete-config.txt
│   │   ├── SD5-complete-config.txt
│   │   ├── SD6-complete-config.txt
│   │   ├── SD7-complete-config.txt
│   │   ├── HOST1-complete-config.txt
│   │   ├── HOST2-complete-config.txt
│   │   └── HOST3-complete-config.txt
│   └── 8d_3dc/                  # 8-Device 3-DC topology configs
│       ├── SD1-complete-config.txt
│       ├── SD2-complete-config.txt
│       ├── SD3-complete-config.txt
│       ├── SD4-complete-config.txt
│       ├── SD5-complete-config.txt
│       ├── SD6-complete-config.txt
│       ├── SD7-complete-config.txt
│       ├── SD8-complete-config.txt
│       ├── HOST1-complete-config.txt
│       ├── HOST2-complete-config.txt
│       ├── HOST3-complete-config.txt
│       └── HOST4-complete-config.txt
└── pyvxr_yaml_files/            # Topology YAML files
    ├── tortuga_spytest_dci_2DC_6D_linux_ubuntu_carib.yaml
    └── tortuga_spytest_dci_3DC_8D_linux_ubuntu_carib.yaml
```

## Scripts Included
- **`deploy_dci.sh`** - Main deployment script with topology selection and configuration management
- **`tmux_ssh_connect.sh`** - tmux session manager for device connections (supports all 8 devices)

## Prerequisites

### System Requirements
1. **Deploy PyVXR Topology**: First deploy your PyVXR topology using the appropriate YAML file
2. **Generate ports.json**: After topology deployment, generate the ports file:
   ```bash
   cd <your_topology_directory>
   vxr ports > ports.json
   ```

### Required Tools
- `jq` - JSON processor
- `sshpass` - SSH password authentication
- `tmux` - Terminal multiplexer (for tmux_ssh_connect.sh)

---

## 1. Main Deployment Script (deploy_dci.sh)

### NEW: Topology Selection Support
The deploy script now supports multiple topology configurations using the `--config-folder` option:

### Basic Usage
```bash
# Deploy 6-device 2-DC topology
./scripts/deploy_dci.sh --config-folder 6d_2dc ./ports.json

# Deploy 8-device 3-DC topology  
./scripts/deploy_dci.sh --config-folder 8d_3dc ./ports.json
```

### Command Line Options
```bash
./scripts/deploy_dci.sh [OPTIONS] --config-folder <topology> <ports.json>

Topology Options:
  --config-folder 6d_2dc    Deploy 6-device 2-DC topology (SD1,2,3,5,6,7 + HOST1,2,3)
  --config-folder 8d_3dc    Deploy 8-device 3-DC topology (SD1-8 + HOST1-4)

Device Selection:
  --devices <list>          Comma-separated list of devices to configure (e.g., SD1,SD4,SD8)
                           If not specified, all discovered devices are configured

Other Options:
  --reset, -r               Force device reset phase (default: skip reset)
  --log, -l                 Enable detailed logging to file
  --frr-only, -f            Apply only FRR BGP configurations
  --frr-debs <dir>          Install FRR debs from directory, restart BGP docker, and reconfigure FRR
  --sequential              Use sequential processing instead of parallel
  --help, -h                Show help message
```

### Deployment Examples
```bash
# Standard deployment (recommended) - from sonic-test directory
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc /path/to/ports.json

# With detailed logging
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --log /path/to/ports.json

# Configure only specific devices (selective deployment)
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD4,SD8 /path/to/ports.json

# Configure single device with FRR-only mode
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD1 --frr-only /path/to/ports.json

# Force reset and deploy
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --reset /path/to/ports.json

# Install FRR packages and configure (optimized - installs before reset)
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --reset --frr-debs /path/to/frr_debs /path/to/ports.json

# Install FRR packages on running system
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --frr-debs /path/to/frr_debs /path/to/ports.json

# Only apply BGP configurations with new FRR packages
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --frr-only --frr-debs /path/to/frr_debs /path/to/ports.json

# Sequential mode (safer but slower)
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --sequential --log /path/to/ports.json

# Configure only DC3 devices (SD4 and SD8) with reset
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD4,SD8 --reset /path/to/ports.json
```

### Device Filtering (NEW)
The `--devices` option allows you to selectively configure only specific devices instead of all discovered devices. This is useful for:

- **Targeted Updates**: Apply configuration changes to specific devices only
- **Testing**: Deploy configurations to a subset of devices for validation
- **Incremental Deployment**: Add new devices to existing topology one at a time
- **Troubleshooting**: Reconfigure only problematic devices

#### Device Filtering Examples
```bash
# Configure only border gateways
./scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD1,SD2,SD3,SD4 ports.json

# Configure only leaf switches
./scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD5,SD6,SD7,SD8 ports.json

# Configure single DC (e.g., DC3 devices)
./scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD4,SD8 ports.json

# Emergency fix for specific device
./scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD3 --frr-only ports.json
```

#### Device Filtering Notes
- Device names must match exactly those in `ports.json` (case-sensitive)
- Invalid device names will cause the script to exit with an error
- HOST devices can also be filtered (e.g., `--devices HOST1,HOST2`)
- If `--devices` is not specified, all discovered devices are configured (original behavior)

### What deploy_dci.sh Does

#### Standard Deployment Phases
1. **Device Discovery** - Discovers SD and HOST devices from ports.json
2. **Configuration Application** - Applies SONiC and FRR configurations
3. **Final Validation** - BGP convergence and connectivity testing

#### With --reset Option
1. **FRR Package Installation** (if --frr-debs provided) - Installs before reset for optimization
2. **Device Reset** - Resets SD devices and reboots
3. **Wait for Online** - Waits for devices to come back online
4. **Configuration Application** - Applies configurations (BGP docker already has packages)
5. **Final Validation** - BGP convergence and connectivity testing

#### With --frr-debs Option (no reset)
1. **Device Discovery** - Verifies connectivity
2. **FRR Package Installation** - Installs packages and restarts BGP docker
3. **Configuration Application** - Applies configurations  
4. **Final Validation** - BGP convergence and connectivity testing

---

## Configuration Files Required
The scripts expect these configuration files in the same directory:
- `SD1-complete-config.txt` through `SD7-complete-config.txt` - SONiC and FRR configurations
- `HOST1-complete-config.txt` through `HOST3-complete-config.txt` - Host networking configurations

---

## Key Features

### deploy_dci.sh Features
- **Parallel Processing**: Configures multiple devices simultaneously for speed
- **FRR Package Management**: Install new FRR packages with optimization
- **Wait for All Devices**: Ensures ALL devices complete successfully (no early exits)
- **Bulk SONiC Operations**: Sends multiple commands in batches for efficiency
- **Error Handling**: Comprehensive error reporting and recovery
- **No Manual Intervention**: Runs completely automated (no confirmation prompts)

### FRR Package Optimization
- **Before Reset**: Installs packages before reset to avoid BGP docker restart after reboot
- **Running System**: Installs packages and restarts BGP docker on live systems
- **Parallel Installation**: Installs packages on multiple devices simultaneously

---

## Topology Support
Designed for the **6D Linux DCI Ubuntu Carib** topology with:
- **6 SONiC Devices**: SD1, SD2, SD3 (DCI Gateways), SD5, SD6, SD7 (DC Leaves)
- **3 HOST Devices**: HOST1, HOST2, HOST3 (Traffic generators/endpoints)
- **Multi-DC EVPN**: Inter-datacenter BGP EVPN-VXLAN connectivity
- **VXLAN Overlay**: Layer 2 stretch with Layer 3 VPN services

### Device Roles
- **SD1, SD2** - DC1 EVPN Gateways (BGP AS 65001, 65002)
- **SD3** - DC2 EVPN Gateway (BGP AS 65003)  
- **SD5, SD6** - DC1 Leaf switches (BGP AS 65005, 65006)
- **SD7** - DC2 Leaf switch (BGP AS 65007)
- **HOST1, HOST2** - DC1 endpoints
- **HOST3** - DC2 endpoint

---

## Typical Workflows

### Full Deployment with FRR Updates
```bash
# 1. Deploy PyVXR topology
pyvxr deploy tortuga_spytest_8D_linux_dci_ubuntu_carib.yaml

# 2. Generate ports file
cd /topology/directory
vxr ports > ports.json

# 3. Deploy with FRR package updates (optimized)
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --reset --frr-debs /path/to/frr_debs --log ports.json

# 4. Set up tmux sessions for monitoring
tmux new-session
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/tmux_ssh_connect.sh ports.json
```

### Incremental Deployment Workflow
```bash
# 1. Deploy border gateways first
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD1,SD2,SD3,SD4 --log ports.json

# 2. Verify BGP connectivity between DCs
# ... manual verification steps ...

# 3. Deploy leaf switches
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD5,SD6,SD7,SD8 --log ports.json

# 4. Deploy HOST devices
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices HOST1,HOST2,HOST3,HOST4 --log ports.json
```

### Quick Configuration Update
```bash
# Apply only configuration changes (no reset)
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc ports.json

# Apply only BGP changes
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --frr-only ports.json

# Update specific devices only
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD2,SD5 --frr-only ports.json

# Quick fix for single device
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD3 ports.json
```



---

## Monitoring & Validation

### Quick Status Checks
```bash
# Check BGP status on SD1
sshpass -p 'cisco123' ssh -p $(jq -r '.SD1.xr_redir22' ports.json) cisco@$(jq -r '.SD1.HostAgent' ports.json) 'vtysh -c "show bgp summary"'

# Check VXLAN tunnels
sshpass -p 'cisco123' ssh -p $(jq -r '.SD1.xr_redir22' ports.json) cisco@$(jq -r '.SD1.HostAgent' ports.json) 'show vxlan tunnel'

# Check interface status
sshpass -p 'cisco123' ssh -p $(jq -r '.SD1.xr_redir22' ports.json) cisco@$(jq -r '.SD1.HostAgent' ports.json) 'show interface status'
```

### tmux Synchronized Commands
```bash
# In tmux DCI_Gateways window:
Ctrl+b then :
setw synchronize-panes on
# Now type commands that will execute on all DCI gateways simultaneously
vtysh -c "show bgp summary"
```

---

## Logging & Runtime

### Logging Options
- **Console Output**: Real-time progress with colored status indicators
- **File Logging**: Use `--log` for detailed timestamped logs
- **Operation Tracking**: All commands and results are logged

### Estimated Runtime
- **Full deployment (parallel)**: ~15-20 minutes
- **Full deployment (sequential)**: ~30-45 minutes  
- **FRR-only (parallel)**: ~5-10 minutes
- **FRR package installation**: ~10-15 minutes
- **With --reset**: +10-15 minutes for reboot wait

---

## Troubleshooting

### Common Issues
1. **SSH Connection Failures**
   - Verify devices are accessible: `ping $(jq -r '.SD1.HostAgent' ports.json)`
   - Check SSH ports: `telnet $(jq -r '.SD1.HostAgent' ports.json) $(jq -r '.SD1.xr_redir22' ports.json)`

2. **Configuration Application Failures**  
   - Check device readiness: All devices must be online before configuration
   - Verify configuration files exist and have correct syntax
   - Use `--log` flag for detailed error information

3. **Device Filtering Issues**
   - Invalid device names: Check device names match exactly those in `ports.json`
   - Missing devices: Verify devices exist in topology before filtering
   - Check available devices: `jq -r 'keys[]' ports.json | sort`

4. **BGP Convergence Issues**
   - Check BGP neighbor configuration: `vtysh -c "show running-config bgp"`
   - Verify interface status: `show interface status`
   - Check VXLAN tunnel status: `show vxlan tunnel`

5. **tmux Session Issues**
   - Ensure tmux version 2.6+: `tmux -V`
   - Add pane title configuration to `~/.tmux.conf`
   - Run script from within tmux session

### Debug Commands
```bash
# Enable detailed logging
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --log --sequential ports.json

# Debug specific device configuration
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices SD4 --log --sequential ports.json

# Check available devices in ports.json
jq -r 'keys[]' ports.json | sort

# Manual SSH test
sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -p $(jq -r '.SD1.xr_redir22' ports.json) cisco@$(jq -r '.SD1.HostAgent' ports.json) 'echo "Connection test successful"'

# Test device filtering validation
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/deploy_dci.sh --config-folder 8d_3dc --devices InvalidDevice ports.json
```

---

## tmux Session Management (tmux_ssh_connect.sh) - OPTIONAL

### Overview
**NOTE: This section is OPTIONAL.** The tmux script is a convenience tool for managing multiple device connections simultaneously. The main deployment script (`deploy_dci.sh`) works independently and does not require tmux.

The `tmux_ssh_connect.sh` script creates organized tmux sessions for managing SSH connections to all devices in your DCI topology. It automatically organizes devices into separate windows based on their roles.

### Prerequisites
```bash
# Install tmux with minimum version 2.6+
sudo apt update && sudo apt install tmux

# Check tmux version (should be 2.6+)
tmux -V

# Enable pane titles (add to ~/.tmux.conf)
set -g pane-border-status top
set -g pane-border-format "#{pane_title}"

# Reload tmux config
tmux source-file ~/.tmux.conf
```

### Usage
```bash
# Must be run from within a tmux session - from sonic-test directory
tmux new-session
./sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/tmux_ssh_connect.sh /path/to/ports.json
```

### What tmux_ssh_connect.sh Does
Creates 4 separate tmux windows with organized SSH connections:

1. **DC_Leaves** - DC Leaf devices (SD5, SD6, SD7) - cisco/cisco123
2. **DCI_Gateways** - DCI Gateway devices (SD1, SD2, SD3) - cisco/cisco123  
3. **HOST_devices** - HOST devices (HOST1, HOST2, HOST3) - vxr/cisco123
4. **sonic_mgmt** - sonic_mgmt device (2 panes) - vxr/cisco123

### tmux Controls & Shortcuts

#### Basic Navigation
```bash
Ctrl+b then w       # Show all windows and switch between them
Ctrl+b then n/p     # Next/previous window  
Ctrl+b then 0,1,2   # Switch to specific window number
Ctrl+b then arrow   # Navigate between panes within window
```

#### Pane Management
```bash
Ctrl+b then z       # Zoom/unzoom current pane (fullscreen toggle)
Ctrl+b then x       # Close current pane (with confirmation)
Ctrl+b then &       # Close entire window (with confirmation)
Ctrl+b then !       # Break pane out into new window
```

#### Advanced Pane Operations
```bash
# Close all panes in current window
Ctrl+b then :
kill-window

# Synchronize input across all panes in window (type same command to all)
Ctrl+b then :
setw synchronize-panes on

# Turn off pane synchronization
Ctrl+b then :
setw synchronize-panes off

# Split current pane horizontally
Ctrl+b then "

# Split current pane vertically  
Ctrl+b then %

# Resize panes
Ctrl+b then Ctrl+arrow keys
```

#### Session Management
```bash
# List all sessions
tmux list-sessions

# Attach to existing session
tmux attach-session -t session_name

# Detach from session (keeps running)
Ctrl+b then d

# Kill all tmux sessions
tmux kill-server
```

### Useful tmux Workflows

#### Monitoring All DCI Gateways
```bash
# 1. Switch to DCI_Gateways window
Ctrl+b then w  # Select DCI_Gateways

# 2. Enable synchronization
Ctrl+b then :
setw synchronize-panes on

# 3. Now type commands that execute on all DCI gateways
vtysh -c "show bgp summary"
show interface status

# 4. Turn off synchronization when done
Ctrl+b then :
setw synchronize-panes off
```

#### Quick Device Access
```bash
# Jump to specific window
Ctrl+b then 1  # DC_Leaves
Ctrl+b then 2  # DCI_Gateways  
Ctrl+b then 3  # HOST_devices
Ctrl+b then 4  # sonic_mgmt

# Navigate between panes in window
Ctrl+b then arrow keys

# Zoom to focus on one device
Ctrl+b then z
```

### tmux Session Features
- **Organized Windows**: Separate windows for different device types
- **Pane Titles**: Clear device identification in each pane
- **Bulk Operations**: Synchronize commands across multiple devices
- **Session Persistence**: Sessions remain active even if disconnected
- **Quick Navigation**: Keyboard shortcuts for rapid device switching

---

## File Structure
```
sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/dci/scripts/
├── deploy_dci.sh              # Main deployment script
├── tmux_ssh_connect.sh        # tmux session manager (optional)
├── README.md                  # This documentation
├── SD1-complete-config.txt    # SD1 SONiC + FRR configuration
├── SD2-complete-config.txt    # SD2 SONiC + FRR configuration
├── SD3-complete-config.txt    # SD3 SONiC + FRR configuration
├── SD5-complete-config.txt    # SD5 SONiC + FRR configuration
├── SD6-complete-config.txt    # SD6 SONiC + FRR configuration
├── SD7-complete-config.txt    # SD7 SONiC + FRR configuration
├── HOST1-complete-config.txt  # HOST1 networking configuration
├── HOST2-complete-config.txt  # HOST2 networking configuration
└── HOST3-complete-config.txt  # HOST3 networking configuration
```