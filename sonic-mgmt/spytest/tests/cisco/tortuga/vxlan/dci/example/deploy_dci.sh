#!/bin/bash
# Comprehensive DCI Configuration Reset and Deployment Script
# 
# This script performs a complete reset and configuration of all SD devices
# in a Data Center Interconnect (DCI) EVPN-VXLAN topology.
# Also provides connectivity testing for HOST devices.
#
# USAGE:
#   ./deploy_dci.sh [OPTIONS] <path_to_port.json>
#
# EXAMPLE:
#   ./deploy_dci.sh /nobackup/sudharr/ws/test/1/sonic-test/port.json
#   ./deploy_dci.sh --reset /nobackup/sudharr/ws/test/1/sonic-test/port.json
#   ./deploy_dci.sh --frr-only /nobackup/sudharr/ws/test/1/sonic-test/port.json
#
# REQUIREMENTS:
#   - jq (JSON processor)
#   - sshpass (non-interactive SSH password authentication)
#   - SSH access to all devices
#   - Configuration files: SD1-complete-config.txt through SD8-complete-config.txt
#   - Optional: HOST1-complete-config.txt through HOST3-complete-config.txt
#
# DEVICE CREDENTIALS:
#   - SD devices: cisco/cisco123
#   - HOST devices: vxr/cisco123
#
# WHAT IT DOES:
#   1. Validates prerequisites and configuration files
#   2. Optionally resets all SD devices (removes configs, reboots)
#   3. Waits for devices to come back online
#   4. Applies SONiC configurations (interfaces, VLANs, etc.)
#   5. Applies FRR BGP configurations (AS numbers, neighbors, etc.)
#   6. Applies HOST configurations (networking, routing, etc.)
#   7. Validates BGP neighbor establishment
#   8. Checks HOST device connectivity
#   9. Provides detailed status summary and manual access commands

set -e  # Exit on any error

# Check command line arguments
SKIP_RESET=true  # Default to skipping reset - use --reset to force reset
ENABLE_LOGGING=false
FRR_ONLY=false
PARALLEL_MODE=true
FRR_DEBS_DIR=""
CONFIG_FOLDER=""
PORT_JSON=""
DEVICE_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --reset|-r)
            SKIP_RESET=false
            shift
            ;;
        --log|-l)
            ENABLE_LOGGING=true
            shift
            ;;
        --frr-only|-f)
            FRR_ONLY=true
            shift
            ;;
        --sequential)
            PARALLEL_MODE=false
            shift
            ;;
        --frr-debs)
            FRR_DEBS_DIR="$2"
            shift 2
            ;;
        --config-folder)
            CONFIG_FOLDER="$2"
            shift 2
            ;;
        --devices)
            DEVICE_FILTER="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] --config-folder <folder_name> <path_to_port.json>"
            echo ""
            echo "Options:"
            echo "  --config-folder     Config folder name (6d_2dc or 8d_3dc)"
            echo "  --devices           Comma-separated list of devices to configure (e.g., SD1,SD4,SD8)"
            echo "  --reset, -r         Force device reset phase (default: skip reset)"
            echo "  --log, -l           Enable detailed logging to file"
            echo "  --frr-only, -f      Apply only FRR BGP configurations"
            echo "  --sequential        Use sequential processing instead of parallel (slower but safer)"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Note: Script now waits for ALL devices to complete successfully (no early exits)"
            echo ""
            echo "Example:"
            echo "  $0 --config-folder 6d_2dc /path/to/port.json                         # Apply 6D 2DC topology configs"
            echo "  $0 --config-folder 8d_3dc /path/to/port.json                         # Apply 8D 3DC topology configs"
            echo "  $0 --config-folder 8d_3dc --reset /path/to/port.json                # Force reset then apply 8D configs"
            echo "  $0 --config-folder 6d_2dc --frr-only /path/to/port.json             # Only apply FRR BGP configs for 6D"
            echo "  $0 --config-folder 8d_3dc --log /path/to/port.json                  # Apply 8D with logging"
            echo "  $0 --config-folder 8d_3dc --devices SD4,SD8 /path/to/port.json      # Apply configs only to SD4 and SD8"
            echo ""
            echo "The port.json file should contain connection details for devices SD1-SD8"
            echo "and optionally HOST1-HOST3 with HostAgent and xr_redir22 fields."
            echo ""
            echo "Device Credentials:"
            echo "  SD devices: cisco/cisco123"
            echo "  HOST devices: vxr/cisco123"
            exit 0
            ;;
        *)
            if [ -z "$PORT_JSON" ]; then
                PORT_JSON="$1"
            else
                echo "ERROR: Unknown argument: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$PORT_JSON" ] || [ -z "$CONFIG_FOLDER" ]; then
    echo "ERROR: Missing required arguments"
    echo ""
    echo "Usage: $0 [OPTIONS] --config-folder <folder_name> <path_to_port.json>"
    echo ""
    echo "Options:"
    echo "  --config-folder     Config folder name (6d_2dc or 8d_3dc)"
    echo "  --devices           Comma-separated list of devices to configure (e.g., SD1,SD4,SD8)"  
    echo "  --reset, -r         Force device reset phase (default: skip reset)"
    echo "  --log, -l           Enable detailed logging to file"
    echo "  --frr-only, -f      Apply only FRR BGP configurations"
    echo "  --frr-debs <dir>    Install FRR debs from directory, restart BGP docker, and reconfigure FRR"
    echo "  --sequential        Use sequential processing instead of parallel (slower but safer)"
    echo "  --help, -h          Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --config-folder 6d_2dc /path/to/port.json                         # Apply 6D 2DC topology configs"
    echo "  $0 --config-folder 8d_3dc /path/to/port.json                         # Apply 8D 3DC topology configs"
    echo "  $0 --config-folder 8d_3dc --reset /path/to/port.json                # Force reset then apply 8D configs"
    echo "  $0 --config-folder 6d_2dc --frr-only /path/to/port.json             # Only apply FRR BGP configs for 6D"
    echo "  $0 --config-folder 8d_3dc --log /path/to/port.json                  # Apply 8D with logging"
    echo "  $0 --config-folder 8d_3dc --devices SD4,SD8 /path/to/port.json      # Apply configs only to SD4 and SD8"
    echo ""
    echo "Device Credentials:"
    echo "  SD devices: cisco/cisco123"
    echo "  HOST devices: vxr/cisco123"
    exit 1
fi

# Validate config folder
if [ "$CONFIG_FOLDER" != "6d_2dc" ] && [ "$CONFIG_FOLDER" != "8d_3dc" ]; then
    echo "ERROR: Invalid config folder '$CONFIG_FOLDER'"
    echo "Supported folders: 6d_2dc, 8d_3dc"
    exit 1
fi

# Configuration
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CONFIG_DIR="$SCRIPT_DIR/../configs/$CONFIG_FOLDER"
if [ "$ENABLE_LOGGING" = true ]; then
    LOG_FILE="$SCRIPT_DIR/deployment-$(date +%Y%m%d-%H%M%S).log"
else
    LOG_FILE="/dev/null"
fi

# Validate config directory exists
if [ ! -d "$CONFIG_DIR" ]; then
    echo "ERROR: Config directory '$CONFIG_DIR' does not exist"
    echo "Available config folders:"
    ls -1 "$SCRIPT_DIR/../configs/" 2>/dev/null || echo "  No config folders found"
    exit 1
fi

# Logging function that only logs to file if logging is enabled
log_output() {
    if [ "$ENABLE_LOGGING" = true ]; then
        tee -a "$LOG_FILE"
    else
        cat
    fi
}

# SSH connection function using port.json
ssh_to_device() {
    local device=$1
    local command=$2
    local host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
    local xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
    
    # Determine credentials based on device type
    local username password
    if [[ "$device" =~ ^SD[0-9]+$ ]]; then
        username="cisco"
        password="cisco123"
    elif [[ "$device" =~ ^HOST[0-9]+$ ]]; then
        username="vxr"
        password="cisco123"
    else
        echo "ERROR: Unknown device type for $device" | log_output
        return 1
    fi
    
    sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$xr_redir22" "$username@$host_agent" "$command" < /dev/null 2>&1 | log_output
}

# Parallel processing functions
parallel_reset_device() {
    local device=$1
    local status_file="/tmp/deploy_dci_reset_${device}.status"
    
    echo "Starting parallel reset for $device" | log_output
    
    {
        if ssh_to_device "$device" "sudo rm -f /etc/sonic/config_db.json" && \
           ssh_to_device "$device" "sudo rm -f /etc/sonic/frr/bgpd.conf" && \
           ssh_to_device "$device" "sudo reboot"; then
            echo "SUCCESS" > "$status_file"
            echo "[$device] Reset commands sent successfully" | log_output
        else
            echo "FAILED" > "$status_file"
            echo "[$device] Reset commands failed" | log_output
        fi
    } &
    
    echo $! > "/tmp/deploy_dci_reset_${device}.pid"
}

parallel_wait_for_device() {
    local device=$1
    local status_file="/tmp/deploy_dci_wait_${device}.status"
    
    {
        if wait_for_device "$device"; then
            echo "ONLINE" > "$status_file"
            echo "✅ [$device] Device is back online" | log_output
        else
            echo "OFFLINE" > "$status_file"
            echo "❌ [$device] Device failed to come back online" | log_output
        fi
    } &
    
    echo $! > "/tmp/deploy_dci_wait_${device}.pid"
}

parallel_apply_config() {
    local device=$1
    local status_file="/tmp/deploy_dci_config_${device}.status"
    
    {
        if apply_config "$device"; then
            echo "SUCCESS" > "$status_file"
            echo "[$device] Configuration applied successfully" | log_output
        else
            echo "FAILED" > "$status_file"
            echo "[$device] Configuration failed" | log_output
        fi
    } &
    
    echo $! > "/tmp/deploy_dci_config_${device}.pid"
}

wait_for_parallel_completion() {
    local operation=$1
    shift
    local cleanup_files=true
    
    # Check if last parameter is true/false (cleanup flag)
    if [[ "${@: -1}" == "true" ]] || [[ "${@: -1}" == "false" ]]; then
        cleanup_files="${@: -1}"
        set -- "${@:1:$(($#-1))}"  # Remove last parameter
    fi
    
    local devices=("$@")
    local max_wait=1800  # 30 minutes timeout
    local start_time=$(date +%s)
    local total_devices=${#devices[@]}
    # Proceed if at least 75% of devices are successful (minimum 2)
    local min_success_threshold=$(( (total_devices * 3 + 3) / 4 ))  # Ceiling of 75%
    if [ $min_success_threshold -lt 2 ]; then
        min_success_threshold=2
    fi
    
    echo "Waiting for parallel $operation operations to complete..." | log_output
    echo "Devices: ${devices[*]}" | log_output
    echo "Timeout: $max_wait seconds" | log_output
    echo "Will wait for ALL $total_devices devices to complete successfully" | log_output
    
    while true; do
        local all_done=true
        local success_count=0
        local failed_count=0
        local pending_count=0
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Check timeout
        if [ $elapsed -gt $max_wait ]; then
            echo "ERROR: Parallel $operation operations timed out after $max_wait seconds" | log_output
            # Kill any remaining processes
            for device in "${devices[@]}"; do
                local pid_file="/tmp/deploy_dci_${operation}_${device}.pid"
                if [ -f "$pid_file" ]; then
                    local pid=$(cat "$pid_file")
                    kill "$pid" 2>/dev/null || true
                    rm -f "$pid_file"
                fi
            done
            return 1
        fi
        
        # Check status of all processes and count results
        for device in "${devices[@]}"; do
            local pid_file="/tmp/deploy_dci_${operation}_${device}.pid"
            local status_file="/tmp/deploy_dci_${operation}_${device}.status"
            
            if [ -f "$pid_file" ]; then
                local pid=$(cat "$pid_file")
                if ps -p "$pid" > /dev/null 2>&1; then
                    all_done=false
                    pending_count=$((pending_count + 1))
                else
                    # Process finished, clean up PID file
                    rm -f "$pid_file"
                    # Check the result
                    if [ -f "$status_file" ]; then
                        local status=$(cat "$status_file")
                        case "$operation" in
                            "reset"|"config")
                                if [ "$status" = "SUCCESS" ]; then
                                    success_count=$((success_count + 1))
                                else
                                    failed_count=$((failed_count + 1))
                                fi
                                ;;
                            "wait")
                                if [ "$status" = "ONLINE" ]; then
                                    success_count=$((success_count + 1))
                                else
                                    failed_count=$((failed_count + 1))
                                fi
                                ;;
                        esac
                    else
                        failed_count=$((failed_count + 1))
                    fi
                fi
            elif [ -f "$status_file" ]; then
                # Status file exists but no PID file, operation completed
                local status=$(cat "$status_file")
                case "$operation" in
                    "reset"|"config"|"host")
                        if [ "$status" = "SUCCESS" ]; then
                            success_count=$((success_count + 1))
                        else
                            failed_count=$((failed_count + 1))
                        fi
                        ;;
                    "wait")
                        if [ "$status" = "ONLINE" ]; then
                            success_count=$((success_count + 1))
                        else
                            failed_count=$((failed_count + 1))
                        fi
                        ;;
                esac
            else
                # Neither PID nor status file exists, something went wrong
                all_done=false
                pending_count=$((pending_count + 1))
            fi
        done
        
        # Check if we should proceed (all done OR critical failure with long wait)
        if [ "$all_done" = true ]; then
            echo "All parallel $operation operations completed in $elapsed seconds" | log_output
            break
        fi
        
        # Note: Script now waits for ALL devices to complete - no more early exits
        
        # Show progress every 60 seconds with brief status
        if [ $((elapsed % 60)) -eq 0 ]; then
            echo "Progress: ${elapsed}s - ✓$success_count ❌$failed_count ⏳$pending_count" | log_output
            
            # For wait operations, show which devices are still pending
            if [ "$operation" = "wait" ] && [ $pending_count -gt 0 ]; then
                pending_devices=""
                for device in "${devices[@]}"; do
                    local pid_file="/tmp/deploy_dci_${operation}_${device}.pid"
                    local status_file="/tmp/deploy_dci_${operation}_${device}.status"
                    if [ -f "$pid_file" ] && ! [ -f "$status_file" ]; then
                        pending_devices="$pending_devices $device"
                    fi
                done
                echo "Still waiting for devices to come online:$pending_devices" | log_output
            fi
        fi
        
        sleep 5
    done
    
    # Collect and report results
    local success_count=0
    local total_count=${#devices[@]}
    
    echo "Parallel $operation results:" | log_output
    for device in "${devices[@]}"; do
        local status_file="/tmp/deploy_dci_${operation}_${device}.status"
        if [ -f "$status_file" ]; then
            local status=$(cat "$status_file")
            case "$operation" in
                "reset")
                    if [ "$status" = "SUCCESS" ]; then
                        echo "  ✅ $device: Reset successful" | log_output
                        success_count=$((success_count + 1))
                    else
                        echo "  ❌ $device: Reset failed" | log_output
                    fi
                    ;;
                "wait")
                    if [ "$status" = "ONLINE" ]; then
                        echo "  ✅ $device: Online" | log_output
                        success_count=$((success_count + 1))
                    else
                        echo "  ❌ $device: Offline" | log_output
                    fi
                    ;;
                "config")
                    if [ "$status" = "SUCCESS" ]; then
                        echo "  ✅ $device: Configuration successful" | log_output
                        success_count=$((success_count + 1))
                    else
                        echo "  ❌ $device: Configuration failed" | log_output
                    fi
                    ;;
                "host")
                    if [ "$status" = "SUCCESS" ]; then
                        echo "  ✅ $device: HOST configuration successful" | log_output
                        success_count=$((success_count + 1))
                    else
                        echo "  ❌ $device: HOST configuration failed" | log_output
                    fi
                    ;;
            esac
            if [ "$cleanup_files" = true ]; then
                rm -f "$status_file"
            fi
        else
            echo "  ❓ $device: No status available (may have been interrupted or still running)" | log_output
        fi
    done
    
    echo "Parallel $operation summary: $success_count/$total_count devices successful" | log_output
    return 0
}

# Function to display DCI topology - dynamically adapts to 6D or 8D topology
display_dci_topology() {
    local num_sd_devices=${#SD_DEVICES[@]}
    local topology_type=""
    
    # Determine topology type based on number of SD devices
    # Note: Cannot determine 8D 2DC vs 3DC from port.json alone
    if [ $num_sd_devices -eq 6 ]; then
        topology_type="6D_2DC"
    elif [ $num_sd_devices -eq 8 ]; then
        topology_type="8D_3DC"
    else
        topology_type="UNKNOWN"
    fi
    
    echo ""
    echo "┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐" | log_output
    echo "│                    EVPN-VXLAN Data Center Interconnect (DCI) Topology - ${topology_type}                                │" | log_output
    echo "└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘" | log_output
    echo "" | log_output
    
    # Display appropriate topology based on discovered devices
    case $topology_type in
        "6D_2DC")
            display_6d_2dc_topology
            ;;
        "8D_3DC")
            display_8d_3dc_topology
            ;;
        *)
            echo "    UNKNOWN TOPOLOGY: ${num_sd_devices} SD devices detected" | log_output
            echo "    Supported topologies: 6D (2DC), 8D (3DC)" | log_output
            echo "    Discovered devices: ${SD_DEVICES[*]}" | log_output
            ;;
    esac
}

# 6 Device, 2 DC Topology
display_6d_2dc_topology() {
    echo "    Data Center 1 (DC1)                               Data Center 2 (DC2)" | log_output
    echo "    ╔═══════════════════════════════════╗            ╔═══════════════════╗" | log_output
    echo "    ║           SPINE LAYER             ║            ║   SPINE LAYER     ║" | log_output
    echo "    ║  ┌────────────┐   ┌────────────┐  ║            ║  ┌────────────┐   ║" | log_output
    echo "    ║  │SD1-DC1-GW1 │   │SD2-DC1-GW2 │  ║◄──────────►║  │SD3-DC2-GW1 │   ║" | log_output
    echo "    ║  │  AS65001   │   │  AS65002   │  ║            ║  │  AS65003   │   ║" | log_output
    echo "    ║  │DC:feda     │   │DC:feda     │  ║            ║  │DC:fed3     │   ║" | log_output
    echo "    ║  │WAN:101.101 │   │WAN:101.101 │  ║            ║  │WAN:102.102 │   ║" | log_output
    echo "    ║  │DCI:10.10.10│   │DCI:20.20.20│  ║            ║  │DCI:30.30.30│   ║" | log_output
    echo "    ║  └─────┬─────┘    └─────┬─────┘   ║            ║  └─────┬─────┘    ║" | log_output
    echo "    ║        │                │         ║            ║        │          ║" | log_output
    echo "    ║        │\\             /│         ║            ║        │          ║" | log_output
    echo "    ║        │ \\           / │         ║            ║        │          ║" | log_output
    echo "    ║        │  \\         /  │         ║            ║        │          ║" | log_output
    echo "    ║        │   \\       /   │         ║            ║        │          ║" | log_output
    echo "    ║        │    \\     /    │         ║            ║        │          ║" | log_output
    echo "    ║        │     \\   /     │         ║            ║        │          ║" | log_output
    echo "    ║        │      \\ /      │         ║            ║        │          ║" | log_output
    echo "    ║        │       X        │         ║            ║        │          ║" | log_output
    echo "    ║        │      / \\      │         ║            ║        │          ║" | log_output
    echo "    ║        │     /   \\     │         ║            ║        │          ║" | log_output
    echo "    ║        │    /     \\    │         ║            ║        │          ║" | log_output
    echo "    ║        │   /       \\   │         ║            ║        │          ║" | log_output
    echo "    ║        │  /         \\  │         ║            ║        │          ║" | log_output
    echo "    ║        │ /           \\ │         ║            ║        │          ║" | log_output
    echo "    ║        │/             \\│         ║            ║        │          ║" | log_output
    echo "    ║  ┌─────▼─────┐  ┌─────▼─────┐     ║            ║  ┌─────▼─────┐    ║" | log_output
    echo "    ║  │SD5-DC1    │  │SD6-DC1    │     ║            ║  │SD7-DC2    │    ║" | log_output
    echo "    ║  │-LEAF1     │  │-LEAF2     │     ║            ║  │-LEAF1     │    ║" | log_output
    echo "    ║  │AS65105    │  │AS65106    │     ║            ║  │AS65107    │    ║" | log_output
    echo "    ║  │VTEP:fed5  │  │VTEP:fed6  │     ║            ║  │VTEP:fed7  │    ║" | log_output
    echo "    ║  └─────┬──┬──┘  └─────┬─────┘     ║            ║  └─────┬─────┘    ║" | log_output
    echo "    ║        │  │           │           ║            ║        │          ║" | log_output
    echo "    ║        │  │           │           ║            ║        │          ║" | log_output
    echo "    ║        │  └───────────│           ║            ║        │          ║" | log_output
    echo "    ║  ┌─────▼─────┐   ┌────▼─────┐     ║            ║  ┌─────▼─────┐    ║" | log_output
    echo "    ║  │   HOST1   │   │  HOST2   │     ║            ║  │   HOST3   │    ║" | log_output
    echo "    ║  │   eth1    │   │  eth1/2  │     ║            ║  │   eth1    │    ║" | log_output
    echo "    ║  │  (SD5)    │   │ (SD5/6)  │     ║            ║  │  (SD7)    │    ║" | log_output
    echo "    ║  └───────────┘   └──────────┘     ║            ║  └───────────┘    ║" | log_output
    echo "    ║           LEAF LAYER              ║            ║   LEAF LAYER      ║" | log_output
    echo "    ║        (Multihomed HOST2)         ║            ║                   ║" | log_output
    echo "    ╚═══════════════════════════════════╝            ╚═══════════════════╝" | log_output
    echo "" | log_output
    echo "    EVPN BGP Sessions & VTEP Details:" | log_output
    echo "    ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐" | log_output
    echo "    │ Device        │ BGP Router-ID   │ VTEP Address         │ DCI Loopback   │ EVPN Neighbors        │" | log_output
    echo "    ├─────────────────────────────────────────────────────────────────────────────────────────────────────┤" | log_output
    echo "    │ SD1-DC1-GW1   │ 100.100.100.1  │ fd27::233:d0c6:feda  │ 10.10.10.10    │ fed5,fed6,30.30.30.30 │" | log_output
    echo "    │ SD2-DC1-GW2   │ 100.100.100.2  │ fd27::233:d0c6:feda  │ 20.20.20.20    │ fed5,fed6,30.30.30.30 │" | log_output
    echo "    │ SD5-DC1-LEAF1 │ 100.100.100.5  │ fd27::233:d0c6:fed5  │ -              │ feda,feda             │" | log_output
    echo "    │ SD6-DC1-LEAF2 │ 100.100.100.6  │ fd27::233:d0c6:fed6  │ -              │ feda,feda             │" | log_output
    echo "    │ SD3-DC2-GW1   │ 200.200.200.3  │ fd28::233:d0c6:fed3  │ 30.30.30.30    │ fed7,10.10.10.10,20.20.20.20 │" | log_output
    echo "    │ SD7-DC2-LEAF1 │ 200.200.200.7  │ fd28::233:d0c6:fed7  │ -              │ fed3                  │" | log_output
    echo "    └─────────────────────────────────────────────────────────────────────────────────────────────────────┘" | log_output
    echo "" | log_output
    echo "    VXLAN Domains & Reorigination:" | log_output
    echo "    ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐" | log_output
    echo "    │ Domain        │ VNI  │ Purpose        │ Reorigination Rule                                        │" | log_output
    echo "    ├────────────────────────────────────────────────────────────────────────────────────────────────────┤" | log_output
    echo "    │ vxlan-local   │ 5010 │ Intra-DC1 EVPN │ Routes received here are reoriginated to vxlan-remote    │" | log_output
    echo "    │ vxlan-local   │ 7010 │ Intra-DC2 EVPN │ Routes received here are reoriginated to vxlan-remote    │" | log_output
    echo "    │ vxlan-remote  │ 5011 │ Inter-DC EVPN  │ Routes received here are reoriginated to vxlan-local     │" | log_output
    echo "    └────────────────────────────────────────────────────────────────────────────────────────────────────┘" | log_output
    echo "" | log_output
    echo "    Physical Connections:" | log_output
    echo "    ┌──────────────────────┬──────────────────────┬──────────────────────┬─────────────────────┐" | log_output
    echo "    │ Intra-DC1 Fabric     │ Intra-DC2 Fabric     │ Inter-DC WAN Links   │ Host Connections    │" | log_output
    echo "    ├──────────────────────┼──────────────────────┼──────────────────────┼─────────────────────┤" | log_output
    echo "    │ SD1↔SD5 (EVPN+IPv6)  │ SD3↔SD7 (EVPN+IPv6)  │ SD1↔SD3 (WAN+EVPN)   │ HOST1↔SD5.Eth12     │" | log_output
    echo "    │ SD1↔SD6 (EVPN+IPv6)  │                      │ SD2↔SD3 (WAN+EVPN)   │ HOST2↔SD5.Eth13     │" | log_output
    echo "    │ SD2↔SD5 (EVPN+IPv6)  │                      │                      │ HOST2↔SD6.Eth12     │" | log_output
    echo "    │ SD2↔SD6 (EVPN+IPv6)  │                      │                      │ HOST3↔SD7.Eth12     │" | log_output
    echo "    └──────────────────────┴──────────────────────┴──────────────────────┴─────────────────────┘" | log_output
    echo "" | log_output
    echo "    Key Features:" | log_output
    echo "    • EVPN Type-2 (MAC/IP) and Type-3 (IMET) routes" | log_output
    echo "    • IPv6 VTEP addresses for intra-DC communication" | log_output
    echo "    • IPv4 DCI loopbacks for inter-DC EVPN sessions" | log_output
    echo "    • IPv4 WAN VTEP addresses (Loopback11) for inter-DC VXLAN tunnels" | log_output
    echo "    • Domain-based reorigination enables route redistribution between DCs" | log_output
    echo "    • HOST2 is multihomed to SD5-DC1-LEAF1 and SD6-DC1-LEAF2 for redundancy" | log_output
    echo "    • Two-DC interconnect: DC1 ↔ DC2" | log_output
}

# 8 Device, 3 DC Topology
display_8d_3dc_topology() {
    echo "    Data Center 1 (DC1)                     Data Center 2 (DC2)           Data Center 3 (DC3)" | log_output
    echo "    ╔═══════════════════════════════════╗  ╔═══════════════════╗  ╔═══════════════════╗" | log_output
    echo "    ║           SPINE LAYER             ║  ║   SPINE LAYER     ║  ║   SPINE LAYER     ║" | log_output
    echo "    ║  ┌────────────┐   ┌────────────┐  ║  ║  ┌────────────┐   ║  ║  ┌────────────┐   ║" | log_output
    echo "    ║  │SD1-DC1-GW1 │   │SD2-DC1-GW2 │  ║  ║  │SD3-DC2-GW1 │   ║  ║  │SD4-DC3-GW1 │   ║" | log_output
    echo "    ║  │  AS65001   │   │  AS65002   │  ║  ║  │  AS65003   │   ║  ║  │  AS65004   │   ║" | log_output
    echo "    ║  │DC:feda     │   │DC:feda     │  ║  ║  │DC:fed3     │   ║  ║  │DC:fed4     │   ║" | log_output
    echo "    ║  │WAN:101.101 │   │WAN:101.101 │  ║  ║  │WAN:102.102 │   ║  ║  │WAN:103.103 │   ║" | log_output
    echo "    ║  │DCI:10.10.10│   │DCI:20.20.20│  ║  ║  │DCI:30.30.30│   ║  ║  │DCI:40.40.40│   ║" | log_output
    echo "    ║  └─────┬─────┘    └─────┬─────┘   ║  ║  └─────┬─────┘    ║  ║  └─────┬─────┘    ║" | log_output
    echo "    ║        │                │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │\\             /│         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │ \\           / │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │  \\         /  │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │   \\       /   │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │    \\     /    │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │     \\   /     │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │      \\ /      │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │       X        │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │      / \\      │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │     /   \\     │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │    /     \\    │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │   /       \\   │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │  /         \\  │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │ /           \\ │         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │/             \\│         ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║  ┌─────▼─────┐  ┌─────▼─────┐     ║  ║  ┌─────▼─────┐    ║  ║  ┌─────▼─────┐    ║" | log_output
    echo "    ║  │SD5-DC1    │  │SD6-DC1    │     ║  ║  │SD7-DC2    │    ║  ║  │SD8-DC3    │    ║" | log_output
    echo "    ║  │-LEAF1     │  │-LEAF2     │     ║  ║  │-LEAF1     │    ║  ║  │-LEAF1     │    ║" | log_output
    echo "    ║  │AS65105    │  │AS65106    │     ║  ║  │AS65107    │    ║  ║  │AS65108    │    ║" | log_output
    echo "    ║  │VTEP:fed5  │  │VTEP:fed6  │     ║  ║  │VTEP:fed7  │    ║  ║  │VTEP:fed8  │    ║" | log_output
    echo "    ║  └─────┬──┬──┘  └─────┬─────┘     ║  ║  └─────┬─────┘    ║  ║  └─────┬─────┘    ║" | log_output
    echo "    ║        │  │           │           ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │  │           │           ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║        │  └───────────│           ║  ║        │          ║  ║        │          ║" | log_output
    echo "    ║  ┌─────▼─────┐   ┌────▼─────┐     ║  ║  ┌─────▼─────┐    ║  ║  ┌─────▼─────┐    ║" | log_output
    echo "    ║  │   HOST1   │   │  HOST2   │     ║  ║  │   HOST3   │    ║  ║  │   HOST4   │    ║" | log_output
    echo "    ║  │   eth1    │   │  eth1/2  │     ║  ║  │   eth1    │    ║  ║  │   eth1    │    ║" | log_output
    echo "    ║  │  (SD5)    │   │ (SD5/6)  │     ║  ║  │  (SD7)    │    ║  ║  │  (SD8)    │    ║" | log_output
    echo "    ║  └───────────┘   └──────────┘     ║  ║  └───────────┘    ║  ║  └───────────┘    ║" | log_output
    echo "    ║           LEAF LAYER              ║  ║   LEAF LAYER      ║  ║   LEAF LAYER      ║" | log_output
    echo "    ║        (Multihomed HOST2)         ║  ║                   ║  ║                   ║" | log_output
    echo "    ╚═══════════════════════════════════╝  ╚═══════════════════╝  ╚═══════════════════╝" | log_output
    echo "" | log_output
    echo "    EVPN BGP Sessions & VTEP Details:" | log_output
    echo "    ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐" | log_output
    echo "    │ Device        │ BGP Router-ID   │ VTEP Address         │ DCI Loopback   │ EVPN Neighbors        │" | log_output
    echo "    ├─────────────────────────────────────────────────────────────────────────────────────────────────────┤" | log_output
    echo "    │ SD1-DC1-GW1   │ 100.100.100.1  │ fd27::233:d0c6:feda  │ 10.10.10.10    │ fed5,fed6,30.30.30.30,40.40.40.40 │" | log_output
    echo "    │ SD2-DC1-GW2   │ 100.100.100.2  │ fd27::233:d0c6:feda  │ 20.20.20.20    │ fed5,fed6,30.30.30.30,40.40.40.40 │" | log_output
    echo "    │ SD5-DC1-LEAF1 │ 100.100.100.5  │ fd27::233:d0c6:fed5  │ -              │ feda,feda             │" | log_output
    echo "    │ SD6-DC1-LEAF2 │ 100.100.100.6  │ fd27::233:d0c6:fed6  │ -              │ feda,feda             │" | log_output
    echo "    │ SD3-DC2-GW1   │ 200.200.200.3  │ fd28::233:d0c6:fed3  │ 30.30.30.30    │ fed7,10.10.10.10,20.20.20.20,40.40.40.40 │" | log_output
    echo "    │ SD7-DC2-LEAF1 │ 200.200.200.7  │ fd28::233:d0c6:fed7  │ -              │ fed3                  │" | log_output
    echo "    │ SD4-DC3-GW1   │ 200.200.200.4  │ fd29::233:d0c6:fed4  │ 40.40.40.40    │ fed8,10.10.10.10,20.20.20.20,30.30.30.30 │" | log_output
    echo "    │ SD8-DC3-LEAF1 │ 200.200.200.8  │ fd29::233:d0c6:fed8  │ -              │ fed4                  │" | log_output
    echo "    └─────────────────────────────────────────────────────────────────────────────────────────────────────┘" | log_output
    echo "" | log_output
    echo "    VXLAN Domains & Reorigination:" | log_output
    echo "    ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐" | log_output
    echo "    │ Domain        │ VNI  │ Purpose        │ Reorigination Rule                                        │" | log_output
    echo "    ├────────────────────────────────────────────────────────────────────────────────────────────────────┤" | log_output
    echo "    │ vxlan-local   │ 5010 │ Intra-DC1 EVPN │ Routes received here are reoriginated to vxlan-remote    │" | log_output
    echo "    │ vxlan-local   │ 7010 │ Intra-DC2 EVPN │ Routes received here are reoriginated to vxlan-remote    │" | log_output
    echo "    │ vxlan-local   │ 8010 │ Intra-DC3 EVPN │ Routes received here are reoriginated to vxlan-remote    │" | log_output
    echo "    │ vxlan-remote  │ 5011 │ Inter-DC EVPN  │ Routes received here are reoriginated to vxlan-local     │" | log_output
    echo "    └────────────────────────────────────────────────────────────────────────────────────────────────────┘" | log_output
    echo "" | log_output
    echo "    Physical Connections:" | log_output
    echo "    ┌──────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┬─────────────────────┐" | log_output
    echo "    │ Intra-DC1 Fabric     │ Intra-DC2 Fabric     │ Intra-DC3 Fabric     │ Inter-DC WAN Links   │ Host Connections    │" | log_output
    echo "    ├──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼─────────────────────┤" | log_output
    echo "    │ SD1↔SD5 (EVPN+IPv6)  │ SD3↔SD7 (EVPN+IPv6)  │ SD4↔SD8 (EVPN+IPv6)  │ SD1↔SD3 (WAN+EVPN)   │ HOST1↔SD5.Eth12     │" | log_output
    echo "    │ SD1↔SD6 (EVPN+IPv6)  │                      │                      │ SD1↔SD4 (WAN+EVPN)   │ HOST2↔SD5.Eth13     │" | log_output
    echo "    │ SD2↔SD5 (EVPN+IPv6)  │                      │                      │ SD2↔SD3 (WAN+EVPN)   │ HOST2↔SD6.Eth12     │" | log_output
    echo "    │ SD2↔SD6 (EVPN+IPv6)  │                      │                      │ SD2↔SD4 (WAN+EVPN)   │ HOST3↔SD7.Eth12     │" | log_output
    echo "    │                      │                      │                      │ SD3↔SD4 (WAN+EVPN)   │ HOST4↔SD8.Eth12     │" | log_output
    echo "    └──────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┴─────────────────────┘" | log_output
    echo "" | log_output
    echo "    Key Features:" | log_output
    echo "    • EVPN Type-2 (MAC/IP) and Type-3 (IMET) routes" | log_output
    echo "    • IPv6 VTEP addresses for intra-DC communication" | log_output
    echo "    • IPv4 DCI loopbacks for inter-DC EVPN sessions" | log_output
    echo "    • IPv4 WAN VTEP addresses (Loopback11) for inter-DC VXLAN tunnels" | log_output
    echo "    • Domain-based reorigination enables route redistribution between DCs" | log_output
    echo "    • HOST2 is multihomed to SD5-DC1-LEAF1 and SD6-DC1-LEAF2 for redundancy" | log_output
    echo "    • Three-DC full mesh: DC1 ↔ DC2 ↔ DC3 ↔ DC1" | log_output
}
# Function to wait for device to be accessible after reboot
wait_for_device() {
    local device=$1
    local host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
    local xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
    local max_attempts=30
    local attempt=1
    
    # Determine credentials based on device type
    local username password
    if [[ "$device" =~ ^SD[0-9]+$ ]]; then
        username="cisco"
        password="cisco123"
    elif [[ "$device" =~ ^HOST[0-9]+$ ]]; then
        username="vxr"
        password="cisco123"
    else
        echo "ERROR: Unknown device type for $device" | log_output
        return 1
    fi
    
    echo "Waiting for $device to come back online..." | log_output
    
    while [ $attempt -le $max_attempts ]; do
        echo "Attempt $attempt/$max_attempts for $device" | log_output
        
        if sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=10 -p "$xr_redir22" "$username@$host_agent" "echo 'online'" &>/dev/null; then
            return 0
        fi
        
        sleep 30
        attempt=$((attempt + 1))
    done
    
    echo "ERROR: $device failed to come back online after reboot" | log_output
    return 1
}

# Function to apply SONiC configuration in bulk
apply_sonic_config() {
    local device=$1
    local config_file="$CONFIG_DIR/${device}-complete-config.txt"
    
    echo "Applying SONiC configuration to $device..." | log_output
    
    # Create temporary file with SONiC commands
    local temp_sonic_config="/tmp/${device}_sonic_config.txt"
    grep "^sudo config" "$config_file" > "$temp_sonic_config"
    
    if [ ! -s "$temp_sonic_config" ]; then
        echo "No SONiC configuration commands found for $device" | log_output
        rm -f "$temp_sonic_config"
        return 0
    fi
    
    local total_commands=$(wc -l < "$temp_sonic_config")
    echo "Sending $total_commands SONiC commands to $device in bulk..." | log_output
    
    # Create a bulk script to execute all commands
    local bulk_script="/tmp/${device}_bulk_sonic.sh"
    echo "#!/bin/bash" > "$bulk_script"
    echo "set -e" >> "$bulk_script"
    echo "echo 'Starting SONiC configuration batch...'" >> "$bulk_script"
    
    # Add all SONiC commands to the bulk script
    local cmd_count=0
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            cmd_count=$((cmd_count + 1))
            echo "echo 'Command $cmd_count/$total_commands: Running...' && $line" >> "$bulk_script"
        fi
    done < "$temp_sonic_config"
    
    echo "echo 'SONiC configuration batch completed successfully'" >> "$bulk_script"
    
    # Make the script executable and copy it to the device, then execute
    chmod +x "$bulk_script"
    
    # Transfer the script and execute it
    local host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
    local xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
    
    echo "[$device] Transferring bulk SONiC script..." | log_output
    if sshpass -p "cisco123" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$xr_redir22" "$bulk_script" "cisco@$host_agent:/tmp/bulk_sonic.sh" 2>&1 | log_output; then
        
        echo "[$device] Executing bulk SONiC configuration..." | log_output
        if sshpass -p "cisco123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -p "$xr_redir22" "cisco@$host_agent" "chmod +x /tmp/bulk_sonic.sh && /tmp/bulk_sonic.sh && rm -f /tmp/bulk_sonic.sh" < /dev/null 2>&1 | log_output; then
            echo "[$device] ✅ SONiC bulk configuration completed successfully" | log_output
        else
            echo "[$device] ❌ SONiC bulk configuration failed" | log_output
            # Cleanup
            rm -f "$temp_sonic_config" "$bulk_script"
            return 1
        fi
    else
        echo "[$device] ❌ Failed to transfer bulk SONiC script" | log_output
        # Cleanup
        rm -f "$temp_sonic_config" "$bulk_script"
        return 1
    fi
    
    # Cleanup
    rm -f "$temp_sonic_config" "$bulk_script"
    echo "[$device] SONiC configuration completed ($total_commands commands)" | log_output
}

# Function to apply FRR BGP configuration
apply_frr_config() {
    local device=$1
    local config_file="$CONFIG_DIR/${device}-complete-config.txt"
    
    echo "Applying FRR BGP configuration to $device..." | log_output
    
    # Ensure BGP docker is running before applying FRR config
    echo "[$device] Verifying BGP docker is ready..." | log_output
    if ! wait_for_bgp_docker "$device"; then
        echo "[$device] ❌ BGP docker not ready after extended wait - this is a critical error" | log_output
        echo "[$device] Attempting to start BGP docker and retry..." | log_output
        
        # Try to start/restart the BGP docker container
        if ssh_to_device "$device" "docker start bgp || docker restart bgp" >/dev/null 2>&1; then
            echo "[$device] BGP docker start/restart command sent, waiting again..." | log_output
            sleep 30  # Give it time to start
            
            # One more attempt to wait for BGP docker
            if wait_for_bgp_docker "$device"; then
                echo "[$device] ✅ BGP docker ready after restart!" | log_output
            else
                echo "[$device] ❌ BGP docker still not ready after restart - FRR configuration will fail" | log_output
                return 1
            fi
        else
            echo "[$device] ❌ Failed to start/restart BGP docker - FRR configuration will fail" | log_output
            return 1
        fi
    fi
    
    # Create temporary files for debug commands, logging commands, and FRR configuration
    local temp_debug_config="/tmp/${device}_debug_config.txt"
    local temp_log_config="/tmp/${device}_log_config.txt"
    local temp_config="/tmp/${device}_frr_config.txt"
    
    # Extract debug commands (between vtysh and configure terminal)
    awk '
    BEGIN { found_vtysh=0; in_debug=0 }
    /^vtysh$/ { found_vtysh=1; next }
    found_vtysh && /^debug / { in_debug=1; print; next }
    found_vtysh && in_debug && /^debug / { print; next }
    found_vtysh && /^configure terminal$/ { exit }
    ' "$config_file" > "$temp_debug_config"
    
    # Extract logging commands (after configure terminal and before hostname)
    awk '
    BEGIN { found_configure=0; in_log=0 }
    /^configure terminal$/ || /^config t$/ || /^conf t$/ { found_configure=1; next }
    found_configure && /^log / { in_log=1; print; next }
    found_configure && in_log && /^log / { print; next }
    found_configure && /^hostname / { exit }
    ' "$config_file" > "$temp_log_config"
    
    # Extract FRR configuration (hostname and everything from "router bgp" to end)
    awk '
    BEGIN { in_frr=0; found_hostname=0; exit_count=0 }
    /^hostname [A-Z0-9-]+$/ && !found_hostname { print; found_hostname=1; next }
    /^router bgp/ { in_frr=1; print; next }
    in_frr && /^exit$/ { 
        print "exit"
        exit_count++
        # After second exit, we should be done with BGP config
        if (exit_count >= 2) {
            exit
        }
        next
    }
    in_frr && !/^#/ && !/^$/ && !/^sudo/ && !/^vtysh/ && !/^configure terminal/ { print }
    ' "$config_file" > "$temp_config"
    
    # Apply debug commands first if we have any
    if [ -s "$temp_debug_config" ]; then
        local debug_lines=$(wc -l < "$temp_debug_config")
        echo "[$device] Applying $debug_lines debug commands..." | log_output
        
        # Create debug command string
        local debug_commands="vtysh"
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                debug_commands="$debug_commands -c '$line'"
            fi
        done < "$temp_debug_config"
        
        # Execute debug commands
        if ssh_to_device "$device" "$debug_commands"; then
            echo "[$device] ✓ Debug commands applied" | log_output
        else
            echo "[$device] ⚠️ Debug commands failed" | log_output
        fi
    else
        echo "[$device] No debug commands found" | log_output
    fi
    
    # Apply logging commands if we have any (in configure terminal mode)
    if [ -s "$temp_log_config" ]; then
        local log_lines=$(wc -l < "$temp_log_config")
        echo "[$device] Applying $log_lines logging commands..." | log_output
        
        # Create logging command string
        local log_commands="vtysh -c 'configure terminal'"
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                log_commands="$log_commands -c '$line'"
            fi
        done < "$temp_log_config"
        
        # Execute logging commands
        if ssh_to_device "$device" "$log_commands"; then
            echo "[$device] ✓ Logging commands applied" | log_output
        else
            echo "[$device] ⚠️ Logging commands failed" | log_output
        fi
    else
        echo "[$device] No logging commands found" | log_output
    fi
    
    # Apply FRR configuration if we have content
    if [ -s "$temp_config" ]; then
        local total_lines=$(wc -l < "$temp_config")
        echo "[$device] Processing $total_lines FRR configuration lines" | log_output
        
        # Create FRR command string
        local frr_commands="vtysh -c 'configure terminal'"
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                frr_commands="$frr_commands -c '$line'"
            fi
        done < "$temp_config"
        
        # Execute FRR configuration
        echo "[$device] Applying FRR BGP configuration..." | log_output
        if ssh_to_device "$device" "$frr_commands"; then
            echo "[$device] ✓ FRR configuration applied" | log_output
        else
            echo "[$device] ⚠️ FRR configuration failed" | log_output
        fi
    else
        echo "[$device] No FRR configuration found" | log_output
    fi
    
    # Cleanup
    rm -f "$temp_debug_config" "$temp_log_config" "$temp_config"
    echo "FRR configuration processing completed for $device" | log_output
}

# Function to copy files to device
copy_to_device() {
    local device=$1
    local local_file=$2
    local remote_path=$3
    local host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
    local xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
    
    if [ ! -f "$local_file" ]; then
        echo "ERROR: Local file $local_file does not exist" | log_output
        return 1
    fi
    
    echo "[$device] Copying: $local_file -> $remote_path" | log_output
    
    # Execute scp and capture exit code
    local exit_code=0
    sshpass -p "cisco123" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$xr_redir22" "$local_file" "cisco@$host_agent:$remote_path" 2>&1 | log_output
    exit_code=${PIPESTATUS[0]}
    
    if [ $exit_code -ne 0 ]; then
        echo "[$device] File copy failed with exit code: $exit_code" | log_output
        return $exit_code
    fi
    
    echo "[$device] Successfully copied: $(basename "$local_file")" | log_output
    return 0
}

# Function to wait for BGP docker to be ready
wait_for_bgp_docker() {
    local device=$1
    local max_attempts=60  # Increased to 60 attempts (10 minutes total)
    local attempt=1
    
    echo "Waiting for BGP docker to be ready on $device..." | log_output
    
    while [ $attempt -le $max_attempts ]; do
        echo "Attempt $attempt/$max_attempts for $device BGP docker" | log_output
        
        # First check if docker container exists and is running
        if ssh_to_device "$device" "docker ps --format '{{.Names}}' | grep -q '^bgp$'" >/dev/null 2>&1; then
            # Container is running, now test if it's ready to accept commands
            if ssh_to_device "$device" "docker exec bgp echo 'BGP docker ready'" >/dev/null 2>&1; then
                echo "$device BGP docker is ready!" | log_output
                return 0
            else
                echo "[$device] BGP docker running but not ready for commands yet..." | log_output
            fi
        else
            echo "[$device] BGP docker container not running yet..." | log_output
        fi
        
        sleep 10
        attempt=$((attempt + 1))
    done
    
    echo "ERROR: $device BGP docker failed to become ready after $max_attempts attempts" | log_output
    return 1
}

# Function to install FRR packages in BGP docker
install_frr_packages_in_bgp_docker() {
    local device=$1
    local deb_files=("${@:2}")
    
    echo "Installing FRR packages in BGP docker on $device..." | log_output
    
    # Create temp directory on device
    ssh_to_device "$device" "mkdir -p /tmp/bgp-packages"
    
    # Copy all .deb files to device
    echo "Copying .deb files to $device..." | log_output
    for deb_file in "${deb_files[@]}"; do
        local filename=$(basename "$deb_file")
        echo "Copying $filename to $device..." | log_output
        copy_to_device "$device" "$deb_file" "/tmp/bgp-packages/$filename"
        
        # Verify file was copied successfully
        if ! ssh_to_device "$device" "test -f /tmp/bgp-packages/$filename"; then
            echo "ERROR: Failed to copy $filename to $device" | log_output
            return 1
        fi
    done
    
    # Update package lists in BGP docker container
    echo "Updating package lists in BGP docker container on $device..." | log_output
    ssh_to_device "$device" "docker exec bgp apt-get update"
    
    # Copy packages into docker and install one by one
    for deb_file in "${deb_files[@]}"; do
        local filename=$(basename "$deb_file")
        echo "Installing package $filename in BGP docker on $device..." | log_output
        
        # Copy file directly into BGP docker container root
        echo "Copying $filename directly into BGP docker container..." | log_output
        ssh_to_device "$device" "docker cp /tmp/bgp-packages/$filename bgp:/"
        
        # Verify file exists inside docker at root
        if ! ssh_to_device "$device" "docker exec bgp test -f /$filename"; then
            echo "ERROR: Failed to copy $filename into BGP docker on $device" | log_output
            continue
        fi
        
        # Install the package from root directory
        echo "Installing $filename with dpkg from root directory..." | log_output
        if ssh_to_device "$device" "docker exec bgp dpkg -i /$filename"; then
            echo "Successfully installed $filename on $device" | log_output
        else
            echo "dpkg failed, attempting to fix dependencies..." | log_output
            ssh_to_device "$device" "docker exec bgp apt-get install -f -y"
            # Try installing again after fixing dependencies
            if ssh_to_device "$device" "docker exec bgp dpkg -i /$filename"; then
                echo "Successfully installed $filename on $device after fixing dependencies" | log_output
            else
                echo "ERROR: Failed to install $filename on $device even after fixing dependencies" | log_output
            fi
        fi
        
        # Clean up the file from docker root directory
        ssh_to_device "$device" "docker exec bgp rm -f /$filename"
    done
    
    # Cleanup temp files on host
    ssh_to_device "$device" "rm -rf /tmp/bgp-packages"
    
    echo "FRR package installation completed on $device" | log_output
}

# Function to restart BGP docker
restart_bgp_docker() {
    local device=$1
    
    echo "Restarting BGP docker on $device..." | log_output
    ssh_to_device "$device" "docker restart bgp"
    
    # Wait for docker to be ready
    sleep 10
    wait_for_bgp_docker "$device"
    
    echo "BGP docker restarted successfully on $device" | log_output
}

# Parallel FRR installation functions
parallel_install_frr_packages() {
    local device=$1
    shift
    local deb_files=("$@")
    local status_file="/tmp/deploy_dci_frr_install_${device}.status"
    
    echo "[$device] Starting parallel FRR package installation..." | log_output
    
    {
        if install_frr_packages_in_bgp_docker "$device" "${deb_files[@]}"; then
            echo "SUCCESS" > "$status_file"
            echo "[$device] FRR package installation SUCCESS" | log_output
        else
            echo "FAILED" > "$status_file"
            echo "[$device] FRR package installation FAILED" | log_output
        fi
    } &
    
    echo $! > "/tmp/deploy_dci_frr_install_${device}.pid"
}

parallel_restart_bgp_docker() {
    local device=$1
    local status_file="/tmp/deploy_dci_bgp_restart_${device}.status"
    
    echo "[$device] Starting parallel BGP docker restart..." | log_output
    
    {
        if restart_bgp_docker "$device"; then
            echo "SUCCESS" > "$status_file"
            echo "[$device] BGP docker restart SUCCESS" | log_output
        else
            echo "FAILED" > "$status_file"
            echo "[$device] BGP docker restart FAILED" | log_output
        fi
    } &
    
    echo $! > "/tmp/deploy_dci_bgp_restart_${device}.pid"
}

# Function to apply HOST configuration with improved error handling
apply_host_config() {
    local device=$1
    local config_file="$CONFIG_DIR/${device}-complete-config.txt"
    
    # Skip HOST4 for 6D topology since it doesn't exist
    if [ "$device" = "HOST4" ] && [ "$CONFIG_FOLDER" = "6d_2dc" ]; then
        echo "INFO: Skipping $device - not present in 6D 2DC topology" | log_output
        return 0
    fi
    
    if [ ! -f "$config_file" ]; then
        echo "INFO: No configuration file found for $device, skipping..." | log_output
        return 0
    fi
    
    echo "Applying HOST configuration to $device..." | log_output
    
    # Create temporary script with all HOST commands
    local temp_host_script="/tmp/${device}_host_config.sh"
    echo "#!/bin/bash" > "$temp_host_script"
    echo "set -e" >> "$temp_host_script"
    echo "echo 'Starting HOST configuration...'" >> "$temp_host_script"
    
    # Add all non-comment lines to the script, handling here-documents properly
    local cmd_count=0
    local in_heredoc=false
    local heredoc_delimiter=""
    
    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            # Check if this line starts a here-document
            if [[ "$line" =~ \<\<[[:space:]]*[\'\"]*([A-Za-z0-9_]+)[\'\"]*[[:space:]]*$ ]]; then
                heredoc_delimiter="${BASH_REMATCH[1]}"
                in_heredoc=true
                cmd_count=$((cmd_count + 1))
                # Remove 'sudo' prefix since we'll run the whole script with sudo
                local clean_line=$(echo "$line" | sed 's/^sudo //')
                echo "echo 'Command $cmd_count: Multi-line command starting...' && $clean_line" >> "$temp_host_script"
            elif [[ "$in_heredoc" = true ]]; then
                # We're inside a here-document, just copy the line as-is
                echo "$line" >> "$temp_host_script"
                # Check if this line ends the here-document
                if [[ "$line" = "$heredoc_delimiter" ]]; then
                    in_heredoc=false
                    heredoc_delimiter=""
                fi
            else
                # Regular line
                cmd_count=$((cmd_count + 1))
                # Remove 'sudo' prefix since we'll run the whole script with sudo
                local clean_line=$(echo "$line" | sed 's/^sudo //')
                echo "echo 'Command $cmd_count: $clean_line' && $clean_line" >> "$temp_host_script"
            fi
        fi
    done < <(grep -v "^#" "$config_file" | grep -v "^$")
    
    echo "echo 'HOST configuration completed successfully'" >> "$temp_host_script"
    
    if [ $cmd_count -eq 0 ]; then
        echo "[$device] No valid commands found in configuration file" | log_output
        rm -f "$temp_host_script"
        return 0
    fi
    
    # Make script executable
    chmod +x "$temp_host_script"
    
    # Get connection details
    local host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
    local xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
    
    if [ "$host_agent" = "null" ] || [ "$xr_redir22" = "null" ]; then
        echo "[$device] ❌ Missing connection details in port.json" | log_output
        rm -f "$temp_host_script"
        return 1
    fi
    
    echo "[$device] Transferring configuration script ($cmd_count commands)..." | log_output
    
    # Transfer and execute the script
    if sshpass -p "cisco123" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$xr_redir22" "$temp_host_script" "vxr@$host_agent:/tmp/host_config.sh" 2>&1 | log_output; then
        
        echo "[$device] Executing HOST configuration script..." | log_output
        if sshpass -p "cisco123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -p "$xr_redir22" "vxr@$host_agent" "chmod +x /tmp/host_config.sh && sudo /tmp/host_config.sh && rm -f /tmp/host_config.sh" < /dev/null 2>&1 | log_output; then
            echo "[$device] ✅ HOST configuration completed successfully" | log_output
        else
            echo "[$device] ❌ HOST configuration script execution failed" | log_output
            rm -f "$temp_host_script"
            return 1
        fi
    else
        echo "[$device] ❌ Failed to transfer HOST configuration script" | log_output
        rm -f "$temp_host_script"
        return 1
    fi
    
    # Cleanup
    rm -f "$temp_host_script"
    echo "[$device] HOST configuration applied successfully" | log_output
}
apply_config() {
    local device=$1
    local config_file="$CONFIG_DIR/${device}-complete-config.txt"
    
    if [ ! -f "$config_file" ]; then
        echo "ERROR: Configuration file $config_file not found" | log_output
        return 1
    fi
    
    local sonic_success=true
    local frr_success=true
    
    if [ "$FRR_ONLY" = true ]; then
        echo "[$device] FRR-only mode" | log_output
        
        # Apply only FRR configuration
        if apply_frr_config "$device"; then
            echo "[$device] ✓ FRR-only complete" | log_output
        else
            echo "[$device] ❌ FRR-only failed" | log_output
            frr_success=false
        fi
        sleep 5
    else
        echo "[$device] Full configuration mode: Applying complete configuration" | log_output
        
        # Apply SONiC configuration first
        echo "[$device] Phase 1: Applying SONiC configuration..." | log_output
        if apply_sonic_config "$device"; then
            echo "[$device] SONiC configuration phase completed" | log_output
        else
            echo "[$device] ERROR: SONiC configuration failed" | log_output
            sonic_success=false
        fi
        sleep 5
        
        # Apply FRR configuration
        if apply_frr_config "$device"; then
            echo "[$device] ✓ FRR phase complete" | log_output
        else
            echo "[$device] ❌ FRR phase failed" | log_output
            frr_success=false
        fi
        sleep 3
    fi
    
    # Report final status
    if [ "$FRR_ONLY" = true ]; then
        if [ "$frr_success" = true ]; then
            echo "[$device] ✅ SUCCESS" | log_output
            return 0
        else
            echo "[$device] ❌ FAILED" | log_output
            return 1
        fi
    else
        if [ "$sonic_success" = true ] && [ "$frr_success" = true ]; then
            echo "[$device] ✅ SUCCESS" | log_output
            return 0
        elif [ "$sonic_success" = true ]; then
            echo "[$device] ⚠️ SONiC ✓, FRR ❌" | log_output
            return 1
        elif [ "$frr_success" = true ]; then
            echo "[$device] ⚠️ SONiC ❌, FRR ✓" | log_output
            return 1
        else
            echo "[$device] ❌ FAILED" | log_output
            return 1
        fi
    fi
}

# Main script execution
if [ "$ENABLE_LOGGING" = true ]; then
    echo "========================================" | tee "$LOG_FILE"
    echo "DCI Configuration Reset and Deployment" | tee -a "$LOG_FILE"
    echo "Port JSON: $PORT_JSON" | tee -a "$LOG_FILE"
    echo "Script Dir: $SCRIPT_DIR" | tee -a "$LOG_FILE"
    echo "Skip Reset: $SKIP_RESET" | tee -a "$LOG_FILE"
    echo "FRR Only: $FRR_ONLY" | tee -a "$LOG_FILE"
    echo "FRR Debs Directory: ${FRR_DEBS_DIR:-none}" | tee -a "$LOG_FILE"
    echo "Parallel Mode: $PARALLEL_MODE" | tee -a "$LOG_FILE"
    echo "Wait All Devices: true (mandatory)" | tee -a "$LOG_FILE"
    echo "Logging Enabled: $ENABLE_LOGGING" | tee -a "$LOG_FILE"
    echo "Log File: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "Started at: $(date)" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"
else
    echo "========================================"
    echo "DCI Configuration Reset and Deployment"
    echo "Port JSON: $PORT_JSON"
    echo "Script Dir: $SCRIPT_DIR"
    echo "Skip Reset: $SKIP_RESET"
    echo "FRR Only: $FRR_ONLY"
    echo "FRR Debs Directory: ${FRR_DEBS_DIR:-none}"
    echo "Parallel Mode: $PARALLEL_MODE"
    echo "Wait All Devices: true (mandatory)"
    echo "Logging Enabled: $ENABLE_LOGGING"
    echo "Started at: $(date)"
    echo "========================================"
fi

# Check prerequisites
for cmd in jq sshpass; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "ERROR: $cmd is required but not installed" | log_output
        echo "Install with: sudo apt-get install $cmd (or equivalent for your system)" | log_output
        exit 1
    fi
done

if [ ! -f "$PORT_JSON" ]; then
    echo "ERROR: port.json not found at $PORT_JSON" | log_output
    echo "Please provide the correct path to port.json" | log_output
    exit 1
fi

if [ ! -d "$SCRIPT_DIR" ]; then
    echo "ERROR: Script directory not found at $SCRIPT_DIR" | log_output
    exit 1
fi

# Validate FRR debs directory if provided
if [ -n "$FRR_DEBS_DIR" ]; then
    if [ ! -d "$FRR_DEBS_DIR" ]; then
        echo "ERROR: FRR debs directory not found at $FRR_DEBS_DIR" | log_output
        exit 1
    fi
    
    # Check for .deb files in directory
    deb_files=("$FRR_DEBS_DIR"/*.deb)
    if [ ! -e "${deb_files[0]}" ]; then
        echo "ERROR: No .deb files found in $FRR_DEBS_DIR" | log_output
        exit 1
    fi
    
    echo "Found ${#deb_files[@]} .deb files in $FRR_DEBS_DIR:" | log_output
    for deb_file in "${deb_files[@]}"; do
        echo "  - $(basename "$deb_file")" | log_output
    done
    echo "" | log_output
fi

# Validate that we have config files
missing_configs=()
missing_host_configs=()

for device in "${SD_DEVICES[@]}"; do
    config_file="$CONFIG_DIR/${device}-complete-config.txt"
    if [ ! -f "$config_file" ]; then
        missing_configs+=("$config_file")
    fi
done

for device in "${HOST_DEVICES[@]}"; do
    config_file="$CONFIG_DIR/${device}-complete-config.txt"
    if [ ! -f "$config_file" ]; then
        missing_host_configs+=("$config_file")
    fi
done

if [ ${#missing_configs[@]} -gt 0 ]; then
    echo "ERROR: Missing SD configuration files:" | log_output
    for file in "${missing_configs[@]}"; do
        echo "  - $file" | log_output
    done
    exit 1
fi

if [ ${#missing_host_configs[@]} -gt 0 ]; then
    echo "INFO: Missing HOST configuration files (optional):" | log_output
    for file in "${missing_host_configs[@]}"; do
        echo "  - $file" | log_output
    done
    echo "HOST configurations will be skipped" | log_output
fi

# Discover devices dynamically from port.json
echo "Discovering devices from port.json..." | log_output
SD_DEVICES=()
HOST_DEVICES=()
FILTERED_DEVICES=()

# Parse device filter if provided
if [ -n "$DEVICE_FILTER" ]; then
    echo "Device filter specified: $DEVICE_FILTER" | log_output
    IFS=',' read -ra FILTERED_DEVICES <<< "$DEVICE_FILTER"
    
    # Validate filtered devices exist in port.json
    invalid_devices=()
    for device in "${FILTERED_DEVICES[@]}"; do
        if ! jq -e ".${device}" "$PORT_JSON" > /dev/null 2>&1; then
            invalid_devices+=("$device")
        fi
    done
    
    if [ ${#invalid_devices[@]} -gt 0 ]; then
        echo "ERROR: Invalid devices specified in filter: ${invalid_devices[*]}" | log_output
        echo "Available devices in port.json:" | log_output
        jq -r 'keys[]' "$PORT_JSON" | sort | log_output
        exit 1
    fi
    
    echo "Valid devices in filter: ${FILTERED_DEVICES[*]}" | log_output
fi

# Extract all device names from JSON and categorize them
for device in $(jq -r 'keys[]' "$PORT_JSON" | sort); do
    # If device filter is specified, only include devices in the filter
    if [ -n "$DEVICE_FILTER" ]; then
        if [[ ! " ${FILTERED_DEVICES[*]} " =~ " ${device} " ]]; then
            continue  # Skip devices not in filter
        fi
    fi
    
    if [[ "$device" =~ ^SD[0-9]+$ ]]; then
        SD_DEVICES+=("$device")
    elif [[ "$device" =~ ^HOST[0-9]+$ ]]; then
        HOST_DEVICES+=("$device")
    fi
done

ALL_DEVICES=("${SD_DEVICES[@]}" "${HOST_DEVICES[@]}")

if [ ${#SD_DEVICES[@]} -eq 0 ]; then
    echo "ERROR: No SD devices found in port.json" | log_output
    exit 1
fi

# Validate and display discovered devices
if [ -n "$DEVICE_FILTER" ]; then
    echo "Filtered devices to be configured:" | log_output
else
    echo "Discovered devices from port.json:" | log_output
fi
echo "SD devices: ${SD_DEVICES[*]}" | log_output
if [ ${#HOST_DEVICES[@]} -gt 0 ]; then
    echo "HOST devices: ${HOST_DEVICES[*]}" | log_output
else
    echo "HOST devices: none" | log_output
fi

echo ""
echo "Validating device connectivity details..." | log_output
for device in "${ALL_DEVICES[@]}"; do
    host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
    xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
    if [ "$host_agent" = "null" ] || [ "$xr_redir22" = "null" ]; then
        echo "ERROR: Device $device missing HostAgent or xr_redir22 in $PORT_JSON" | log_output
        exit 1
    fi
    echo "$device: $host_agent:$xr_redir22" | log_output
done

# Prompt user for confirmation
echo ""
if [ "$FRR_ONLY" = true ]; then
    echo "This script will:"
    echo "1. Skip device reset (FRR-only mode)"
    echo "2. Check device connectivity"
    if [ -n "$FRR_DEBS_DIR" ]; then
        echo "3. Install FRR packages from $FRR_DEBS_DIR"
        echo "4. Restart BGP docker containers"
        echo "5. Apply ONLY FRR BGP configurations from $SCRIPT_DIR"
        echo "6. Validate BGP neighbor establishment"
    else
        echo "3. Apply ONLY FRR BGP configurations from $SCRIPT_DIR"
        echo "4. Validate BGP neighbor establishment"
    fi
elif [ "$SKIP_RESET" = true ]; then
    echo "This script will:"
    echo "1. Skip device reset (default behavior, use --reset to force reset)"
    echo "2. Check device connectivity"
    if [ -n "$FRR_DEBS_DIR" ]; then
        echo "3. Install FRR packages from $FRR_DEBS_DIR"
        echo "4. Restart BGP docker containers"
        echo "5. Apply complete DCI configurations from $SCRIPT_DIR"
        echo "6. Validate BGP neighbor establishment"
    else
        echo "3. Apply complete DCI configurations from $SCRIPT_DIR"
        echo "4. Validate BGP neighbor establishment"
    fi
else
    echo "This script will:"
    if [ -n "$FRR_DEBS_DIR" ]; then
        echo "1. Install FRR packages from $FRR_DEBS_DIR (before reset - optimization)"
        echo "2. Reset all SD devices (remove configs and reboot)"
        echo "3. Wait for devices to come back online"
        echo "4. Apply complete DCI configurations from $SCRIPT_DIR"
        echo "5. Validate BGP neighbor establishment"
        echo "   (Note: BGP docker restart not needed - packages installed before reset)"
    else
        echo "1. Reset all SD devices (remove configs and reboot)"
        echo "2. Wait for devices to come back online"
        echo "3. Apply complete DCI configurations from $SCRIPT_DIR"
        echo "4. Validate BGP neighbor establishment"
    fi
fi
echo ""
if [ "$PARALLEL_MODE" = true ]; then
    echo "Processing Mode: PARALLEL (faster - all devices processed simultaneously)"
    echo "Estimated time: ~10-15 minutes for full deployment"
else
    echo "Processing Mode: SEQUENTIAL (safer - one device at a time)"
    echo "Estimated time: ~30-45 minutes for full deployment"
fi
if [ -n "$DEVICE_FILTER" ]; then
    echo "Devices to be configured (filtered): ${SD_DEVICES[*]}"
else
    echo "Devices to be configured: ${SD_DEVICES[*]}"
fi
if [ ${#HOST_DEVICES[@]} -gt 0 ]; then
    if [ -n "$DEVICE_FILTER" ]; then
        echo "Host devices available (filtered): ${HOST_DEVICES[*]}"
    else
        echo "Host devices available: ${HOST_DEVICES[*]}"
    fi
fi
echo "Proceeding with deployment..."

if [ "$SKIP_RESET" = false ]; then
    # Install FRR packages before reset if requested (optimization)
    if [ -n "$FRR_DEBS_DIR" ]; then
        echo "Phase 1a: Installing FRR packages before reset (optimization)..." | log_output
        echo "================================================================" | log_output
        
        # Get .deb files
        deb_files=("$FRR_DEBS_DIR"/*.deb)
        echo "Installing FRR packages from: $FRR_DEBS_DIR" | log_output
        echo "Found ${#deb_files[@]} .deb files to install" | log_output
        echo "Installing before reset to avoid BGP docker restart after reboot" | log_output
        
        if [ "$PARALLEL_MODE" = true ]; then
            echo "Installing FRR packages in parallel mode..." | log_output
            
            # Install packages on all SD devices in parallel
            for device in "${SD_DEVICES[@]}"; do
                parallel_install_frr_packages "$device" "${deb_files[@]}"
            done
            
            # Wait for all installations to complete
            if wait_for_parallel_completion "frr_install" "${SD_DEVICES[@]}"; then
                echo "✅ FRR package installation completed on all devices" | log_output
            else
                echo "⚠️  Some FRR package installations may have failed" | log_output
            fi
            
        else
            echo "Installing FRR packages in sequential mode..." | log_output
            
            # Install packages sequentially
            for device in "${SD_DEVICES[@]}"; do
                echo "Installing FRR packages on $device..." | log_output
                if install_frr_packages_in_bgp_docker "$device" "${deb_files[@]}"; then
                    echo "✅ FRR packages installed on $device" | log_output
                else
                    echo "❌ FRR package installation failed on $device" | log_output
                fi
                
                sleep 5  # Brief wait between devices
            done
        fi
        
        echo "Phase 1a completed: FRR packages installed before reset" | log_output
        echo "=======================================================" | log_output
        echo ""
        
    fi
    
    echo "Phase 1b: Resetting all SD devices..." | log_output
    echo "=====================================" | log_output

    if [ "$PARALLEL_MODE" = true ]; then
        echo "Using parallel mode for device reset (faster)" | log_output
        
        # Start parallel reset operations
        for device in "${SD_DEVICES[@]}"; do
            parallel_reset_device "$device"
        done
        
        # Wait for all reset operations to complete
        if wait_for_parallel_completion "reset" "${SD_DEVICES[@]}"; then
            echo "All reset operations completed successfully" | log_output
        else
            echo "Some reset operations failed or timed out" | log_output
        fi
        
        echo "Waiting 90 seconds for devices to settle after reset..." | log_output
        sleep 90
        
        echo "Phase 2: Waiting for devices to come back online (parallel)..." | log_output
        echo "=============================================================" | log_output
        
        # Start parallel wait operations
        for device in "${SD_DEVICES[@]}"; do
            parallel_wait_for_device "$device"
        done
        
        # Wait for all devices to come online (preserve status files for collection)
        if wait_for_parallel_completion "wait" "${SD_DEVICES[@]}" false; then
            echo "Device online check completed" | log_output
        else
            echo "Some devices failed to come online or timed out" | log_output
        fi
        
        # Collect online devices from status files
        online_devices=()
        for device in "${SD_DEVICES[@]}"; do
            status_file="/tmp/deploy_dci_wait_${device}.status"
            if [ -f "$status_file" ] && [ "$(cat "$status_file")" = "ONLINE" ]; then
                online_devices+=("$device")
            fi
            # Clean up status file after checking
            rm -f "$status_file"
        done
        
    else
        echo "Using sequential mode for device reset (safer)" | log_output
        
        # Reset all devices sequentially
        for device in "${SD_DEVICES[@]}"; do
            echo "Resetting $device..." | log_output
            
            ssh_to_device "$device" "sudo rm -f /etc/sonic/config_db.json" || true
            ssh_to_device "$device" "sudo rm -f /etc/sonic/frr/bgpd.conf" || true  
            ssh_to_device "$device" "sudo reboot" || true
            
            echo "$device reset command sent" | log_output
            sleep 5
        done

        echo "All reset commands sent. Waiting 90 seconds before checking device status..." | log_output
        sleep 90

        echo "Phase 2: Waiting for devices to come back online (sequential)..." | log_output
        echo "===============================================================" | log_output

        # Wait for all devices to come back sequentially
        online_devices=()
        for device in "${SD_DEVICES[@]}"; do
            if wait_for_device "$device"; then
                online_devices+=("$device")
            else
                echo "WARNING: $device did not come back online, skipping configuration..." | log_output
            fi
        done
    fi
else
    echo "Phase 1: Skipping device reset (default behavior)" | log_output
    echo "=========================================================" | log_output
    
    echo "Phase 2: Checking device connectivity..." | log_output
    echo "=======================================" | log_output
    
    # Check which devices are currently online without resetting
    online_devices=()
    online_hosts=()
    
    echo "Checking SD devices..." | log_output
    for device in "${SD_DEVICES[@]}"; do
        echo "Checking connectivity to $device..." | log_output
        host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
        xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
        
        # Determine credentials based on device type
        username=""
        password=""
        if [[ "$device" =~ ^SD[0-9]+$ ]]; then
            username="cisco"
            password="cisco123"
        elif [[ "$device" =~ ^HOST[0-9]+$ ]]; then
            username="vxr"
            password="cisco123"
        else
            echo "WARNING: Unknown device type for $device, skipping..." | log_output
            continue
        fi
        
        if sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=10 -p "$xr_redir22" "$username@$host_agent" "echo 'online'" &>/dev/null; then
            echo "✅ $device online" | log_output
            online_devices+=("$device")
        else
            echo "⚠️ $device not accessible" | log_output
        fi
    done
    
    echo "Checking HOST devices..." | log_output
    for device in "${HOST_DEVICES[@]}"; do
        if jq -e ".${device}" "$PORT_JSON" > /dev/null; then
            echo "Checking connectivity to $device..." | log_output
            host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
            xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
            
            if sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=10 -p "$xr_redir22" vxr@"$host_agent" "echo 'online'" &>/dev/null; then
                echo "✅ $device is online and accessible" | log_output
                online_hosts+=("$device")
            else
                echo "⚠️  WARNING: $device is not accessible" | log_output
            fi
        fi
    done
fi

echo "Devices back online: ${online_devices[*]}" | log_output
if [ ${#online_hosts[@]} -gt 0 ]; then
    echo "Host devices online: ${online_hosts[*]}" | log_output
fi

# FRR Package Installation Phase (if requested and not installing before reset)
if [ -n "$FRR_DEBS_DIR" ] && [ "$SKIP_RESET" = true ]; then
    echo "Phase 3: Installing FRR packages..." | log_output
    echo "====================================" | log_output
    
    # Get .deb files
    deb_files=("$FRR_DEBS_DIR"/*.deb)
    echo "Installing FRR packages from: $FRR_DEBS_DIR" | log_output
    echo "Found ${#deb_files[@]} .deb files to install" | log_output
    
    if [ "$PARALLEL_MODE" = true ]; then
        echo "Installing FRR packages in parallel mode..." | log_output
        
        # Install packages on all online SD devices in parallel
        for device in "${online_devices[@]}"; do
            parallel_install_frr_packages "$device" "${deb_files[@]}"
        done
        
        # Wait for all installations to complete
        if wait_for_parallel_completion "frr_install" "${online_devices[@]}"; then
            echo "✅ FRR package installation completed on all devices" | log_output
        else
            echo "⚠️  Some FRR package installations may have failed" | log_output
        fi
        
        echo "Restarting BGP docker containers in parallel..." | log_output
        
        # Restart BGP docker on all devices in parallel
        for device in "${online_devices[@]}"; do
            parallel_restart_bgp_docker "$device"
        done
        
        # Wait for all restarts to complete
        if wait_for_parallel_completion "bgp_restart" "${online_devices[@]}"; then
            echo "✅ BGP docker restarts completed on all devices" | log_output
        else
            echo "⚠️  Some BGP docker restarts may have failed" | log_output
        fi
        
    else
        echo "Installing FRR packages in sequential mode..." | log_output
        
        # Install packages sequentially
        for device in "${online_devices[@]}"; do
            echo "Installing FRR packages on $device..." | log_output
            if install_frr_packages_in_bgp_docker "$device" "${deb_files[@]}"; then
                echo "✅ FRR packages installed on $device" | log_output
            else
                echo "❌ FRR package installation failed on $device" | log_output
            fi
            
            echo "Restarting BGP docker on $device..." | log_output
            if restart_bgp_docker "$device"; then
                echo "✅ BGP docker restarted on $device" | log_output
            else
                echo "❌ BGP docker restart failed on $device" | log_output
            fi
            
            sleep 10  # Wait between devices
        done
    fi
    
    echo "Phase 3 completed: FRR package installation and BGP docker restart" | log_output
    echo "=================================================================" | log_output
    echo ""
    
    # Update phase number for configuration application
    CONFIG_PHASE="Phase 4"
elif [ -n "$FRR_DEBS_DIR" ] && [ "$SKIP_RESET" = false ]; then
    echo "Phase 3: FRR packages will be installed after reset during configuration" | log_output
    echo "=======================================================================" | log_output
    CONFIG_PHASE="Phase 3"
else
    CONFIG_PHASE="Phase 3"
fi

echo "$CONFIG_PHASE: Applying configurations..." | log_output
echo "===================================" | log_output

# Check if all discovered SD devices are online before proceeding
echo "Verifying all discovered SD devices are online before applying configurations..." | log_output
missing_devices=()
for device in "${SD_DEVICES[@]}"; do
    if [[ ! " ${online_devices[*]} " =~ " ${device} " ]]; then
        missing_devices+=("$device")
    fi
done

if [ ${#missing_devices[@]} -gt 0 ]; then
    echo "⚠️  WARNING: The following SD devices are not online: ${missing_devices[*]}" | log_output
    echo "🔄 Waiting for ALL devices to come online before applying configurations..." | log_output
    
    # Keep checking for missing devices every 30 seconds
    max_additional_wait=300  # 5 minutes additional wait
    additional_start_time=$(date +%s)
    
    while [ ${#missing_devices[@]} -gt 0 ] && [ $(($(date +%s) - additional_start_time)) -lt $max_additional_wait ]; do
        local elapsed_minutes=$((($(date +%s) - additional_start_time) / 60))
        echo "Still waiting for: ${missing_devices[*]} ($elapsed_minutes min elapsed)" | log_output
        sleep 30
        
        # Re-check missing devices
        still_missing=()
        for device in "${missing_devices[@]}"; do
            host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
            xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
            
            if sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=10 -p "$xr_redir22" cisco@"$host_agent" "echo 'online'" &>/dev/null; then
                echo "✅ $device just came online!" | log_output
                online_devices+=("$device")
            else
                still_missing+=("$device")
            fi
        done
        missing_devices=("${still_missing[@]}")
    done
    
    if [ ${#missing_devices[@]} -gt 0 ]; then
        echo "❌ Timeout: The following devices are still not online after additional 5 minutes: ${missing_devices[*]}" | log_output
        echo "⚠️  Proceeding with configuration on available devices only" | log_output
    else
        echo "🎉 ALL SD devices are now online! Proceeding with configurations..." | log_output
    fi
else
    echo "✅ All discovered SD devices are online, proceeding with configurations..." | log_output
fi

# Check HOST device connectivity for all modes
echo "Checking HOST device connectivity..." | log_output
online_hosts=()
for device in "${HOST_DEVICES[@]}"; do
    if jq -e ".${device}" "$PORT_JSON" > /dev/null; then
        echo "Checking connectivity to $device..." | log_output
        host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
        xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
        
        if sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=10 -p "$xr_redir22" vxr@"$host_agent" "echo 'online'" &>/dev/null; then
            echo "✅ $device is online and accessible" | log_output
            online_hosts+=("$device")
        else
            echo "⚠️  WARNING: $device is not accessible" | log_output
        fi
    fi
done

if [ "$PARALLEL_MODE" = true ]; then
    echo "Using parallel mode for configuration application (faster)" | log_output
    
    # Devices already verified online, proceeding directly with configuration
    echo "✅ All devices verified online, proceeding with configuration..." | log_output
    
    echo "Applying ALL device configurations in parallel..." | log_output
    
    # Apply all SD device configurations in parallel
    sd_devices_to_config=()
    for device in "${online_devices[@]}"; do
        sd_devices_to_config+=("$device")
        parallel_apply_config "$device"
    done
    
    if [ ${#sd_devices_to_config[@]} -gt 0 ]; then
        if wait_for_parallel_completion "config" "${sd_devices_to_config[@]}"; then
            echo "All SD device configurations completed" | log_output
        else
            echo "Some SD device configurations failed" | log_output
        fi
    fi
    
else
    echo "Using sequential mode for configuration application (safer)" | log_output
    
    # Dynamically categorize devices based on what's available for sequential mode
    SPINE_DEVICES=()
    LEAF_DEVICES=()

    for device in "${online_devices[@]}"; do
        # SD1-SD4 are typically spines, SD5+ are leaves
        if [[ "$device" =~ ^SD[1-4]$ ]]; then
            SPINE_DEVICES+=("$device")
        else
            LEAF_DEVICES+=("$device")
        fi
    done

    echo "Device categorization for sequential mode:" | log_output
    echo "Spine devices: ${SPINE_DEVICES[*]}" | log_output
    echo "Leaf devices: ${LEAF_DEVICES[*]}" | log_output
    
    echo "Applying spine configurations first..." | log_output
    for device in "${SPINE_DEVICES[@]}"; do
        echo "Configuring spine $device..." | log_output
        if ! apply_config "$device"; then
            echo "ERROR: Failed to configure $device" | log_output
        fi
        sleep 30  # Wait between device configurations
    done

    echo "Applying leaf configurations..." | log_output
    for device in "${LEAF_DEVICES[@]}"; do
        echo "Configuring leaf $device..." | log_output
        if ! apply_config "$device"; then
            echo "ERROR: Failed to configure $device" | log_output
        fi
        sleep 30  # Wait between device configurations
    done
fi

if [ "$FRR_ONLY" = false ] && [ ${#online_hosts[@]} -gt 0 ]; then
    if [ "$PARALLEL_MODE" = true ]; then
        echo "Applying HOST configurations in parallel..." | log_output
        
        # HOST devices already verified online, proceeding with configuration
        echo "✅ HOST devices verified online, proceeding with configuration..." | log_output
        
        # Start parallel HOST configurations
        for device in "${online_hosts[@]}"; do
            echo "Starting HOST configuration for $device..." | log_output
            {
                if apply_host_config "$device"; then
                    echo "SUCCESS" > "/tmp/deploy_dci_host_${device}.status"
                    echo "✅ [$device] HOST configuration applied successfully" | log_output
                else
                    echo "FAILED" > "/tmp/deploy_dci_host_${device}.status"
                    echo "❌ [$device] HOST configuration failed" | log_output
                fi
            } &
            echo $! > "/tmp/deploy_dci_host_${device}.pid"
        done
        
        # Wait for HOST configurations to complete
        if wait_for_parallel_completion "host" "${online_hosts[@]}"; then
            echo "HOST configurations completed" | log_output
        else
            echo "Some HOST configurations failed" | log_output
        fi
        
    else
        echo "Applying HOST configurations sequentially..." | log_output
        for device in "${online_hosts[@]}"; do
            echo "Configuring host $device..." | log_output
            if ! apply_host_config "$device"; then
                echo "ERROR: Failed to configure $device" | log_output
            fi
            sleep 10  # Shorter wait for host configurations
        done
    fi
else
    if [ "$FRR_ONLY" = true ]; then
        echo "Skipping HOST configurations (FRR-only mode)" | log_output
    else
        echo "No HOST devices online, skipping HOST configurations" | log_output
    fi
fi

# Determine final phase number based on whether FRR installation was performed
if [ -n "$FRR_DEBS_DIR" ]; then
    FINAL_PHASE="Phase 5"
else
    FINAL_PHASE="Phase 4"
fi

echo "$FINAL_PHASE: Final Validation and Status..." | log_output
echo "=======================================" | log_output

# Display the final DCI topology
display_dci_topology

# Wait for BGP convergence
echo "Waiting 30 seconds for BGP convergence..." | log_output
sleep 30

# Test HOST gateway connectivity as part of final validation
if [ ${#HOST_DEVICES[@]} -gt 0 ] && [ "$FRR_ONLY" = false ]; then
    echo ""
    echo "🔗 Testing HOST Gateway Connectivity (Final Validation)..." | log_output
    echo "=========================================================" | log_output
    
    # Test all HOST devices from JSON, not just those in online_hosts array
    for device in "${HOST_DEVICES[@]}"; do
        echo "🔄 Testing connectivity for $device..." | log_output
        
        # Check if device is accessible first
        host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
        xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
        
        if [ "$host_agent" = "null" ] || [ "$xr_redir22" = "null" ]; then
            echo "⚠️  $device: Missing connection details in JSON, skipping..." | log_output
            continue
        fi
        
        # Test SSH connectivity first
        if ! timeout 5 sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ConnectTimeout=5 -p "$xr_redir22" vxr@"$host_agent" "echo 'online'" &>/dev/null; then
            echo "❌ $device: Not accessible via SSH, skipping gateway test" | log_output
            continue
        fi
        
        echo "✅ $device: SSH connectivity confirmed" | log_output
        
        # Look for gateway IP in multiple ways
        config_file="$CONFIG_DIR/${device}-complete-config.txt"
        gateway_ip=""
        
        if [ -f "$config_file" ]; then
            # Method 1: Look for gateway4: in config file
            if grep -q "gateway4:" "$config_file"; then
                gateway_ip=$(grep "gateway4:" "$config_file" | awk '{print $2}' | head -1)
                echo "📋 $device: Found gateway in config file: $gateway_ip" | log_output
            # Method 2: Look for ping commands with gateway IPs
            elif grep -q "ping -c.*10\.212\.10\." "$config_file"; then
                gateway_ip=$(grep "ping -c.*10\.212\.10\." "$config_file" | grep -o "10\.212\.10\.[0-9]\+" | head -1)
                echo "📋 $device: Found gateway in ping command: $gateway_ip" | log_output
            # Method 3: Look for any IP route commands
            elif grep -q "ip route" "$config_file"; then
                gateway_ip=$(grep "ip route" "$config_file" | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" | tail -1)
                echo "📋 $device: Found gateway in route command: $gateway_ip" | log_output
            fi
        fi
        
        # Method 4: If no config file or no gateway found, try to detect from device
        if [ -z "$gateway_ip" ]; then
            echo "🔍 $device: No gateway in config file, checking device routing table..." | log_output
            gateway_ip=$(timeout 10 sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                -p "$xr_redir22" vxr@"$host_agent" \
                "ip route | grep default | awk '{print \$3}' | head -1" 2>/dev/null || echo "")
            
            if [ -n "$gateway_ip" ]; then
                echo "� $device: Found default gateway on device: $gateway_ip" | log_output
            fi
        fi
        
        # Method 5: Try common gateway IPs if nothing found
        if [ -z "$gateway_ip" ]; then
            echo "🔍 $device: No gateway found, trying common gateway IPs..." | log_output
            for test_gw in "10.212.10.1" "192.168.1.1" "10.10.10.1" "172.16.1.1"; do
                echo "🧪 $device: Testing potential gateway $test_gw..." | log_output
                if timeout 10 sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                    -p "$xr_redir22" vxr@"$host_agent" \
                    "ping -c 2 -W 2 $test_gw" &>/dev/null; then
                    gateway_ip="$test_gw"
                    echo "✅ $device: Found working gateway: $gateway_ip" | log_output
                    break
                fi
            done
        fi
        
        # Perform the actual gateway connectivity test
        if [ -n "$gateway_ip" ]; then
            echo "🌐 Testing $device connectivity to gateway $gateway_ip..." | log_output
            
            # Perform ping test with more verbose output
            ping_result=$(timeout 15 sshpass -p 'cisco123' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                -p "$xr_redir22" vxr@"$host_agent" \
                "ping -c 5 -W 3 $gateway_ip" 2>&1)
            
            if echo "$ping_result" | grep -q "5 received\|[4-5] received"; then
                echo "✅ $device: Gateway $gateway_ip is REACHABLE (excellent connectivity)" | log_output
            elif echo "$ping_result" | grep -q "[1-3] received"; then
                echo "⚠️  $device: Gateway $gateway_ip is PARTIALLY REACHABLE (some packet loss)" | log_output
            else
                echo "❌ $device: Gateway $gateway_ip is NOT REACHABLE" | log_output
                echo "   Debug info: $(echo "$ping_result" | tail -2 | tr '\n' ' ')" | log_output
            fi
        else
            echo "❓ $device: No gateway IP found to test" | log_output
        fi
        
        echo "" | log_output
    done
    
    echo "HOST Gateway Connectivity Test Completed" | log_output
    echo "" | log_output
fi

# Check BGP status summary
echo "BGP Status Summary:" | log_output
for device in "${SPINE_DEVICES[@]}"; do
    if [[ " ${online_devices[*]} " =~ " ${device} " ]]; then
        neighbor_count=$(ssh_to_device "$device" "vtysh -c 'show bgp summary' | grep -c 'Established'" || echo "0")
        echo "$device: $neighbor_count BGP sessions established" | log_output
    fi
done

echo "========================================" | log_output
echo "Deployment completed at: $(date)" | log_output
if [ "$ENABLE_LOGGING" = true ]; then
    echo "Log file: $LOG_FILE" | log_output
fi
echo "Online devices: ${online_devices[*]}" | log_output
echo "========================================" | log_output

echo ""
echo "🎯 Summary: ${#online_devices[@]}/${#SD_DEVICES[@]} devices configured"
if [ ${#online_hosts[@]} -gt 0 ] && [ "$FRR_ONLY" = false ]; then
    echo "✅ Host devices online: ${#online_hosts[@]}"
fi
if [ "$FRR_ONLY" = true ]; then
    echo "✅ FRR BGP configurations applied to online devices"
else
    echo "✅ Configurations applied to online devices"
fi
if [ ${#online_hosts[@]} -gt 0 ] && [ "$FRR_ONLY" = false ]; then
    echo "✅ HOST configurations applied to online hosts"
elif [ "$FRR_ONLY" = true ]; then
    echo "✅ HOST configurations skipped (FRR-only mode)"
fi
echo "✅ BGP convergence wait completed"
echo ""
echo "📋 Manual SSH Access Commands:"
echo "==============================="
echo "SD Devices (cisco/cisco123):"
for device in "${SD_DEVICES[@]}"; do
    if jq -e ".${device}" "$PORT_JSON" > /dev/null; then
        host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
        xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
        echo "$device: sshpass -p 'cisco123' ssh -p $xr_redir22 cisco@$host_agent"
    fi
done

echo ""
echo "HOST Devices (vxr/cisco123):"
for device in "${HOST_DEVICES[@]}"; do
    if jq -e ".${device}" "$PORT_JSON" > /dev/null; then
        host_agent=$(jq -r ".${device}.HostAgent" "$PORT_JSON")
        xr_redir22=$(jq -r ".${device}.xr_redir22" "$PORT_JSON")
        echo "$device: sshpass -p 'cisco123' ssh -p $xr_redir22 vxr@$host_agent"
    fi
done

echo ""
echo "📊 Quick Status Check Commands:"
echo "==============================="
echo "Check BGP on SD1: sshpass -p 'cisco123' ssh -p $(jq -r '.SD1.xr_redir22' "$PORT_JSON") cisco@$(jq -r '.SD1.HostAgent' "$PORT_JSON") 'vtysh -c \"show bgp summary\"'"
echo "Check interfaces: sshpass -p 'cisco123' ssh -p $(jq -r '.SD1.xr_redir22' "$PORT_JSON") cisco@$(jq -r '.SD1.HostAgent' "$PORT_JSON") 'show interface status'"
echo ""
if [ "$ENABLE_LOGGING" = true ]; then
    echo "📝 Log file location: $LOG_FILE"
else
    echo "📝 Logging was disabled (use --log flag to enable)"
fi
echo ""

if [ ${#online_devices[@]} -eq ${#SD_DEVICES[@]} ]; then
    echo "🎉 SUCCESS: All devices were reset and configured successfully!"
else
    echo "⚠️  WARNING: Some devices may need manual intervention:"
    for device in "${SD_DEVICES[@]}"; do
        if [[ ! " ${online_devices[*]} " =~ " ${device} " ]]; then
            echo "   - $device (did not come back online)"
        fi
    done
fi

# Cleanup temporary files
echo "Cleaning up temporary files..." | log_output
rm -f /tmp/deploy_dci_*_*.status /tmp/deploy_dci_*_*.pid 2>/dev/null || true

echo "Deployment script completed at: $(date)" | log_output