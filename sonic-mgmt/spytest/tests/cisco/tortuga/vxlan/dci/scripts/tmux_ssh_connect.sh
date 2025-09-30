#!/bin/bash

# Script to create tmux window with SSH connections to devices from port.json
# Must be run from within a tmux session
# Usage: ./tmux_ssh_connect.sh <path_to_port.json>

set -e

# Function to display usage
usage() {
    echo "Usage: $0 <path_to_port.json>"
    echo ""
    echo "This script creates tmux windows with SSH connections to devices from port.json"
    echo "Must be run from within a tmux session."
    echo ""
    echo "Arguments:"
    echo "  <path_to_port.json>  Path to the port.json file containing device information"
    echo ""
    echo "Examples:"
    echo "  $0 sonic-test/port.json"
    echo "  $0 /path/to/your/port.json"
    echo ""
    exit 1
}

# Check if argument is provided
if [[ $# -ne 1 ]]; then
    echo "Error: Missing required argument"
    echo ""
    usage
fi

# Check if help is requested
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

# Configuration
PORT_JSON_FILE="$1"
LEAVES_WINDOW="DC_Leaves"
DCI_GW_WINDOW="DCI_Gateways"
HOST_WINDOW="HOST_devices"
SONIC_MGMT_WINDOW="sonic_mgmt"
USERNAME="cisco"
PASSWORD="cisco123"
HOST_USERNAME="vxr"
HOST_PASSWORD="cisco123"
SONIC_MGMT_USERNAME="vxr"
SONIC_MGMT_PASSWORD="cisco123"

# Check if we're running inside a tmux session
if [[ -z "$TMUX" ]]; then
    echo "Error: This script must be run from within a tmux session!"
    echo "Please start tmux first: tmux new-session"
    echo "Then run this script from within the tmux session."
    exit 1
fi

echo "Running inside tmux session. Creating new windows for devices"

# Check if port.json exists
if [[ ! -f "$PORT_JSON_FILE" ]]; then
    echo "Error: Port.json file '$PORT_JSON_FILE' not found!"
    echo "Please check the file path and try again."
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install jq first."
    echo "On Ubuntu/Debian: sudo apt install jq"
    echo "On CentOS/RHEL: sudo yum install jq"
    exit 1
fi

# Check if sshpass is installed for password authentication
if ! command -v sshpass &> /dev/null; then
    echo "Warning: sshpass is not installed. You'll need to enter passwords manually."
    echo "To install sshpass:"
    echo "On Ubuntu/Debian: sudo apt install sshpass"
    echo "On CentOS/RHEL: sudo yum install sshpass"
    echo ""
    read -p "Continue without sshpass? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    USE_SSHPASS=false
else
    USE_SSHPASS=true
fi

# Kill existing windows if they exist
tmux kill-window -t "$LEAVES_WINDOW" 2>/dev/null || true
tmux kill-window -t "$DCI_GW_WINDOW" 2>/dev/null || true
tmux kill-window -t "$HOST_WINDOW" 2>/dev/null || true
tmux kill-window -t "$SONIC_MGMT_WINDOW" 2>/dev/null || true

echo "Creating 4 tmux windows for different device types"

# Parse JSON and get device names
devices=($(jq -r 'keys[]' "$PORT_JSON_FILE"))

if [[ ${#devices[@]} -eq 0 ]]; then
    echo "Error: No devices found in '$PORT_JSON_FILE'"
    echo "Please verify that the JSON file contains device configurations."
    exit 1
fi

echo "Found ${#devices[@]} devices: ${devices[*]}"

# Separate devices by type
leaf_devices=()      # SD5, SD6, SD7 (DC leaves)
dci_gw_devices=()    # SD1, SD2, SD3 (DCI gateways)
host_devices=()

for device in "${devices[@]}"; do
    if [[ "$device" == "SD5" || "$device" == "SD6" || "$device" == "SD7" || "$device" == "SD8" ]]; then
        leaf_devices+=("$device")
    elif [[ "$device" == "SD1" || "$device" == "SD2" || "$device" == "SD3" || "$device" == "SD4" ]]; then
        dci_gw_devices+=("$device")
    elif [[ "$device" == HOST* ]]; then
        host_devices+=("$device")
    fi
done

echo "DC Leaf devices (${#leaf_devices[@]}): ${leaf_devices[*]}"
echo "DCI Gateway devices (${#dci_gw_devices[@]}): ${dci_gw_devices[*]}"
echo "HOST devices (${#host_devices[@]}): ${host_devices[*]}"

# Function to create SSH command
create_ssh_command() {
    local device="$1"
    local host_agent="$2"
    local xr_port="$3"
    local ssh_username="$4"
    local ssh_password="$5"
    
    if [[ "$USE_SSHPASS" == "true" ]]; then
        echo "sshpass -p '$ssh_password' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ssh_username@$host_agent -p $xr_port"
    else
        echo "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $ssh_username@$host_agent -p $xr_port"
    fi
}

# Function to set pane title
set_pane_title() {
    local window="$1"
    local device="$2"
    # Set title for current active pane in window
    tmux select-pane -t "$window" -T "$device"
}

# ===============================
# WINDOW 1: DC LEAF DEVICES (SD5, SD6, SD7)
# ===============================
if [[ ${#leaf_devices[@]} -gt 0 ]]; then
    echo ""
    echo "Creating Window 1: DC Leaf devices (${#leaf_devices[@]} panes)"
    
    # Create new window for DC leaf devices
    tmux new-window -n "$LEAVES_WINDOW"
    
    first_leaf="${leaf_devices[0]}"
    host_agent=$(jq -r ".\"$first_leaf\".HostAgent" "$PORT_JSON_FILE")
    xr_port=$(jq -r ".\"$first_leaf\".xr_redir22" "$PORT_JSON_FILE")
    
    echo "Creating first pane for: $first_leaf ($host_agent:$xr_port)"
    
    # Send SSH command to the first pane
    ssh_cmd=$(create_ssh_command "$first_leaf" "$host_agent" "$xr_port" "$USERNAME" "$PASSWORD")
    tmux send-keys -t "$LEAVES_WINDOW" "$ssh_cmd" Enter
    
    # Set pane title for first leaf device
    set_pane_title "$LEAVES_WINDOW" "$first_leaf"
    
    # Add remaining leaf devices as new panes
    for device in "${leaf_devices[@]:1}"; do
        host_agent=$(jq -r ".\"$device\".HostAgent" "$PORT_JSON_FILE")
        xr_port=$(jq -r ".\"$device\".xr_redir22" "$PORT_JSON_FILE")
        
        echo "Adding pane for: $device ($host_agent:$xr_port)"
        
        ssh_cmd=$(create_ssh_command "$device" "$host_agent" "$xr_port" "$USERNAME" "$PASSWORD")
        tmux split-window -t "$LEAVES_WINDOW" "$ssh_cmd"
        
        # Set pane title for the newly created pane (tmux automatically focuses on it)
        set_pane_title "$LEAVES_WINDOW" "$device"
        
        tmux select-layout -t "$LEAVES_WINDOW" tiled
    done
    
    # Set final layout for leaf window
    tmux select-layout -t "$LEAVES_WINDOW" tiled
else
    echo "No DC leaf devices found, skipping leaf window"
fi

# ===============================
# WINDOW 2: DCI GATEWAY DEVICES (SD1, SD2, SD3)
# ===============================
if [[ ${#dci_gw_devices[@]} -gt 0 ]]; then
    echo ""
    echo "Creating Window 2: DCI Gateway devices (${#dci_gw_devices[@]} panes)"
    
    # Create new window for DCI gateway devices
    tmux new-window -n "$DCI_GW_WINDOW"
    
    first_gw="${dci_gw_devices[0]}"
    host_agent=$(jq -r ".\"$first_gw\".HostAgent" "$PORT_JSON_FILE")
    xr_port=$(jq -r ".\"$first_gw\".xr_redir22" "$PORT_JSON_FILE")
    
    echo "Creating first pane for: $first_gw ($host_agent:$xr_port)"
    
    # Send SSH command to the first pane
    ssh_cmd=$(create_ssh_command "$first_gw" "$host_agent" "$xr_port" "$USERNAME" "$PASSWORD")
    tmux send-keys -t "$DCI_GW_WINDOW" "$ssh_cmd" Enter
    
    # Set pane title for first gateway device
    set_pane_title "$DCI_GW_WINDOW" "$first_gw"
    
    # Add remaining gateway devices as new panes
    for device in "${dci_gw_devices[@]:1}"; do
        host_agent=$(jq -r ".\"$device\".HostAgent" "$PORT_JSON_FILE")
        xr_port=$(jq -r ".\"$device\".xr_redir22" "$PORT_JSON_FILE")
        
        echo "Adding pane for: $device ($host_agent:$xr_port)"
        
        ssh_cmd=$(create_ssh_command "$device" "$host_agent" "$xr_port" "$USERNAME" "$PASSWORD")
        tmux split-window -t "$DCI_GW_WINDOW" "$ssh_cmd"
        
        # Set pane title for the newly created pane (tmux automatically focuses on it)
        set_pane_title "$DCI_GW_WINDOW" "$device"
        
        tmux select-layout -t "$DCI_GW_WINDOW" tiled
    done
    
    # Set final layout for gateway window
    tmux select-layout -t "$DCI_GW_WINDOW" tiled
else
    echo "No DCI gateway devices found, skipping gateway window"
fi

# ===============================
# WINDOW 3: HOST DEVICES
# ===============================
if [[ ${#host_devices[@]} -gt 0 ]]; then
    echo ""
    echo "Creating Window 2: HOST devices (${#host_devices[@]} panes)"
    
    # Create new window for HOST devices
    tmux new-window -n "$HOST_WINDOW"
    
    first_host="${host_devices[0]}"
    host_agent=$(jq -r ".\"$first_host\".HostAgent" "$PORT_JSON_FILE")
    xr_port=$(jq -r ".\"$first_host\".xr_redir22" "$PORT_JSON_FILE")
    
    echo "Creating first pane for: $first_host ($host_agent:$xr_port)"
    
    # Send SSH command to the first pane (using HOST credentials)
    ssh_cmd=$(create_ssh_command "$first_host" "$host_agent" "$xr_port" "$HOST_USERNAME" "$HOST_PASSWORD")
    tmux send-keys -t "$HOST_WINDOW" "$ssh_cmd" Enter
    
    # Set pane title for first HOST device
    set_pane_title "$HOST_WINDOW" "$first_host"
    
    # Add remaining HOST devices as new panes
    for device in "${host_devices[@]:1}"; do
        host_agent=$(jq -r ".\"$device\".HostAgent" "$PORT_JSON_FILE")
        xr_port=$(jq -r ".\"$device\".xr_redir22" "$PORT_JSON_FILE")
        
        echo "Adding pane for: $device ($host_agent:$xr_port)"
        
        ssh_cmd=$(create_ssh_command "$device" "$host_agent" "$xr_port" "$HOST_USERNAME" "$HOST_PASSWORD")
        tmux split-window -t "$HOST_WINDOW" "$ssh_cmd"
        
        # Set pane title for the newly created pane (tmux automatically focuses on it)
        set_pane_title "$HOST_WINDOW" "$device"
        
        tmux select-layout -t "$HOST_WINDOW" tiled
    done
    
    # Set final layout for HOST window
    tmux select-layout -t "$HOST_WINDOW" tiled
else
    echo "No HOST devices found, skipping HOST window"
fi

# ===============================
# WINDOW 4: SONIC_MGMT (2 panes)
# ===============================
echo ""
echo "Creating Window 4: sonic_mgmt (2 panes)"

# Get sonic_mgmt device information
sonic_mgmt_host=$(jq -r '.sonic_mgmt.HostAgent' "$PORT_JSON_FILE")
sonic_mgmt_port=$(jq -r '.sonic_mgmt.xr_redir22' "$PORT_JSON_FILE")

echo "sonic_mgmt device: $sonic_mgmt_host:$sonic_mgmt_port"

# Create new window for sonic_mgmt
tmux new-window -n "$SONIC_MGMT_WINDOW"

echo "Creating first pane for sonic_mgmt"
# Send SSH command to the first pane
ssh_cmd=$(create_ssh_command "sonic_mgmt" "$sonic_mgmt_host" "$sonic_mgmt_port" "$SONIC_MGMT_USERNAME" "$SONIC_MGMT_PASSWORD")
tmux send-keys -t "$SONIC_MGMT_WINDOW" "$ssh_cmd" Enter

# Set title for first pane
set_pane_title "$SONIC_MGMT_WINDOW" "sonic_mgmt-1"

echo "Creating second pane for sonic_mgmt"
# Split window and create second pane with same SSH connection
ssh_cmd=$(create_ssh_command "sonic_mgmt" "$sonic_mgmt_host" "$sonic_mgmt_port" "$SONIC_MGMT_USERNAME" "$SONIC_MGMT_PASSWORD")
tmux split-window -t "$SONIC_MGMT_WINDOW" "$ssh_cmd"

# Set title for second pane
set_pane_title "$SONIC_MGMT_WINDOW" "sonic_mgmt-2"

# Arrange panes in horizontal split (side by side)
tmux select-layout -t "$SONIC_MGMT_WINDOW" even-horizontal

echo ""
echo "Setup complete! 4 tmux windows created:"
echo "1. '$LEAVES_WINDOW' - DC Leaf devices (${#leaf_devices[@]} panes: ${leaf_devices[*]}) - cisco/cisco123"
echo "2. '$DCI_GW_WINDOW' - DCI Gateway devices (${#dci_gw_devices[@]} panes: ${dci_gw_devices[*]}) - cisco/cisco123"
echo "3. '$HOST_WINDOW' - HOST devices (${#host_devices[@]} panes) - vxr/cisco123"
echo "4. '$SONIC_MGMT_WINDOW' - sonic_mgmt (2 panes) - vxr/cisco123"
echo ""
echo "Tmux controls:"
echo "- Ctrl+b then w: see all windows and switch between them"
echo "- Ctrl+b then n/p: next/previous window"
echo "- Ctrl+b then 0,1,2...: switch to specific window number"
echo "- Ctrl+b then arrow keys: navigate between panes"
echo "- Ctrl+b then z: zoom/unzoom current pane"
echo "- Ctrl+b then x: close current pane"
echo "- Ctrl+b then &: close entire window"
echo ""

# Switch to the first window (DC Leaves)
if [[ ${#leaf_devices[@]} -gt 0 ]]; then
    tmux select-window -t "$LEAVES_WINDOW"
    echo "Switched to DC Leaves window"
elif [[ ${#dci_gw_devices[@]} -gt 0 ]]; then
    tmux select-window -t "$DCI_GW_WINDOW"
    echo "Switched to DCI Gateways window"
elif [[ ${#host_devices[@]} -gt 0 ]]; then
    tmux select-window -t "$HOST_WINDOW"
    echo "Switched to HOST devices window"
else
    tmux select-window -t "$SONIC_MGMT_WINDOW"
    echo "Switched to sonic_mgmt window"
fi