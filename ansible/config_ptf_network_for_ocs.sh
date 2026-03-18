#!/bin/bash

# Script to configure PTF container network
# Usage: ./config_ptf_network.sh [OPTIONS]
# Options:
#   -s, --server-interface <interface>  Server physical interface name (e.g., eth0, eno1)
#   -v, --vm-set-name <name>            VM set name
#   -i, --ptf-ip <IP/mask>              PTF container management IP address and mask (e.g., 10.255.0.254/23)
#   -g, --mgmt-gw <IP>                  Management network gateway IP address
#   -d, --dns <DNS>                     DNS servers (space-separated, e.g., '192.168.1.1 192.168.1.2')
#   -h, --help                          Display this help message

# Default values
SERVER_INTERFACE=""
VM_SET_NAME="ptf"
PTF_IP=""
MGMT_GW=""
DNS_SERVERS=""
MGMT_BRIDGE="br0"

# Variables for rollback mechanism
ORIGINAL_IP=""
ORIGINAL_GW=""
ROLLBACK_REQUIRED=false
SCRIPT_EXITED=false

# Display help message
show_help() {
    echo "Script to configure PTF container network"
    echo ""
    echo "Usage: ./config_ptf_network.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --server-interface <interface>  Server physical interface name (e.g., eth0, eno1)"
    echo "  -v, --vm-set-name <name>            VM set name"
    echo "  -i, --ptf-ip <IP/mask>              PTF container management IP address and mask (e.g., 10.255.0.254/23)"
    echo "  -g, --mgmt-gw <IP>                  Management network gateway IP address"
    echo "  -d, --dns <DNS>                     DNS servers (space-separated, e.g., '192.168.1.1 192.168.1.2')"
    echo "  -h, --help                          Display this help message"
    echo ""
    echo "WARNING:"
    echo "  This script modifies server network configuration by bridging the physical"
    echo "  interface. If executed remotely, network connectivity may be lost if the"
    echo "  script fails. It is recommended to run this script locally or with console"
    echo "  access. The script includes automatic rollback on failure."
    echo ""
    echo "Example:"
    echo "  ./config_ptf_network_for_ocs.sh -s eth0 -i 10.255.0.254/23 -g 10.255.0.1"
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--server-interface)
                SERVER_INTERFACE="$2"
                shift 2
                ;;
            -v|--vm-set-name)
                VM_SET_NAME="$2"
                shift 2
                ;;
            -i|--ptf-ip)
                PTF_IP="$2"
                shift 2
                ;;
            -g|--mgmt-gw)
                MGMT_GW="$2"
                shift 2
                ;;
            -d|--dns)
                DNS_SERVERS="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                ;;
        esac
    done

    # Check required parameters
    if [[ -z "$PTF_IP" ]]; then
        echo "Error: PTF container management IP address must be specified"
        show_help
    fi

    if [[ -z "$MGMT_GW" ]]; then
        echo "Error: Management network gateway IP address must be specified"
        show_help
    fi
}

# Rollback function to restore original network configuration
rollback_network_config() {
    # Capture the exit code from the command that triggered the trap
    # Note: This may not always be accurate when called from trap
    local exit_code=$?
    
    # Don't rollback if script completed successfully
    if [[ $SCRIPT_EXITED -eq 1 ]]; then
        return 0
    fi
    
    echo ""
    echo "!!! ERROR DETECTED - Attempting to rollback network configuration !!!"
    echo ""
    
    if [[ $ROLLBACK_REQUIRED -eq false ]]; then
        echo "No rollback needed - network configuration not yet modified"
        return 0
    fi
    
    if [[ -z "$SERVER_INTERFACE" ]]; then
        echo "No server interface specified, skipping rollback"
        return 0
    fi
    
    echo "Rolling back network configuration for interface: $SERVER_INTERFACE"
    
    # Remove interface from bridge
    if brctl show $MGMT_BRIDGE 2>/dev/null | grep -q $SERVER_INTERFACE; then
        echo "Removing $SERVER_INTERFACE from bridge $MGMT_BRIDGE"
        brctl delif $MGMT_BRIDGE $SERVER_INTERFACE
    fi
    
    # Restore original IP address to physical interface
    if [[ -n "$ORIGINAL_IP" ]]; then
        echo "Restoring original IP address to $SERVER_INTERFACE: $ORIGINAL_IP"
        ip addr flush dev $SERVER_INTERFACE 2>/dev/null
        if ! ip addr add $ORIGINAL_IP dev $SERVER_INTERFACE; then
            echo "Warning: Failed to restore IP address to $SERVER_INTERFACE"
        fi
    fi
    
    # Restore original gateway
    if [[ -n "$ORIGINAL_GW" ]]; then
        echo "Restoring original gateway: $ORIGINAL_GW"
        ip route del default dev $MGMT_BRIDGE 2>/dev/null
        if ! ip route add default via $ORIGINAL_GW dev $SERVER_INTERFACE; then
            echo "Warning: Failed to restore default gateway"
        fi
    fi
    
    # Bring interface up
    echo "Bringing interface $SERVER_INTERFACE up"
    if ! ip link set $SERVER_INTERFACE up; then
        echo "Warning: Failed to bring interface $SERVER_INTERFACE up"
    fi
    
    # Remove bridge IP if it was added
    if [[ -n "$ORIGINAL_IP" ]] && ip addr show $MGMT_BRIDGE 2>/dev/null | grep -q 'inet\s+'; then
        echo "Removing IP address from bridge $MGMT_BRIDGE"
        ip addr flush dev $MGMT_BRIDGE 2>/dev/null
    fi
    
    echo ""
    echo "Rollback completed. Please verify network connectivity."
    echo "If connectivity issues persist, you may need to manually restore configuration."
    
    # Return the original exit code if it indicates failure, otherwise return 1
    if [[ $exit_code -ne 0 ]]; then
        return $exit_code
    else
        return 1
    fi
}

# Setup trap for cleanup and rollback
setup_trap() {
    # Trap EXIT to handle script termination
    # The EXIT trap will be called with the exit status of the command that terminated the script
    trap 'rollback_network_config' EXIT
    
    # Trap INT (Ctrl+C) and TERM signals
    # Save the exit code before calling rollback
    trap 'echo "Interrupted by user"; SCRIPT_EXITED=0; exit 130' INT TERM
}

# Create mgmt_bridge if it doesn't exist
create_mgmt_bridge() {
    echo "=== Creating mgmt_bridge ==="
    if brctl show | grep -q "^$MGMT_BRIDGE\s"; then
        echo "Bridge $MGMT_BRIDGE already exists"
    else
        echo "Creating bridge $MGMT_BRIDGE"
        brctl addbr $MGMT_BRIDGE
        ip link set $MGMT_BRIDGE up
        echo "Bridge $MGMT_BRIDGE created successfully"
    fi
    echo
}

# Configure PTF container network
configure_ptf_network() {
    echo "=== Configuring PTF container network ==="

    # Define PTF container name
    PTF_CONTAINER_NAME="ptf_${VM_SET_NAME}"
    echo "PTF container name: $PTF_CONTAINER_NAME"

    # Check if PTF container is running
    if ! docker ps -q -f name=$PTF_CONTAINER_NAME | grep -q .; then
        echo "Error: PTF container $PTF_CONTAINER_NAME is not running"
        return 1
    fi

    # Get PTF container PID
    PTF_PID=$(docker inspect --format '{{.State.Pid}}' $PTF_CONTAINER_NAME)
    if [[ -z "$PTF_PID" ]]; then
        echo "Error: Cannot get PTF container PID"
        return 1
    fi
    echo "PTF container PID: $PTF_PID"

    # Define interface names
    EXT_IF="ptf-${VM_SET_NAME}-m"
    INT_IF="mgmt"
    TMP_INT_IF="${INT_IF}_tmp"

    # Create veth pair if external interface doesn't exist
    if ! ip link show $EXT_IF > /dev/null 2>&1; then
        echo "Creating veth pair $EXT_IF <-> $TMP_INT_IF"
        ip link add $EXT_IF type veth peer name $TMP_INT_IF
        if [[ $? -ne 0 ]]; then
            echo "Error: Failed to create veth pair"
            return 1
        fi
    else
        echo "veth pair $EXT_IF already exists"
        # Check if internal interface exists
        if ! ip link show $TMP_INT_IF > /dev/null 2>&1; then
            echo "Error: Temporary internal interface $TMP_INT_IF does not exist"
            echo "Recreating veth pair $EXT_IF <-> $TMP_INT_IF"
            # Delete existing external interface
            ip link delete $EXT_IF
            # Recreate veth pair
            ip link add $EXT_IF type veth peer name $TMP_INT_IF
            if [[ $? -ne 0 ]]; then
                echo "Error: Failed to create veth pair"
                return 1
            fi
        fi
    fi

    # Add external interface to mgmt_bridge
    if ! brctl show $MGMT_BRIDGE | grep -q $EXT_IF; then
        echo "Adding $EXT_IF to bridge $MGMT_BRIDGE"
        brctl addif $MGMT_BRIDGE $EXT_IF
        if [[ $? -ne 0 ]]; then
            echo "Error: Failed to add interface to bridge"
            return 1
        fi
    else
        echo "Interface $EXT_IF is already in bridge $MGMT_BRIDGE"
    fi

    # Enable external interface
    ip link set $EXT_IF up

    # Move temporary internal interface to PTF container's network namespace
    if ! ip link show $TMP_INT_IF > /dev/null 2>&1; then
        echo "Error: Temporary internal interface $TMP_INT_IF does not exist"
        return 1
    fi

    echo "Moving temporary interface $TMP_INT_IF to PTF container's network namespace"
    ip link set $TMP_INT_IF netns $PTF_PID
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to move interface to container namespace"
        return 1
    fi

    # Rename and configure interface inside PTF container's network namespace
    echo "Configuring interface $INT_IF in PTF container"
    nsenter -t $PTF_PID -n ip link set $TMP_INT_IF name $INT_IF
    nsenter -t $PTF_PID -n ip link set $INT_IF up
    nsenter -t $PTF_PID -n ip addr add $PTF_IP dev $INT_IF
    nsenter -t $PTF_PID -n ip route add default via $MGMT_GW dev $INT_IF

    # Configure DNS
    # Preserve existing DNS configuration and append new DNS servers
    if [[ -n "$DNS_SERVERS" ]]; then
        echo "Configuring custom DNS servers: $DNS_SERVERS"
        # Backup original resolv.conf
        nsenter -t $PTF_PID -n cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
        # Append custom DNS servers
        for dns in $DNS_SERVERS; do
            nsenter -t $PTF_PID -n bash -c "echo 'nameserver $dns' >> /etc/resolv.conf"
        done
    else
        # No custom DNS provided, check if existing DNS configuration is present
        existing_dns=$(nsenter -t $PTF_PID -n grep -c "^nameserver" /etc/resolv.conf 2>/dev/null || echo "0")
        if [[ "$existing_dns" -eq 0 ]]; then
            echo "No existing DNS configuration found, adding Google Public DNS"
            nsenter -t $PTF_PID -n bash -c "echo 'nameserver 8.8.8.8' >> /etc/resolv.conf"
            nsenter -t $PTF_PID -n bash -c "echo 'nameserver 8.8.4.4' >> /etc/resolv.conf"
        else
            echo "Existing DNS configuration preserved ($existing_dns nameservers found)"
        fi
    fi

    # Test connectivity
    echo "Testing connectivity from PTF container to gateway $MGMT_GW"
    if nsenter -t $PTF_PID -n ping -c 3 $MGMT_GW > /dev/null 2>&1; then
        echo "Connectivity test succeeded!"
    else
        echo "Warning: Connectivity test failed, please check network configuration"
    fi

    # Display PTF container network configuration
    echo "PTF container network configuration:"
    nsenter -t $PTF_PID -n ifconfig
    echo "PTF container routing table:"
    nsenter -t $PTF_PID -n ip route
    echo
}

# Bridge server physical interface to mgmt_bridge
bridge_server_interface() {
    if [[ -z "$SERVER_INTERFACE" ]]; then
        echo "Warning: Server physical interface not specified, skipping bridging step"
        return 0
    fi

    echo "=== Bridging server physical interface ==="
    echo "Server physical interface: $SERVER_INTERFACE"

    # Check if interface exists
    if ! ip link show $SERVER_INTERFACE > /dev/null 2>&1; then
        echo "Error: Server physical interface $SERVER_INTERFACE does not exist"
        return 1
    fi

    # Check if interface is already in the bridge
    if brctl show $MGMT_BRIDGE | grep -q $SERVER_INTERFACE; then
        echo "Interface $SERVER_INTERFACE is already in bridge $MGMT_BRIDGE"
        return 0
    fi

    # Check if interface is in another bridge
    echo "Checking if interface $SERVER_INTERFACE is in another bridge"
    for bridge in $(brctl show | grep -v "^bridge name" | awk '{print $1}'); do
        if [[ "$bridge" != "$MGMT_BRIDGE" ]] && brctl show $bridge | grep -q $SERVER_INTERFACE; then
            echo "Error: Interface $SERVER_INTERFACE is already in bridge $bridge, cannot add to multiple bridges"
            return 1
        fi
    done

    # Save original IP configuration of the interface
    echo "Saving original IP configuration of interface $SERVER_INTERFACE"
    ORIGINAL_IP=$(ip addr show $SERVER_INTERFACE | grep -E 'inet\s+' | awk '{print $2}')
    ORIGINAL_GW=$(ip route show default | grep -E "dev\s+$SERVER_INTERFACE" | awk '{print $3}')

    echo "Original IP: $ORIGINAL_IP"
    echo "Original gateway: $ORIGINAL_GW"

    # Validate that we have valid original configuration before proceeding
    if [[ -z "$ORIGINAL_IP" ]]; then
        echo "Warning: Could not determine original IP address of $SERVER_INTERFACE"
        echo "Proceeding with caution - rollback may not be possible"
    fi

    # Mark that rollback will be required from this point
    ROLLBACK_REQUIRED=true

    # Disable interface
    echo "Disabling interface $SERVER_INTERFACE"
    ip link set $SERVER_INTERFACE down

    # Add interface to mgmt_bridge
    echo "Adding $SERVER_INTERFACE to bridge $MGMT_BRIDGE"
    if ! brctl addif $MGMT_BRIDGE $SERVER_INTERFACE; then
        echo "Error: Failed to add server interface to bridge"
        # Re-enable interface
        ip link set $SERVER_INTERFACE up
        ROLLBACK_REQUIRED=false
        return 1
    fi

    # Enable interface
    echo "Enabling interface $SERVER_INTERFACE"
    ip link set $SERVER_INTERFACE up

    # Enable bridge
    echo "Enabling bridge $MGMT_BRIDGE"
    if ! ip link set $MGMT_BRIDGE up; then
        echo "Error: Failed to enable bridge $MGMT_BRIDGE"
        return 1
    fi

    # Enable STP (Spanning Tree Protocol) to prevent network loops
    echo "Enabling STP on bridge $MGMT_BRIDGE"
    brctl stp $MGMT_BRIDGE on

    # Configure IP address on bridge (CRITICAL STEP - after this point, network may be disrupted)
    if [[ -n "$ORIGINAL_IP" ]]; then
        if ! ip addr show $MGMT_BRIDGE | grep -q 'inet\s+'; then
            echo "Configuring IP address on bridge $MGMT_BRIDGE: $ORIGINAL_IP"
            if ! ip addr add $ORIGINAL_IP dev $MGMT_BRIDGE; then
                echo "Error: Failed to add IP address to bridge"
                echo "Attempting immediate rollback..."
                return 1
            fi
        fi
    fi

    # Add default route (CRITICAL STEP)
    if [[ -n "$ORIGINAL_GW" ]]; then
        if ! ip route show default | grep -q "dev\s+$MGMT_BRIDGE"; then
            echo "Adding default route on bridge $MGMT_BRIDGE: $ORIGINAL_GW"
            if ! ip route add default via $ORIGINAL_GW dev $MGMT_BRIDGE; then
                echo "Error: Failed to add default route"
                echo "Attempting immediate rollback..."
                return 1
            fi
        fi
    fi

    # Clear IP address from physical interface (POINT OF NO RETURN)
    # After this step, the physical interface no longer has an IP address
    if [[ -n "$ORIGINAL_IP" ]]; then
        echo "Clearing IP address from interface $SERVER_INTERFACE"
        ip addr flush dev $SERVER_INTERFACE
        echo "Network configuration migration completed successfully"
        echo "Interface $SERVER_INTERFACE is now part of bridge $MGMT_BRIDGE"
    fi

    # Display STP status
    echo "STP status of bridge $MGMT_BRIDGE:"
    brctl showstp $MGMT_BRIDGE | grep -E "(stp|forwarding)"
    echo

    # Display bridge status
    echo "Bridge $MGMT_BRIDGE status:"
    brctl show $MGMT_BRIDGE

    # Display current network configuration
    echo "Current network configuration:"
    ip addr show $MGMT_BRIDGE
    ip route show
    echo
}

# Main function
main() {
    # Setup trap for rollback mechanism
    setup_trap

    # Parse command line arguments
    parse_args "$@"

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root"
        exit 1
    fi

    # Execute steps
    echo "=== Starting PTF network configuration ==="
    
    create_mgmt_bridge
    
    if ! configure_ptf_network; then
        echo "=== PTF network configuration failed at configure_ptf_network step ==="
        exit 1
    fi
    
    if ! bridge_server_interface; then
        echo "=== PTF network configuration failed at bridge_server_interface step ==="
        exit 1
    fi
    
    echo "=== PTF network configuration completed successfully ==="
    # Mark script as completed successfully to prevent rollback
    SCRIPT_EXITED=1
    ROLLBACK_REQUIRED=false
}

# Run main function
main "$@"
