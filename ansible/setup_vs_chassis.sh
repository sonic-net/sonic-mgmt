#!/bin/bash

# Define variables
platform="x86_64-kvm_x86_64-r0"
metadata_file="/etc/sonic/vs_chassis_metadata.json"
updategraph_file="/etc/sonic/updategraph.conf"
minigraph_input_file="/etc/sonic/minigraph.xml"
minigraph_output_file="/etc/sonic/minigraph.xml"
remove_macsec_script="/usr/local/bin/remove_macsec.py"
rc_local_file="/etc/rc.local"
platform_dir="/usr/share/sonic/device/$platform"
platform_chassisdb_conf_file="$platform_dir/chassisdb.conf"
chassis_db_address=10.6.0.100
midplane_subnet=10.6.0.0/16
num_asic=1
services=("swss" "syncd" "bgp" "teamd" "gbsyncd" "database" "lldp")
platform_env_file="$platform_dir/platform_env.conf"
macsec_supported_arista_hwskus=("Arista-7800R3AK-36DM2-*" "Arista-7800R3AK-36D2-*" "Arista-7800R3A-36P-*" "Arista-7800R3A-36DM2-*" "Arista-7800R3A-36D-*" "Arista-7800R3A-36D2-*")
macsec_supported_nokia_hwskus=("Nokia-IXR7250E-36x100G" "Nokia-IXR7250E-36x400G")

# Usage: match_pattern "string" "${pattern_list[@]}"
match_pattern() {
    local string="$1"
    shift
    local pattern_list=("$@")

    for pattern in "${pattern_list[@]}"; do
        case $string in
            $pattern) return 0;; # Match found
        esac
    done

    return 1 # No match found
}

# Function to extract values from metadata using jq
extract_metadata() {
    local field=$1
    jq -r ".$field" "$metadata_file"
}

# Function to check if a directory exists
check_directory() {
    local directory=$1
    if [ ! -d "$directory" ]; then
        echo "Directory not found: $directory"
        exit 1
    fi
}

# Function to remove an existing file
remove_existing_file() {
    local file=$1
    if [ -f "$file" ]; then
        rm "$file"
        echo "Deleted existing file: $file"
    fi
}

# Function to get NUM_ASIC
get_num_asic() {
    local asic_conf_file="$1"
    if [ -f "$asic_conf_file" ]; then
        num_asic_new=$(awk -F "=" '/^NUM_ASIC=/ {print $2}' "$asic_conf_file")
        if [ -n "$num_asic" ]; then
            echo "NUM_ASIC found in $asic_conf_file: $num_asic"
            num_asic=$num_asic_new
        else
            echo "NUM_ASIC not found in $asic_conf_file"
            exit 1
        fi
    else
        echo "asic.conf file not found $asic_conf_file"
    fi
}

# Function to update NUM_ASIC in platform ASIC configuration file
update_asic_conf() {
    local file="$1"
    if [ -f "$file" ]; then
        sed -i "s/^NUM_ASIC=.*/NUM_ASIC=$num_asic/" "$file"
        echo "NUM_ASIC: $num_asic updated in $file"
    else
        echo "NUM_ASIC=$num_asic" > "$file"
        echo "Created $file with NUM_ASIC=$num_asic"
    fi
}

# Function to add commands to rc.local
add_commands_to_rc_local() {
    local slot_num="$1"
    local num_asic="$2"
    sed -i "s/^exit 0/sudo ip link set dev eth1 down\nsudo ip link set dev eth1 name eth1-midplane\nsudo ip address add 10.6.$slot_num.100\/16 dev eth1-midplane\nsudo ip link set dev eth1-midplane up\n\nexit 0/" "$rc_local_file"
    echo "Added commands to rename eth1 to eth1-midplane and added midplane ip: 10.6.$slot_num.100/16 in $rc_local_file"

    # if linecard and num_asic==1, rename the last port to Cpu0
    if [ "$is_linecard" = true ] && [ "$num_asic" -eq 1 ]; then
        lanemap_file="$hwsku_dir/lanemap.ini"
        if [ ! -f "$lanemap_file" ]; then
            echo "lanemap.ini file not found: $lanemap_file"
            exit 1
        fi
        #read the last line of lanemap.ini file, if it contains Cpu0, then rename the prev_port+1 to Cpu0
        last_port=$(tail -n 1 "$lanemap_file" | cut -d ":" -f 1)
        prev_port=$(tail -n 2 "$lanemap_file" | head -n 1 | cut -d ":" -f 1)
        if [ "$last_port" = "Cpu0" ]; then
            # Extract the numeric part of the interface name
            num="${prev_port#eth}"
            # Increment the numeric part
            ((num++))
            # Construct the new interface name
            cur_port="eth$num"
            echo "Renaming $cur_port to $last_port"

            sed -i "s/^exit 0/sudo ip link set dev $cur_port down\nsudo ip link set dev $cur_port name $last_port\nsudo ip link set dev $last_port up\n\nexit 0/" "$rc_local_file"
            echo "Added command to rename $cur_port to $last_port in $rc_local_file"
        fi
    fi
}

# Function to stop and disable services
stop_disable_services() {
    local num_asic="$1"
    if [ "$num_asic" -gt 1 ]; then
        for service in "${services[@]}"; do
            echo "Stop/Disable/Mask $service"
            sudo systemctl stop "$service"
            sudo systemctl disable "$service"
            sudo systemctl mask "$service"
            sudo docker rm "$service"
        done
    fi
}

# Function to set up midplane address and wait for supervisor
setup_midplane_and_wait_for_supervisor() {
    local slot_num="$1"
    if [ "$is_linecard" = true ]; then
        echo "Setting up midplane address for linecard: $slot_num"
        sudo ip -d addr show eth1
        sudo ip link set up dev eth1
        sudo ip addr add 10.6.$slot_num.100/16 dev eth1

        echo "Waiting for supervisor to become reachable"
        counter=0
        while [! ping -c 1 10.6.0.100 &> /dev/null && counter <= 300]; do
            counter=$((counter+1))
            if [ $((counter%5)) -eq 0 ]; then
                echo "Still waiting for supervisor to become reachable"
            fi
            sleep 1
        done
        echo "Supervisor is reachable"
    else
        sudo ip -d addr show eth1
        sudo ip link set up dev eth1
        sudo ip addr add 10.6.$slot_num.100/16 dev eth1
        echo "Supervisor is up on midplane"
    fi
}

# Main script

# Check if the metadata file exists
if [ ! -f "$metadata_file" ]; then
    echo "Metadata file not found: $metadata_file"
    exit 1
fi

# Disable Macsec Profile in minigraph
if [ -f "$minigraph_input_file" ] && [ -f "$remove_macsec_script" ]; then
    python3 $remove_macsec_script "$minigraph_input_file" "$minigraph_output_file"

    if [ $? -eq 0 ]; then
        echo "MacsecProfile successfully removed from $minigraph_output_file"
    else
        echo "Error: remove_macsec.py execution failed."
    fi
fi

# Disable DHCP Graph update service if enabled
if [ -f "$updategraph_file" ]; then
    sudo sed -i 's/enabled=true/enabled=false/g' $updategraph_file
    echo "Disabled updategraph service"
fi

# Read metadata values
is_chassis=$(extract_metadata "is_chassis")
is_supervisor=$(extract_metadata "is_supervisor")
is_linecard=$(extract_metadata "is_linecard")
sup_slot_num=$(extract_metadata "sup_slot_num")
lc_slot_num=$(extract_metadata "lc_slot_num")
hw_sku=$(extract_metadata "hw_sku")

# Display the extracted metadata
echo "is_chassis: $is_chassis"
echo "is_supervisor: $is_supervisor"
echo "is_linecard: $is_linecard"
echo "sup_slot_num: $sup_slot_num"
echo "lc_slot_num: $lc_slot_num"
echo "hw_sku: $hw_sku"

# Check if the platform directory exists
check_directory "$platform_dir"

# Check if the directory exists for the specified hardware SKU
hwsku_dir="/usr/share/sonic/device/$platform/$hw_sku"
check_directory "$hwsku_dir"

# Set NUM_ASIC if the device is a linecard
if [ "$is_linecard" = true ]; then
    asic_conf_file="$hwsku_dir/asic.conf"
    get_num_asic "$asic_conf_file"
fi

# Update NUM_ASIC in platform ASIC configuration file
update_asic_conf "$platform_dir/asic.conf"

# Remove existing chassisdb.conf file
remove_existing_file "$platform_chassisdb_conf_file"

# Configure chassisdb.conf file
if [ "$is_supervisor" = true ]; then
    echo "start_chassis_db=1" > "$platform_chassisdb_conf_file"
    echo "chassis_db_address=$chassis_db_address" >> "$platform_chassisdb_conf_file"
    echo "midplane_subnet=$midplane_subnet" >> "$platform_chassisdb_conf_file"
    echo "lag_id_start=1" >> "$platform_chassisdb_conf_file"
    echo "lag_id_end=1024" >> "$platform_chassisdb_conf_file"
    echo "Created $platform_chassisdb_conf_file for supervisor"
else
    echo "chassis_db_address=$chassis_db_address" > "$platform_chassisdb_conf_file"
    echo "midplane_subnet=$midplane_subnet" >> "$platform_chassisdb_conf_file"
    echo "Created $platform_chassisdb_conf_file for linecard"
fi

# Set macsec_enabled in platform_env.conf if the hardware SKU is supported
if match_pattern "$hw_sku" "${macsec_supported_arista_hwskus[@]}" || match_pattern "$hw_sku" "${macsec_supported_nokia_hwskus[@]}"; then
    echo "macsec_enabled=1" > "$platform_env_file"
    echo "Enabled MACsec in $platform_env_file for hwsku: $hw_sku"
fi

# Set supversor in platform_env.conf if the device is marked as supervisor
if [ "$is_supervisor" = true ]; then
    echo "supervisor=1" > "$platform_env_file"
fi

slot_num=0
if [ "$is_supervisor" = true ]; then
    slot_num=$sup_slot_num
else
    slot_num=$lc_slot_num
fi
# Add commands to rc.local
add_commands_to_rc_local "$slot_num" "$num_asic"

# Stop and disable services
stop_disable_services "$num_asic"
# Unmask database since it is needed
sudo systemctl unmask database

# Set up midplane address and wait for supervisor
setup_midplane_and_wait_for_supervisor "$slot_num"
