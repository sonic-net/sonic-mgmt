#!/bin/bash -ex

# Test for the issue #19 (https://github.com/Azure/SONiC/issues/19)
# H/w config:
#    +--------+      +-------+
#    |  Host  X<---->Y  DUT  |
#    +--------+      +-------+
#
# S/w config:
# iface            - the name of the interface X
# dut_host         - ip/hostname of the DUT management interface
# dut_connected_ip - ip/hostname on the interface Y
# dut_user         - user on DUT (capable to run docker, has Host in known_hosts
# Call syntax:
# neigh_test.sh admin arc-switch1027 20.0.0.1 20.0.0.2
#                $1        $2           $3      $4

# default values
iface=eth2
iface_ip=20.0.0.2
dut_host=arc-switch1027
dut_connected_ip=20.0.0.1
dut_user=admin

mac1=00:c0:ca:c0:1a:05
mac2=00:c0:ca:c0:1a:06

if [ ! -z $4 ]; then
    iface_ip=$4
fi

if [ ! -z $3 ]; then
    dut_connected_ip=$3
fi

if [ ! -z $2 ]; then
    dut_host=$2
fi

if [ ! -z $1 ]; then
    dut_user=$1
fi

mac1=00:c0:ca:c0:1a:05
mac2=00:c0:ca:c0:1a:06

function ping_dut()
{
    ping ${dut_connected_ip} -c 3 -I ${iface} >/dev/null;
}

# get mac of given interface
# $1 interface to get mac on
# ret: mac as string
function get_mac()
{
    local mac=`ifconfig ${1} | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`
    #read mac < /sys/class/net/${1}/address
    #ifconfig ${1} | grep ether | awk '{print $2}' net-tools > 2.0
    echo ${mac};
}

# set mac on local interface
# $1 - interface
# $2 - mac to set
function set_mac()
{
    ifconfig ${1} down; ifconfig ${1} hw ether ${2}; ifconfig ${1} up;
}

# get neighbour mac from SAI DB for given ip
# $1 - ip of the neighbour
# ret: 1 - not found
#      0 - success
function get_neighbour_mac()
{
    # convert ip to hex format (20.0.0.2 -> 14000002)
    iface_ip_hex=`printf '%02X' ${iface_ip//./ }`
    # grep redis DB to find a key holding data for the neighbour with this IP
    key=`ssh ${dut_user}@${dut_host} "bash -c 'docker exec database redis-cli -n 1 KEYS ASIC* ' | grep -i ${iface_ip_hex}"`
    #echo $key; echo
    # NEIGHBOUR_DST_MAC_ADDRESS attribute code is 0, so using key 00000000
    mac=`ssh ${dut_user}@${dut_host} "bash -c 'docker exec database redis-cli -n 1 HGET ${key} 00000000'"`
    echo ${mac}
}

# save host's mac
host_mac=$(get_mac ${iface})

# populate neighbour #1
set_mac ${iface} ${mac1}
ping_dut

# check neighbour #1
neigh_mac=$(get_neighbour_mac ${iface_ip})
if [ $neigh_mac != ${mac1//:/} ]; then
    echo "Neighbour mac set failed"
    exit 1
fi

# populate neighbour #2 (ip will remain the same)
set_mac ${iface} ${mac2}
ping_dut

# chech neighbour's mac changed
neigh_mac=$(get_neighbour_mac ${iface_ip})
if [ $neigh_mac != ${mac2//:/} ]; then
    echo "Neighbour mac update failed"
    exit 1
fi

# restore host mac address
set_mac ${iface} ${host_mac}

exit 0
