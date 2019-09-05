#!/bin/bash

set -e

ppm_map_file="/tmp/ptf_ports_mmp.json"
echo -n "{" > $ppm_map_file
for INTF in $(ip -br link show | grep 'eth' | awk '{sub(/@.*/,"",$1); print $1}'); do
    if [ ${INTF##eth} != 0 ]
    then
        echo -n "," >> $ppm_map_file
    fi
    
    ADDR="$(ip -br link show dev ${INTF} | awk '{print $3}')"
    PREFIX="$(cut -c1-15 <<< ${ADDR})"
    SUFFIX="$(printf "%02x" ${INTF##eth})"
    MAC="${PREFIX}${SUFFIX}"

    echo "Update ${INTF} MAC address: ${ADDR}->$MAC"
    ip link set dev ${INTF} address ${MAC}
    
    echo -n "\"${INTF##eth}\": \"${MAC}\"" >> $ppm_map_file
done
echo -n "}" >> $ppm_map_file
