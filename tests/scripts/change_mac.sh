#!/bin/bash

set -euo pipefail

INTF_LIST=$(ls /sys/class/net | grep -E "^eth[0-9]+$")

for INTF in ${INTF_LIST}; do
    ADDR="$(ip link show ${INTF} | grep ether | awk '{print $2}')"
    PREFIX="$(cut -c1-15 <<< ${ADDR})"
    SUFFIX="$(printf "%02x" ${INTF##eth})"
    MAC="${PREFIX}${SUFFIX}"

    echo "Update ${INTF} MAC address: ${ADDR}->$MAC"
    ip link set dev ${INTF} address ${MAC}
done
