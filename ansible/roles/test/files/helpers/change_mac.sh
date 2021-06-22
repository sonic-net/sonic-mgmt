#!/bin/bash

set -euo pipefail

INTF_LIST=$(ls /sys/class/net | grep -E "^eth[0-9]+$")

for INTF in ${INTF_LIST}; do
    ADDR="$(cat /sys/class/net/${INTF}/address)"
    PREFIX="$(cut -c1-15 <<< ${ADDR})"
    SUFFIX="$(printf "%02x" ${INTF##eth})"
    MAC="${PREFIX}${SUFFIX}"

    echo "Update ${INTF} MAC address: ${ADDR}->$MAC"
    # bringing the device down/up to trigger ipv6 link local address change
    ip link set dev ${INTF} down
    ip link set dev ${INTF} address ${MAC}
    ip link set dev ${INTF} up
done
