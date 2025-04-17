#!/bin/bash

set -euo pipefail

INTF_LIST=$(ls /sys/class/net | grep -E "^eth[0-9]+$")

for INTF in ${INTF_LIST}; do
    ADDR="$(cat /sys/class/net/${INTF}/address)"
    PREFIX="$(cut -c1-13 <<< ${ADDR})"
    INTF_ID=${INTF##eth}
    SUFFIX="$(printf "%x:%02x" $(expr ${INTF_ID} / 256) $(expr ${INTF_ID} % 256))"
    MAC="${PREFIX}${SUFFIX}"

    echo "Update ${INTF} MAC address: ${ADDR}->$MAC"
    # bringing the device down/up to trigger ipv6 link local address change
    ip link set dev ${INTF} down
    ip link set dev ${INTF} address ${MAC}
    ip link set dev ${INTF} up
done
