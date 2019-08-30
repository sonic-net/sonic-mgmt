#!/bin/bash

set -e

for INTF in $(ip -br link show | grep 'eth' | awk '{sub(/@.*/,"",$1); print $1}'); do
    ADDR="$(ip -br link show dev ${INTF} | awk '{print $3}')"
    PREFIX="$(cut -c1-15 <<< ${ADDR})"
    SUFFIX="$(printf "%02x" ${INTF##eth})"
    MAC="${PREFIX}${SUFFIX}"

    echo "Update ${INTF} MAC address: ${ADDR}->$MAC"
    ip link set dev ${INTF} address ${MAC}
done
