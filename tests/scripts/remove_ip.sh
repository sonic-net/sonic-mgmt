#!/bin/bash

set -euo pipefail

INTF_LIST=$(ls /sys/class/net | grep eth)

for INTF in ${INTF_LIST}; do
    echo "Flush ${INTF} IP address"
    ip addr flush dev ${INTF}
done
