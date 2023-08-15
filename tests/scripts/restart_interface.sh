#!/bin/bash

set -euo pipefail

INTF_LIST=$(ls /sys/class/net | grep -E "^eth[0-9]+(\.[0-9]+)?$")

for INTF in ${INTF_LIST}; do
    echo "Restart interface: ${INTF}"
    ifconfig "${INTF}" down
    ifconfig "${INTF}" up
done
