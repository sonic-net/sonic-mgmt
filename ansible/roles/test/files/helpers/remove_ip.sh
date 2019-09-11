#!/bin/bash

set -euo pipefail

INTF_LIST=$(ip -br link show | grep 'eth' | awk '{sub(/@.*/,"",$1); print $1}')

for INTF in ${INTF_LIST}; do
    echo "Flush ${INTF} IP address"
    ip addr flush dev ${INTF}
done
