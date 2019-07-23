#!/bin/bash

set -e

for INTF in $(ip -br link show | grep 'eth' | awk '{sub(/@.*/,"",$1); print $1}'); do
    echo "Flush ${INTF} IP address"
    ip addr flush dev ${INTF}
done
