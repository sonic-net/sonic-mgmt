#!/bin/bash

set -euo pipefail

INTF_IDX_LIST=$(cat /proc/net/dev | grep eth | awk -F'eth|:' '{print $2}')

for i in ${INTF_IDX_LIST}; do
  echo "Flush eth${i} IP address"
  ip address flush dev eth$i
done
