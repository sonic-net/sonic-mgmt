#!/bin/bash

set -euo pipefail

INTF_LIST=$(ifconfig | grep eth | cut -f 1 -d ' ')

for i in ${INTF_LIST}; do
  prefix=$(ifconfig $i | grep HWaddr | cut -c39-53)
  suffix=$( printf "%02x" ${i##eth})
  mac=$prefix$suffix
  echo $i $mac
  ifconfig $i hw ether $mac
done
