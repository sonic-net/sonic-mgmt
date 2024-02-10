#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2024 Cisco Systems, Inc., All rights reserved.

FABRIC_NAME=tortuga-1x3
PYVXR_HOST=tortuga-1x3.cisco.com
HOST_PORTS=57291,41157,44799,55603,52097,52411,56183,57277,40323
LEAF_PORTS=40361,41899,40815

CONFIG_GEN=./config-gen
os=$(uname)
if [[ "${os}" == "Darwin" ]]; then
  CONFIG_GEN=./config-gen-mac-arm64
fi

CLOUD_URL=https://tortuga-k8s-a.cisco.com:32398
START_TIME=$(date +%s)
TEST_TAGS=ipv6-drake,ipv6-evpn

set -euo pipefail

"${CONFIG_GEN}" \
    --reset \
    --lldp \
    --auto \
    --prefix \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --hosts "${HOST_PORTS}" \
    --spines 1 \
    --leaves "${LEAF_PORTS}" \
    --tags "${TEST_TAGS}"

end=$(date +%s)
stm=$((end-START_TIME))
echo
echo "Completed in ${stm}s"
echo

