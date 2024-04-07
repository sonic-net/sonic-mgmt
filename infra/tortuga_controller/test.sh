#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2024 Cisco Systems, Inc., All rights reserved.

# NOTES: To test a different PyVxr topology than 1x3, do the following.
# - Set fabric name to new PyVxr topology fabric name (E.g. my-fabric-2x3)
# - Set HOST_PORTS
# - Set LEAF_PORTS
# - Set SPINE_PORTS (E.g. 2 for 2x3)
#
FABRIC_NAME=tortuga-1x3
PYVXR_HOST=tortuga-1x3.cisco.com
HOST_PORTS=57291,41157,44799,55603,52097,52411,56183,57277,40323
LEAF_PORTS=40361,41899,40815
SPINE_COUNT=1
TEST_NAME="${1}"

CONFIG_GEN=./config-gen
os=$(uname)
if [[ "${os}" != "Linux" ]]; then
  echo 'Must run from a Linux machine'
  exit 1
fi

CLOUD_URL=https://tortuga-k8s-a.cisco.com:32398
START_TIME=$(date +%s)
TEST_TAGS=sonic-test

set -euo pipefail

function cleanup() {
  "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}"
  sleep 20
  "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}"
  echo
  echo "-------------------------Running ${1}-------------------------"
  echo
}

# Tests static anycast gateway.
# L2VNI 5100 + Vlan10 - one port per leaf; IP = 41.216.0.1/24
# L2VNI 5200 + Vlan20 - one port per leaf; IP = 41.216.1.1/24
# L2VNI 5300 + Vlan30 - one port per leaf; IP = 41.216.2.1/24
# L3VNI 12000000 + VRF-default + [Vlan10, Vlan20, Vlan30, Vlan3600]
# All hosts should be able to ping each other.
if [[ "${TEST_NAME}" == "all" ]] || [[ -z "${TEST_NAME}" ]]; then
  cleanup "static-anycast-gateway"

  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --hosts "${HOST_PORTS}" \
    --spines "${SPINE_COUNT}" \
    --leaves "${LEAF_PORTS}" \
    --tags "${TEST_TAGS},add-sag"
fi

# Test multi-VNI with single vlan in each VNI.
# L3VNI 5100 + VRF + Vlan10, Vlan3600 - one port per leaf; IP = 41.216.0.1/24
# L3VNI 5200 + VRF + Vlan20, Vlan3601 - one port per leaf; IP = 41.216.10.1/24
# L3VNI 5300 + VRF + Vlan30, Vlan3602 - one port per leaf; IP = 41.216.20.1/24
if [[ "${TEST_NAME}" == "all" ]] || [[ "${TEST_NAME}" == "l3vni" ]]; then
  cleanup "multiple-l3vni"

  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --hosts "${HOST_PORTS}" \
    --spines "${SPINE_COUNT}" \
    --leaves "${LEAF_PORTS}" \
    --tags "${TEST_TAGS}"
fi

# Tests static anycast gateway.
# L2VNI 5100 + Vlan10 - one port per leaf; IP = 41.216.0.1/24
# L2VNI 5200 + Vlan20 - one port per leaf; IP = 41.216.1.1/24
# L2VNI 5300 + Vlan30 - one port per leaf; IP = 41.216.2.1/24
# L3VNI 40000 + VRF + [Vlan10, Vlan20, Vlan30, Vlan3600]
# All hosts should be able to ping each other.
if [[ "${TEST_NAME}" == "all" ]] || [[ "${TEST_NAME}" == "sag" ]]; then
  cleanup "sag-l3vni"

  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --hosts "${HOST_PORTS}" \
    --spines "${SPINE_COUNT}" \
    --leaves "${LEAF_PORTS}" \
    --sagMac "00:11:22:33:44:55" \
    --tags "${TEST_TAGS},add-sag,ipv6-l3vni"
fi

# Test one Vni and multiple Vlans.
# E.g. VNI 5100 - Vlan 10 - one port per leaf
#                 Vlan 20 - one port per leaf
#                 VRF
if [[ "${TEST_NAME}" == "all" ]] || [[ "${TEST_NAME}" == "one-vni" ]]; then
  cleanup "one-vni"

  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --test "one-vni" \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --hosts "${HOST_PORTS}" \
    --spines "${SPINE_COUNT}" \
    --leaves "${LEAF_PORTS}" \
    --tags "${TEST_TAGS}"
fi

# Tests one Vni and one Vlan.
# E.g. VNI 5100 - Vlan 10 - multiple ports per leaf
#                 VRF
if [[ "${TEST_NAME}" == "all" ]] || [[ "${TEST_NAME}" == "one-vlan" ]]; then
  cleanup "one-vlan"

  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --test "one-vlan" \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --hosts "${HOST_PORTS}" \
    --spines "${SPINE_COUNT}" \
    --leaves "${LEAF_PORTS}" \
    --tags "${TEST_TAGS}"
fi

end=$(date +%s)
stm=$((end-START_TIME))
echo
echo "Completed in ${stm}s"
echo

