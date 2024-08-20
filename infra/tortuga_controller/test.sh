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

# Vrf40000 is automatically created by Tortuga when a L2VNI + SAG
# is added to the fabric.
SUBINFS1x3="Vrf40000|*|Ethernet1_9|eth1|lo|0"
RELAYS1x3="Vrf40000|relay1|5.1.30.1|5010#5020"
RELAYS1x3="*"
BGPPEERS1x3="Vrf40000|bgp1#5.1.30.1#4000#65200"
BGPPEERS1x3="*"
ROUTES1x3="Vrf40000|5.1.1.0/24|41.220.1.1|leaf1|Ethernet1_32_1"
#ROUTES1x3="${ROUTES1x3},Vrf40000|6.6.6.0/24|blackhole"
PORTS1x3="leaf1|Ethernet1_32_1#41.220.1.2/24#Vrf40000"

CONFIG_GEN=./config-gen
os=$(uname)
if [[ "${os}" == "Darwin" ]]; then
  CONFIG_GEN=./sandbox/gobin/config-gen
fi

CLOUD_URL=https://tortuga-k8s-a.cisco.com:32398
START_TIME=$(date +%s)
TEST_TAGS=sonic-test
CGEN_TEST=extended
ORG_NAME="Test"

# Disable SSH based pre/post checks in prod mode.
if [[ "${TEST_NAME}" == "prod" ]]; then
  TEST_TAGS="${TEST_TAGS},no-ssh"
  TEST_NAME=""
fi

set -euo pipefail

function cleanup() {
  "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}" --orgName "${ORG_NAME}" --timeout "90s"
  echo
  echo "-------------------------Running ${1}-------------------------"
  echo
}

# Tests static anycast gateway.
# L2VNI 5100 + Vlan10 - one port per leaf; IP = 41.216.0.1/24
# L2VNI 5200 + Vlan20 - one port per leaf; IP = 41.216.1.1/24
# L2VNI 5300 + Vlan30 - one port per leaf; IP = 41.216.2.1/24
# All Vlans are added to Vrf12000000 initially. Test then moves them to
# a new Vrf40000.
# L3VNI 40000 + VRF + [Vlan10, Vlan20, Vlan30, Vlan3600]
# All hosts should be able to ping each other.
if [[ "${TEST_NAME}" == "all" ]] || [[ -z "${TEST_NAME}" ]]; then
  cleanup "static-anycast-gateway"

  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --orgName "${ORG_NAME}" \
    --test "${CGEN_TEST}" \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --spines "${SPINE_COUNT}" \
    --leaves "${LEAF_PORTS}" \
    --hosts "${HOST_PORTS}" \
    --dhcpRelays "${RELAYS1x3}" \
    --bgpPeers "${BGPPEERS1x3}" \
    --subInterfaces "${SUBINFS1x3}" \
    --ports "${PORTS1x3}" \
    --routes "${ROUTES1x3}" \
    --tags "${TEST_TAGS},add-sag,ipv4,ipv6,l3vni,loopback"
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
    --orgName "${ORG_NAME}" \
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

