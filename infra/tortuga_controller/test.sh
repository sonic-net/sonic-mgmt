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
HOST_PORTS=40409,39855,36427,41851,49665,56787,35027,56005,51299
LEAF_PORTS=43039,45263,52467
SPINE_PORTS=43541

CONFIG_GEN=./config-gen
os=$(uname)
if [[ "${os}" == "Darwin" ]]; then
  CONFIG_GEN=./sandbox/gobin/config-gen
fi

# Common static routes, sub-interfaces and routed port configs for PyVxr setups.
# Vrf40000 is automatically created by Tortuga when a L2VNI + SAG is added.
PYVXR_ROUTES="Vrf12000000|6.6.6.0/24#blackhole"
PYVXR_PORTS="leaf0|Ethernet1_32_1#41.230.10.2/24#Vrf12000000"
PYVXR_SUBINFS="Vrf40000|*|Ethernet1_11|eth1|lo|2"
PYVXR_DHCPS="*"
PYVXR_BGPPEERS="*"
PYVXR_CHANNELS="*"
PYVXR_VRFS="*"
CLOUD_URL=https://tortuga-k8s-a.cisco.com:32398
START_TIME=$(date +%s)
TEST_TAGS="sonic-test,beta2,ipv4,ipv6,loopback,mlag-esi,mlag-port"
CGEN_TEST=extended
ORG_NAME="Test"
HOST_USER="vxr"
LAG=true
MLAG=true

# Disable SSH based pre/post checks in prod mode.
if [[ "${1}" == "-prod" ]]; then
  TEST_TAGS="${TEST_TAGS},no-ssh"
elif [[ "${1}" == "-nolag" ]]; then
  LAG=false
  MLAG=false
fi

if [[ "${LAG}" == true ]]; then
  PYVXR_CHANNELS="PortChannel0|leaf0:Ethernet1_9#leaf0:Ethernet1_12|10|false|eth1#eth2"
  LENGTH=$(echo "${LEAF_PORTS}" | tr -cd , | wc -c)

  # Add MLAG on [first, second] leaves.
  if [[ ${LENGTH} -gt 0 ]]; then
    if [[ "${MLAG}" == true ]]; then
      PYVXR_CHANNELS="PortChannel0|leaf0:Ethernet1_9#leaf1:Ethernet1_12|10|false|eth1#eth2"

      # Add a MLAG on [second, first] leaves when there are three leaf switches.
      if [[ ${LENGTH} -gt 1 ]]; then
        PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel10|leaf1:Ethernet1_9#leaf0:Ethernet1_12|10|false|eth1#eth2"
      fi
    else
      PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel10|leaf1:Ethernet1_9#leaf1:Ethernet1_12|10|false|eth1#eth2"
    fi
  fi

  # Last leaf always has LAG.
  if [[ ${LENGTH} -gt 1 ]]; then
    PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel20|leaf2:Ethernet1_9#leaf2:Ethernet1_12|10|false|eth1#eth2"
  fi
fi

set -euo pipefail

# SONiC regression test flow:
# 1) Create three L2VNI with SAG.
#     L2VNI 5100 + Vlan10 - one port per leaf; IPv4 = 41.216.0.1/24, IPv6 = dead:face::0:1/112
#     L2VNI 5200 + Vlan20 - one port per leaf; IPv4 = 41.216.1.1/24, IPv6 = dead:face::1:1/112
# 2) Adds VLANs to Vrf12000000
# 3) Creates a new VRF (Vrf40000)
# 4) Moves all VLANs to Vrf40000
# 5) Adds Loopbacks to all leaf switches.
# 6) Adds multiple SubInterfaces to all leaves from host1.
# 7) Adds static routes to host's loopbacks.
function run_pyvxr() {
  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --verify \
    --orgName "${ORG_NAME}" \
    --hostUser "${HOST_USER}" \
    --test "${CGEN_TEST}" \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --pyvxr "${PYVXR_HOST}" \
    --spines "${SPINE_PORTS}" \
    --leaves "${LEAF_PORTS}" \
    --hosts "${HOST_PORTS}" \
    --ports "${PYVXR_PORTS}" \
    --routes "${PYVXR_ROUTES}" \
    --dhcpRelays "${PYVXR_DHCPS}" \
    --bgpPeers "${PYVXR_BGPPEERS}" \
    --subInterfaces "${PYVXR_SUBINFS}" \
    --portChannels "${PYVXR_CHANNELS}" \
    --vrfs "${PYVXR_VRFS}" \
    --tags "${TEST_TAGS}"
}

echo
echo "-------------------------SONiC regression tests-------------------------"
echo
"${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}" --orgName "${ORG_NAME}" --timeout "3m"
run_pyvxr

end=$(date +%s)
stm=$((end-START_TIME))
echo
echo "Completed in ${stm}s"
echo

