#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2025 Cisco Systems, Inc., All rights reserved.
#
# Take a look at config-gen.pptx for more details on tests.
#
# Running test.sh using command line arguments.
#  ./test.sh -n <fabric-name> -p <pyvxr-host> -s <spine-ports> -l <leaf-ports> -h <host-ports>
#
set -euo pipefail

FABRIC_NAME=tortuga-1x3
PYVXR_HOST=tortuga-1x3.cisco.com
HOST_PORTS=40409,39855,36427,41851,49665,56787,35027,56005,51299
LEAF_PORTS=43039,45263,52467
SPINE_PORTS=43541

# SONiC team should set the BIN_DIR.
BIN_DIR="."
CONFIG_GEN="${BIN_DIR}/config-gen"
os=$(uname)
if [[ "${os}" == "Darwin" ]]; then
  CONFIG_GEN=./sandbox/gobin/config-gen
elif [[ -d "${BIN_DIR}" ]]; then
  curl http://ramius-fs1.cisco.com/cdi-images/config-gen --output "${CONFIG_GEN}"
  chmod +x "${CONFIG_GEN}"
fi

# Common static routes, sub-interfaces and routed port configs for PyVxr setups.
# Vrf40000 is automatically created by Tortuga when a L2VNI + SAG is added.
PYVXR_ROUTES="Vrf12000000|6.6.6.0/24#blackhole,Vrf40000|7.7.7.1/32#41.216.0.2#3|7.7.7.2/32#41.216.0.3#3|8.8.8.2/32#41.216.0.3#4"
PYVXR_PORTS="leaf0|Ethernet1_32_1#41.230.10.2/24#Vrf12000000"
PYVXR_SUBINFS="Vrf40000|*|Ethernet1_11|eth1#2|lo"
PYVXR_POLICIES="policy-imp#false#*|true#9999:99"
PYVXR_POLICIES="${PYVXR_POLICIES},policy-exp#true#*|false#*#9999:99|false#*#4|true#*#64510:*|false#*#0.0.0.0/0#0.0.0.0/0@GE@32|true#*"
PYVXR_DHCPS="*"
PYVXR_BGPPEERS="*"
PYVXR_CHANNELS="*"
PYVXR_VRFS=""
PYVXR_STPS="*"
CLOUD_URL=https://tortuga-k8s-a.cisco.com:30728
START_TIME=$(date +%s)
TEST_TAGS="sonic-test,ipv4,ipv6,loopback"
CGEN_TEST=extended
ORG_NAME="Test"
HOST_USER="vxr"
STP=true
DHCP=vlan
BREAKOUTS="$"
LOADTEST="*"
TIMEOUT="15m"
BULK_MODE=true

# Parse command line arguments.
while :
do
  if [[ $# = 0 ]]; then
    break;
  fi

  case $1 in
  -n|-name)
    FABRIC_NAME="${2}"
    shift; shift;;
  -p|-pyvxr|--pyvxr)
    PYVXR_HOST="${2}"
    shift; shift;;
  -h|-hosts|--hosts)
    HOST_PORTS="${2}"
    shift; shift;;
  -l|-leaves|--leaves)
    LEAF_PORTS="${2}"
    shift; shift;;
  -s|-spines|--spines)
    SPINE_PORTS="${2}"
    shift; shift;;
  -u|-url)
    CLOUD_URL="${2}"
    shift; shift;;
  -o|-org)
    ORG_NAME="${2}"
    shift; shift;;
  -prod)
    TEST_TAGS="${TEST_TAGS},no-ssh"
    shift;;
  -dhcp)
    DHCP="${2}"
    shift; shift;;
  -no-stp)
    STP=false
    shift;;
  -vrfs)
    PYVXR_VRFS="${2}"
    shift; shift;;
  -no-breakout)
    BREAKOUTS="*"
    shift;;
  -no-bulk-mode)
    BULK_MODE=false
    shift;;
  -loadtest)
    CGEN_TEST=loadtest
    LOADTEST="250#10#20"
    TIMEOUT="1h"
    shift;;
  -t|-tags)
    TEST_TAGS="${TEST_TAGS},${2}"
    shift; shift;;
  -a|-action)
    CGEN_TEST="${2}"
    shift; shift;;
  *)
    shift;;
  esac
done

# Number of leaf switches - 1.
LENGTH=$(echo "${LEAF_PORTS}" | tr -cd , | wc -c)

# Enable bulk-mode config.
if [[ "${BULK_MODE}" == true ]]; then
  TEST_TAGS="${TEST_TAGS},bulk-config"
fi

# PortChannels are always between two fixed ports.
LAG_PORT1="Ethernet1_9"
LAG_PORT2="Ethernet1_13"
PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"
PYVXR_IPS="Vrf40000|7.7.7.1|10"

# Add MLAG on [first, second] leaves.
if [[ ${LENGTH} -gt 0 ]]; then
  PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf1:${LAG_PORT2}|10|false|eth1#eth2"

  if [[ ${LENGTH} -gt 1 ]]; then
    PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel10|leaf1:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"
    PYVXR_IPS="Vrf40000|7.7.7.1#7.7.7.2|10"

    # Last leaf always has LAG.
    PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel20|leaf2:${LAG_PORT1}#leaf2:${LAG_PORT2}|10|false|eth1#eth2"
  fi
fi

# Add BGP peers. bgp1 uses default policies, and bgp2 uses custom policies.
PYVXR_BGPPEERS="Vrf40000|bgp1#4000|41.216.0.4#2000|leaf0#Loopback10"
if [[ ${LENGTH} -gt 1 ]]; then
  PYVXR_BGPPEERS="${PYVXR_BGPPEERS},Vrf40000|bgp2#4000|41.216.0.5#3000|leaf1#Loopback10|policy-exp#policy-imp"
fi

# Enable STP for PyVxr. STP is always on leaf0.
STP_PORT1="Ethernet1_16"
STP_PORT2="Ethernet1_17"
if [[ "${STP}" == true ]]; then
  HOST_SPECS="${HOST_PORTS},dummy/eth1|leaf0|${STP_PORT1}|80|true"
  HOST_SPECS="${HOST_SPECS},dummy/eth2|leaf0|${STP_PORT2}|80|true"
  PYVXR_STPS="true#00-00-00-00-00-01,leaf0|${STP_PORT1}#true##ROOT_GUARD|${STP_PORT2}#true#ROOT_GUARD"
  PYVXR_VRFS="${PYVXR_VRFS},Vrf40001|80"
  TEST_TAGS="${TEST_TAGS},stp"
else
  HOST_SPECS="${HOST_PORTS}"
  PYVXR_PORTS="${PYVXR_PORTS},leaf0|${STP_PORT1}#false|${STP_PORT2}#false"
  TEST_TAGS="${TEST_TAGS},no-stp"
fi

# Set up DHCP relay configs. DHCP server is on the fourth host of leaf0.
# Fourth host has an untagged Vlan of 40. Vrf40000 has a Loopback of 41.216.230.1
DHCP_PORT="Ethernet1_12"
if [[ "${DHCP}" == "vlan" ]]; then
  PYVXR_VRFS="${PYVXR_VRFS},Vrf40000|10#20#40|41.216.230.0/24"
  PYVXR_DHCPS="Vrf40000|relay-20|41.216.3.2|20"

  # Extend Vlan of DHCP relay to all leaves.
  if [[ ${LENGTH} -gt 0 ]]; then
    HOST_SPECS="${HOST_SPECS},dummy/eth1|leaf1|none|40|false"
  fi
  if [[ ${LENGTH} -gt 1 ]]; then
    HOST_SPECS="${HOST_SPECS},dummy/eth1|leaf2|none|40|false"
  fi
elif [[ "${DHCP}" == "port" ]]; then
  PYVXR_VRFS="${PYVXR_VRFS},Vrf40000|10#20|41.216.230.0/24"
  PYVXR_DHCPS="Vrf40000|relay-20|41.216.3.2|20"
  PYVXR_PORTS="${PYVXR_PORTS},leaf0|${DHCP_PORT}#41.216.3.1/24#dead:face::3:1/112#Vrf40000"
fi

if [[ -z "${PYVXR_VRFS}" ]]; then
  PYVXR_VRFS="*"
fi

TEST_TAGS="${TEST_TAGS},dhcp-${DHCP}"
if [[ "${BREAKOUTS}" == "$" ]]; then
  TEST_TAGS="${TEST_TAGS},breakout"
else
  TEST_TAGS="${TEST_TAGS},no-breakout"
fi

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
    --hosts "${HOST_SPECS}" \
    --ports "${PYVXR_PORTS}" \
    --routes "${PYVXR_ROUTES}" \
    --pingIps "${PYVXR_IPS}" \
    --dhcpRelays "${PYVXR_DHCPS}" \
    --bgpPeers "${PYVXR_BGPPEERS}" \
    --bgpPolicies "${PYVXR_POLICIES}" \
    --subInterfaces "${PYVXR_SUBINFS}" \
    --portChannels "${PYVXR_CHANNELS}" \
    --vrfs "${PYVXR_VRFS}" \
    --vlanStp "${PYVXR_STPS}" \
    --timeout "${TIMEOUT}" \
    --input "${LOADTEST}" \
    --tags "${TEST_TAGS}"
}

echo
echo "-------------------------SONiC regression tests-------------------------"
echo
if [[ "${CGEN_TEST}" != "ping" ]]; then
  "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}" --orgName "${ORG_NAME}" --timeout "3m"
  echo
fi

run_pyvxr

end=$(date +%s)
stm=$((end-START_TIME))
echo
echo "Completed in ${stm}s"
echo

