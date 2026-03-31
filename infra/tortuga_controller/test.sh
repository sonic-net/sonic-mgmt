#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2026 Cisco Systems, Inc., All rights reserved.
#
# Take a look at config-gen.pptx for more details on tests.
#
# Commandline arguments for single fabric tests.
#  ./test.sh -n <fabric-name> -p <pyvxr-host> -s <spine-ports> -l <leaf-ports> -h <host-ports>
#  ./test.sh -n <fabric-name> -p <pyvxr-host> --spines <spine-ports> --leaves <leaf-ports> --hosts <host-ports>
#
# Commandline arguments for DCI tests. Specify "-c" for number of fabrics in the DCI.
# For example, "-c 3" for dci1x2-3-static-sim.yaml, and "-c 2" for both dci1x2-2-bgp-sim.yaml
# and dci2x2-2-bgp-sim.yaml
#  ./test.sh -n <fabric-name> -p <pyvxr-host> -c 2 -s <spine-ports> -l <leaf-ports> -h <host-ports>
#  ./test.sh -n <fabric-name> -p <pyvxr-host> -c 3 --spines <spine-ports> --leaves <leaf-ports> --hosts <host-ports>
#
set -euo pipefail

FABRIC_NAME=tortuga-1x3
PYVXR_HOST=tortuga-1x3.cisco.com
HOST_PORTS=40409,39855,36427,41851,49665,56787,35027,56005,51299
LEAF_PORTS=43039,45263,52467
SPINE_PORTS=43541
FABRIC_COUNT=1

# SONiC team should set the BIN_DIR.
BIN_DIR="."
CONFIG_GEN="${BIN_DIR}/config-gen"
if [[ -f ./sandbox/gobin/config-gen ]]; then
  CONFIG_GEN=./sandbox/gobin/config-gen
elif [[ -d "${BIN_DIR}" ]]; then
  curl http://ramius-fs1.cisco.com/cdi-images/config-gen --output "${CONFIG_GEN}"
  chmod +x "${CONFIG_GEN}"
fi

# Common sub-interfaces and routed port configs for PyVxr setups.
# Vrf40000 is automatically created by Tortuga when a L2VNI + SAG is added.
PYVXR_DHCPS="*"
PYVXR_BGPPEERS="*"
PYVXR_CHANNELS="*"
PYVXR_VRFS=""
PYVXR_STPS="*"
CLOUD_URL=
START_TIME=$(date +%s)
TEST_TAGS="ipv4,ipv6,bgp-debug"
CGEN_TEST=extended
ORG_NAME="Test"
HOST_USER="vxr"
STP=true
DHCP=vlan
LAG=true
BREAKOUT="breakout"
LOADTEST="*"
TIMEOUT="15m"
BULK_PATCH=false # Enable bulk config patch.
LLDP_CHECK=true  # Check and assert for LLDP system description.
IPSLA=true       # Enable IpSla tests.
SB_PEER=true     # Add southbound peers.
SB_SPINE=true    # Use spine as southbound peer.
DSCP="no-dscp"   # Enable DSCP/QoS tests.
SCALE_VLANS=8    # Number of host Vlans to be added.
SCALE_VNIS=8     # Number of VNIs to be added for scale testing.
SCALE_PCS=5      # Number of PortChannels to be added for scale testing.
SCALE_SUBINFS=8  # Number of host/switch routed sub-interfaces.
SCALE_ROUTES=8   # Number of FRR routes (Loopback IP + Static routes).

# Test ports.
STP_PORT1="Ethernet1_16"
STP_PORT2="Ethernet1_17"
DHCP_PORT="Ethernet1_12"
SUBINF_PORT="Ethernet1_11"
LAG_PORT1="Ethernet1_9"
LAG_PORT2="Ethernet1_13"
ROUTED_PORT1="Ethernet1_14"
ROUTED_PORT2="Ethernet1_32"
VLAN_PORT1="Ethernet1_10"
VLAN_PORT2="Ethernet1_12"

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
  -no-arp-ping)
    TEST_TAGS="${TEST_TAGS},no-arp-ping"
    shift;;
  -dup-ok)
    TEST_TAGS="${TEST_TAGS},dup-ok"
    shift;;
  -dhcp)
    DHCP="${2}"
    shift; shift;;
  -dscp)
    DSCP="dscp"
    shift;;
  -no-stp)
    STP=false
    shift;;
  -no-lag)
    LAG=false
    shift;;
  -vrfs)
    PYVXR_VRFS="${2}"
    shift; shift;;
  -vnis)
    SCALE_VNIS="${2}"
    shift; shift;;
  -subinfs)
    SCALE_SUBINFS="${2}"
    shift; shift;;
  -vlans)
    SCALE_VLANS="${2}"
    shift; shift;;
  -routes)
    SCALE_ROUTES="${2}"
    shift; shift;;
  -pcs)
    SCALE_PCS="${2}"
    shift; shift;;
  -no-breakout)
    BREAKOUT="no-breakout"
    shift;;
  -no-ipsla)
    IPSLA=false
    shift;;
  -bulk-patch)
    BULK_PATCH=true
    shift;;
  -no-lldp-sys)
    LLDP_CHECK=false
    shift;;
  -t|-tags)
    TEST_TAGS="${TEST_TAGS},${2}"
    shift; shift;;
  -a|-action)
    CGEN_TEST="${2}"
    shift; shift;;
  -c|-count)
    FABRIC_COUNT="${2}"
    shift; shift;;
  *)
    shift;;
  esac
done

# Get URL from config file.
if [[ -z "${CLOUD_URL}" ]]; then
  YAML=$(curl --retry 5 -s http://ramius-fs1.cisco.com/cdi-images/tortuga/drake-config-pradeep1.yml 2>&1)
  CLOUD_URL=$(echo ${YAML} | grep -Eo 'https://tortuga-k8s-a.cisco.com:[0-9]+')
fi
echo "Cloud URL = ${CLOUD_URL}"

# Number of leaf switches - 1.
LENGTH=$(echo "${LEAF_PORTS}" | tr -cd , | wc -c)
LENGTH=$((LENGTH + 1))
LENGTH=$((LENGTH / FABRIC_COUNT))

# Disable southbound spine peering in following cases.
# - If there is only one switch.
# - In mesh topology (no spines).
# - In DCI mode (spines cannot have VRF).
if [[ ${LENGTH} -eq 1 ]] || [[ ${SPINE_PORTS} -eq 0 ]] || [[ ${FABRIC_COUNT} -gt 1 ]]; then
  SB_SPINE=false
fi

# Enable bulk patch.
if [[ "${BULK_PATCH}" == true ]]; then
  TEST_TAGS="${TEST_TAGS},bulk-patch"
fi

# Enable LLDP system description check.
if [[ "${LLDP_CHECK}" == false ]]; then
  TEST_TAGS="${TEST_TAGS},no-lldp-sys"
fi

# Add sub-interfaces on hosts connected to the ports specified in SUBINF_PORT.
PYVXR_SUBINFS="Vrf40000|*|${SUBINF_PORT}|eth1#${SCALE_SUBINFS}|lo"

# Add tagged vlans for host sub-interfaces. In case of a single switch setup,
# add tagged vlans on the DHCP host port so as to have connected vlan hosts.
PYVXR_VLANS="Vrf40000|*|${VLAN_PORT1}|eth1#${SCALE_VLANS}"
if [[ ${LENGTH} -eq 1 ]]; then
  PYVXR_VLANS="${PYVXR_VLANS},Vrf40000|*|${VLAN_PORT2}|eth1#${SCALE_VLANS}"
fi

# Add a routed port on leaf0 with point-to-point network.
PYVXR_PORTS="leaf0|${ROUTED_PORT1}#41.230.10.1/31#Vrf40000,leaf0|${ROUTED_PORT2}#41.240.10.1/28#Vrf12000000"

# Add static routes -- one blackhole, one using point-to-point IP and two ECMP routes.
PYVXR_ROUTES="Vrf12000000|6.6.6.0/24#blackhole|10.10.10.0/24#41.240.10.2|10.10.10.0/24#41.240.10.3"

# Add BGP peers and BGP policies.
# Northbound BGP peer is on a routed port using point-to-point connection. Northbound peer uses
# custom policies. Custom export policy re-writes next-hop to leaf0's Loopback IPs. By default,
# FRR assigns connected port's IP as next-hop, and that would create traffic failures. Following
# scripts add IP 41.230.10.0/31 on eth2 of host3.
PYVXR_POLICIES="export-nb#true#41.220.200.200#fc00:dead:face::200:200|false#*#9999:99|false#*#RED|true#*#PURPLE|true#*#8888:88|false#*#0.0.0.0/0#41.220.0.0/16@GE@16|true#*"
PYVXR_POLICIES="${PYVXR_POLICIES},import-nb#false#*|true#9999:99+"
PYVXR_BGPPEERS="Vrf40000|northbound#4000#*#host3@41.230.10.0/31@eth2#leaf0|41.230.10.0#4500|leaf0#${ROUTED_PORT1}|export-nb#import-nb"

# Add a IPv6 northbound BGP peer on third host of last leaf.
V6HOST=host2
V6LEAF=leaf0
if [[ ${LENGTH} -eq 2 ]]; then
  V6HOST=host6
  V6LEAF=leaf1
elif [[ ${LENGTH} -gt 2 ]]; then
  V6HOST=host9
  V6LEAF=leaf2
fi

# Add second northbound BGP peer with IPv6 address family. This peer uses default BGP policies.
PYVXR_PORTS="${PYVXR_PORTS},${V6LEAF}|${SUBINF_PORT}#50.50.50.1/28#5000::0/127#Vrf40000"
PYVXR_BGPPEERS="${PYVXR_BGPPEERS},Vrf40000|ipv6-nb#5000#*#${V6HOST}@50.50.50.2/28@5000::1/127@eth1#${V6LEAF}|5000::1/128#5500|${V6LEAF}#${SUBINF_PORT}"
PYVXR_ROUTES="${PYVXR_ROUTES},*#${V6HOST}|fc00:dead:face::0/96#5000::0"
PYVXR_IPS="50.50.50.2#5000::1/127"

# We use leaf0 Loopback for southbound peering when spine based peering is disabled.
SB_ANNOTATIONS="host1@41.216.1.2#leaf0"
SB_NODE1=leaf0
if [[ "${SB_SPINE}" == true ]]; then
  SB_NODE1=spine0
fi

# Southbound BGP peer is on leaf0, and uses custom policies.
# Annotations are used by config-gen to configure FRR on hosts.
if [[ "${SB_PEER}" == true ]]; then
  PYVXR_POLICIES="${PYVXR_POLICIES},export-sb#true#*|true#*#9999:99#8888:88|false#*#BLACK|false#*#0.0.0.0/0|true#*"
  PYVXR_POLICIES="${PYVXR_POLICIES},import-sb#false#*|true#8888:88+"
  PYVXR_BGPPEERS="${PYVXR_BGPPEERS},Vrf40000|southbound#3000#*#${SB_ANNOTATIONS}|41.216.1.0/28#3500#20|${SB_NODE1}#Loopback10"
  PYVXR_BGPPEERS="${PYVXR_BGPPEERS}|export-sb#import-sb"
fi

# Add static routes for Vrf40000
PYVXR_IPS="${PYVXR_IPS}#7.7.7.1"
PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000|8.8.8.2/32#41.216.0.3#RED|8.8.8.3/32#41.216.0.3#GREEN|7.7.7.1/32#41.216.0.2#BLUE"

# Add PortChannels for single switch setup.
PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"

# Add PortChannels for two leaves fabric.
if [[ ${LENGTH} -eq 2 ]]; then
  PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf1:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel10|leaf1:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.2"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.2/32#41.216.0.3#BLUE"
fi

# Add PortChannels for three leaf fabric: MLAG on first and second leaves, and LAG on third leaf.
if [[ ${LENGTH} -gt 2 ]]; then
  PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf1:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel10|leaf1:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel20|leaf2:${LAG_PORT1}#leaf2:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.2#7.7.7.3"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.2/32#41.216.0.3#BLUE|7.7.7.3/32#41.216.0.4#BLUE"
fi

# Add PortChannels for six leaf fabric: MLAG on fourth and fifth leaves, and LAG on sixth leaf.
if [[ ${LENGTH} -gt 4 ]]; then
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel30|leaf3:${LAG_PORT1}#leaf4:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel40|leaf4:${LAG_PORT1}#leaf3:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel50|leaf5:${LAG_PORT1}#leaf5:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.4#7.7.7.5#7.7.7.6"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.4/32#41.216.0.5#BLUE|7.7.7.5/32#41.216.0.6#3|7.7.7.6/32#41.216.0.7#BLUE"
fi

# Add PortChannels for nine leaf fabric: MLAG on seventh and eighth leaves, and LAG on ninth leaf.
if [[ ${LENGTH} -gt 7 ]]; then
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel60|leaf6:${LAG_PORT1}#leaf7:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel70|leaf7:${LAG_PORT1}#leaf6:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel80|leaf8:${LAG_PORT1}#leaf8:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.7#7.7.7.8#7.7.7.9"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.7/32#41.216.0.8#BLUE|7.7.7.8/32#41.216.0.9#3|7.7.7.9/32#41.216.0.10#BLUE"
fi

# Enable STP for PyVxr. STP is always on leaf0.
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
# Fourth host has an untagged Vlan 40. Vrf40000 has a Loopback with 41.217.217.0/24 as IP.
if [[ "${DHCP}" == "vlan" ]]; then
  PYVXR_VRFS="${PYVXR_VRFS},Vrf40000|10#20#40|41.217.217.0/24#7000::2:0/112"
  PYVXR_DHCPS="Vrf40000|relay-20|41.216.3.2|20"

  # Extend Vlan of DHCP relay to all leaves.
  if [[ ${LENGTH} -gt 1 ]]; then
    HOST_SPECS="${HOST_SPECS},dummy/eth1|leaf1|none|40|false"
  fi
  if [[ ${LENGTH} -gt 2 ]]; then
    HOST_SPECS="${HOST_SPECS},dummy/eth1|leaf2|none|40|false"
  fi
elif [[ "${DHCP}" == "port" ]]; then
  PYVXR_VRFS="${PYVXR_VRFS},Vrf40000|10#20|41.217.217.0/24#7000::2:0/112"
  PYVXR_DHCPS="Vrf40000|relay-20|41.216.3.2|20"
  PYVXR_PORTS="${PYVXR_PORTS},leaf0|${DHCP_PORT}#41.216.3.1/24#fc00:dead:face::3:1/112#Vrf40000"
fi

if [[ -z "${PYVXR_VRFS}" ]]; then
  PYVXR_VRFS="*"
fi

# Disable PortChannels.
if [[ "${LAG}" == false ]]; then
  PYVXR_CHANNELS="*"
fi

# Add a routed port on leaf1 and add host IP to host6 (last host on leaf1).
# This route is going to be used as the IP/SLA route on leaf1.
if [[ ${LENGTH} -gt 1 ]]; then
  PYVXR_PORTS="${PYVXR_PORTS},leaf1|${ROUTED_PORT1}#41.230.20.1/24#Vrf40000#host6@eth2@41.230.20.2/24"
  PYVXR_IPS="${PYVXR_IPS}#41.230.20.2"
fi

# Configure IP/SLA and static routes for traffic-gen running in host0 and
# host4. For single switch setup, enable traffic-gen on host0 and host1.
if [[ "${IPSLA}" == true ]]; then
  if [[ ${LENGTH} -gt 2 ]]; then
    PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000#ip-sla-routes#host0@host6@host7|20.20.20.2/32#41.216.0.2|20.20.20.2/32#41.230.20.2|20.20.20.2/32#41.216.0.4"
  elif [[ ${LENGTH} -gt 1 ]]; then
     PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000#ip-sla-routes#host0@host6|20.20.20.2/32#41.216.0.2|20.20.20.2/32#41.230.20.2"
  else
    PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000#ip-sla-routes#host0@host1|20.20.20.2/32#41.216.0.2|20.20.20.2/32#41.216.1.2"
  fi

  PYVXR_IPSLAS="Vrf40000|ip-sla-1#TCP#9100#10#3#20.20.20.2/32"
else
  PYVXR_IPSLAS="*"
fi

# Append VLAN to the IPs. Following lines MUST BE the last lines before
# invoking config-gen.
PYVXR_IPS="Vrf40000|${PYVXR_IPS}|10"
TEST_TAGS="${TEST_TAGS},dhcp-${DHCP},${DSCP},${BREAKOUT}"

function run_pyvxr() {
  "${CONFIG_GEN}" \
    --lldp \
    --auto \
    --prefix \
    --orgName "${ORG_NAME}" \
    --hostUser "${HOST_USER}" \
    --test "${CGEN_TEST}" \
    --cloud "${CLOUD_URL}" \
    --fabric "${FABRIC_NAME}" \
    --count "${FABRIC_COUNT}" \
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
    --hostVlans "${PYVXR_VLANS}" \
    --portChannels "${PYVXR_CHANNELS}" \
    --ipSlas "${PYVXR_IPSLAS}" \
    --vrfs "${PYVXR_VRFS}" \
    --vlanStp "${PYVXR_STPS}" \
    --timeout "${TIMEOUT}" \
    --input "${LOADTEST}" \
    --frrRoutes "${SCALE_ROUTES}" \
    --scaleVnis "${SCALE_VNIS}" \
    --scalePcs "${SCALE_PCS}" \
    --tags "${TEST_TAGS}"
}

echo
echo "-------------------------SONiC regression tests-------------------------"
echo
if [[ "${CGEN_TEST}" != "ping" ]]; then
  if [[ ${FABRIC_COUNT} -eq 1 ]]; then
    "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}" --orgName "${ORG_NAME}" --timeout "3m"
  else
    for ((i = 2; i <= FABRIC_COUNT; i++)); do
      "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}${i}" --orgName "${ORG_NAME}" --timeout "1s"
    done

    # Delete the first DC.
    "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}1" --orgName "${ORG_NAME}" --timeout "3m"
  fi
  echo
fi

run_pyvxr

end=$(date +%s)
stm=$((end-START_TIME))
echo
echo "Completed in ${stm}s"
echo
