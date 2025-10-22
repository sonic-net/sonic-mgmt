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

# Common sub-interfaces and routed port configs for PyVxr setups.
# Vrf40000 is automatically created by Tortuga when a L2VNI + SAG is added.
PYVXR_DHCPS="*"
PYVXR_BGPPEERS="*"
PYVXR_CHANNELS="*"
PYVXR_VRFS=""
PYVXR_STPS="*"
CLOUD_URL=https://tortuga-k8s-a.cisco.com:30709
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
BULK_MODE=true   # Enable bulk config load.
BULK_PATCH=false # Enable bulk config patch.
LLDP_CHECK=true  # Check and assert for LLDP system description.
IPSLA=true       # Enable IpSla tests.
DSCP="no-dscp"   # Enable DSCP/QoS tests.
SCALE_VLANS=10   # Number of host Vlans to be added.
SCALE_VNIS=10    # Number of VNIs to be added for scale testing.
SCALE_PCS=5      # Number of PortChannels to be added for scale testing.
SCALE_SUBINFS=2  # Number of host/switch routed sub-interfaces.
SCALE_ROUTES=10  # Number of FRR routes (Loopback IP + Static routes).

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
  -arp-ping)
    TEST_TAGS="${TEST_TAGS},arp-ping"
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
  -no-bulk-mode)
    BULK_MODE=false
    BULK_PATCH=false
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
if [[ ${LENGTH} -eq 0 ]]; then
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
PYVXR_POLICIES="export-nb#true#41.220.200.200#fc00:dead:face::200:200|false#*#9999:99|false#*#GREEN|true#*#8888:88|false#*#0.0.0.0/0#41.220.0.0/16@GE@16|true#*"
PYVXR_POLICIES="${PYVXR_POLICIES},import-nb#false#*|true#9999:99"
PYVXR_BGPPEERS="Vrf40000|northbound#4000#*#host3@41.230.10.0/31@eth2#leaf0|41.230.10.0#4500|leaf0#${ROUTED_PORT1}|export-nb#import-nb"

# Add a IPv6 northbound BGP peer on third host of last leaf.
V6HOST=host2
V6LEAF=leaf0
if [[ ${LENGTH} -eq 1 ]]; then
  V6HOST=host6
  V6LEAF=leaf1
elif [[ ${LENGTH} -gt 1 ]]; then
  V6HOST=host9
  V6LEAF=leaf2
fi
PYVXR_PORTS="${PYVXR_PORTS},${V6LEAF}|${SUBINF_PORT}#50.50.50.1/28#5000::1/112#Vrf40000"
PYVXR_BGPPEERS="${PYVXR_BGPPEERS},Vrf40000|ipv6-nb#5000#*#${V6HOST}@50.50.50.2/28@5000::2/112@eth1#${V6LEAF}|5000::2/128#5500|${V6LEAF}#${SUBINF_PORT}"
PYVXR_ROUTES="${PYVXR_ROUTES},*#${V6HOST}|fc00:dead:face::0/96#5000::1"
PYVXR_IPS="50.50.50.2#5000::2"

# Southbound BGP peer is on leaf0 and leaf1, and uses custom policies.
# Annotations are used by config-gen to configure FRR on hosts.
SB_ANNOTATIONS="host1@41.216.1.2#leaf0#host5@41.216.1.3#leaf1#host8@41.216.1.4#leaf2"
PYVXR_POLICIES="${PYVXR_POLICIES},export-sb#true#*|true#*#9999:99#8888:88|false#*#BLACK|false#*#0.0.0.0/0|true#*"
PYVXR_POLICIES="${PYVXR_POLICIES},import-sb#false#*|true#8888:88"
PYVXR_BGPPEERS="${PYVXR_BGPPEERS},Vrf40000|southbound#3000#*#${SB_ANNOTATIONS}|41.216.1.0/28#3500#20|leaf0#Loopback10"
if [[ ${LENGTH} -gt 0 ]]; then
  PYVXR_BGPPEERS="${PYVXR_BGPPEERS}#leaf1#Loopback10"
fi
if [[ ${LENGTH} -gt 1 ]]; then
  PYVXR_BGPPEERS="${PYVXR_BGPPEERS}#leaf2#Loopback10"
fi
PYVXR_BGPPEERS="${PYVXR_BGPPEERS}|export-sb#import-sb"

# Add static routes for Vrf400000
PYVXR_IPS="${PYVXR_IPS}#7.7.7.1"
PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000|8.8.8.2/32#41.216.0.3#GREEN|8.8.8.3/32#41.216.0.3#RED|7.7.7.1/32#41.216.0.2#BLUE"

# Add PortChannels for single switch setup.
PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"

# Add PortChannels for two leaves fabric.
if [[ ${LENGTH} -eq 1 ]]; then
  PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf1:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel10|leaf1:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.2"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.2/32#41.216.0.3#BLUE"
fi

# Add PortChannels for three leaf fabric: MLAG on first and second leaves, and LAG on third leaf.
if [[ ${LENGTH} -gt 1 ]]; then
  PYVXR_CHANNELS="PortChannel1|leaf0:${LAG_PORT1}#leaf1:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel10|leaf1:${LAG_PORT1}#leaf0:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel20|leaf2:${LAG_PORT1}#leaf2:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.2#7.7.7.3"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.2/32#41.216.0.3#BLUE|7.7.7.3/32#41.216.0.4#BLUE"
fi

# Add PortChannels for six leaf fabric: MLAG on fourth and fifth leaves, and LAG on sixth leaf.
if [[ ${LENGTH} -gt 3 ]]; then
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel30|leaf3:${LAG_PORT1}#leaf4:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel40|leaf4:${LAG_PORT1}#leaf3:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel50|leaf5:${LAG_PORT1}#leaf5:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.4#7.7.7.5#7.7.7.6"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.4/32#41.216.0.5#BLUE|7.7.7.5/32#41.216.0.6#3|7.7.7.6/32#41.216.0.7#BLUE"
fi

# Add PortChannels for nine leaf fabric: MLAG on seventh and eighth leaves, and LAG on nineth leaf.
if [[ ${LENGTH} -gt 6 ]]; then
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel60|leaf6:${LAG_PORT1}#leaf7:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel70|leaf7:${LAG_PORT1}#leaf6:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_CHANNELS="${PYVXR_CHANNELS},PortChannel80|leaf8:${LAG_PORT1}#leaf8:${LAG_PORT2}|10|false|eth1#eth2"
  PYVXR_IPS="${PYVXR_IPS}#7.7.7.7#7.7.7.8#7.7.7.9"
  PYVXR_ROUTES="${PYVXR_ROUTES}|7.7.7.7/32#41.216.0.8#BLUE|7.7.7.8/32#41.216.0.9#3|7.7.7.9/32#41.216.0.10#BLUE"
fi

PYVXR_IPS="Vrf40000|${PYVXR_IPS}|10"

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
# Fourth host has an untagged Vlan 40. Vrf40000 has a Loopback with 41.216.230.1 as IP.
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

# Disable PortChannels.
if [[ "${LAG}" == false ]]; then
  PYVXR_CHANNELS="*"
fi

TEST_TAGS="${TEST_TAGS},dhcp-${DHCP},${DSCP},${BREAKOUT}"

# Configure IP/SLA and static routes for traffic-gen running in host0 and
# host4. For single switch setup, enable traffic-gen on host0 and host1.
if [[ "${IPSLA}" == true ]]; then
  if [[ ${LENGTH} -gt 1 ]]; then
    PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000#ip-sla-routes#host0@host4@host7|20.20.20.2/32#41.216.0.2|20.20.20.2/32#41.216.0.3|20.20.20.2/32#41.216.0.4"
  elif [[ ${LENGTH} -gt 0 ]]; then
     PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000#ip-sla-routes#host0@host4|20.20.20.2/32#41.216.0.2|20.20.20.2/32#41.216.0.3"
  else
    PYVXR_ROUTES="${PYVXR_ROUTES},Vrf40000#ip-sla-routes#host0@host1|20.20.20.2/32#41.216.0.2|20.20.20.2/32#41.216.1.2"
  fi

  PYVXR_IPSLAS="Vrf40000|ip-sla-1#TCP#9100#10#3#20.20.20.2/32"
  TEST_TAGS="${TEST_TAGS},ip-sla"
else
  PYVXR_IPSLAS="*"
fi

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
  "${CONFIG_GEN}" --cloud "${CLOUD_URL}" --reset --fabric "${FABRIC_NAME}" --orgName "${ORG_NAME}" --timeout "3m"
  echo
fi

run_pyvxr

end=$(date +%s)
stm=$((end-START_TIME))
echo
echo "Completed in ${stm}s"
echo
