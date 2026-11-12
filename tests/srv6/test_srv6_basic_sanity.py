import time
import logging
import pytest
import ptf.packet as scapy

from ptf.testutils import simple_tcp_packet
from ptf.mask import Mask
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from srv6_utils import announce_route
from srv6_utils import find_node_interfaces
from srv6_utils import check_bgp_neighbors
from srv6_utils import check_bgp_neighbors_func
from srv6_utils import runSendReceive
from srv6_utils import check_routes
from srv6_utils import check_v6_route_nhg_chain
from srv6_utils import check_vrf_route_nhg_chain
from srv6_utils import recording_fwding_chain
from srv6_utils import turn_on_off_frr_debug
from srv6_utils import collect_frr_debugfile

from common_utils import enable_tcpdump
from common_utils import disable_tcpdump


from srv6_utils import *
from srv6_utils import (
    apply_config_cmmds_to_vtysh,
    start_record_collection,
    stop_record_collection,
    assert_appdb_nexthop_removed,
    assert_appdb_nexthop_present,
    verify_nhg_before_routes,
)

logger = logging.getLogger(__name__)


#
# Add --skip_sanity when running pytest to avoid current pytest use /etc/sonic/minigraph.xml
# The running option could be removed once the pytest sanity check is enhancemed on using
# this file.
#
pytestmark = [
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("ciscovs-7nodes", "force10-7nodes"),
    pytest.mark.skip_check_dut_health
]

test_vm_names = ["PE1", "PE2", "PE3", "P2", "P3", "P4"]

#
# Sender PE3's MAC
#
sender_mac = "52:54:00:df:1c:5e"

#
# The port used by ptf to connect with backplane. This number is different from 3 ndoe case.
#
ptf_port_for_backplane = 18

# The number of routes published by each CE
num_ce_routes = 10

#
# Routes learnt from pe1 and pe2
#
route_prefix_for_pe1_and_pe2 = "192.100.0"

#
# Routes learnt from pe3
#
route_prefix_for_pe3 = "192.200.0"

#
# This 10 sec sleep is used for make sure software programming is finished
# It has enough buffer zone.
#
sleep_duration = 10

#
# BGP neighbor up waiting time, waiting up to 180 sec
#
bgp_neighbor_up_wait_time = 180

#
# BGP neighbor down waiting time, waiting up to 30 sec
#
bgp_neighbor_down_wait_time = 30


#
# Initialize the testbed
#
def setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, ptfadapter):

    logger.info("reinit ptfadapter")
    ptfadapter.reinit({'need_backplane': True})

    logger.info("Announce routes from CEs")
    ptfip = ptfhost.mgmt_ip
    nexthop = "10.10.246.254"
    port_num = [5000, 5001, 5002]

    # Publish to PE1
    neighbor = "10.10.246.29"
    # Publish to PE2
    neighbor2 = "10.10.246.30"
    route_prefix_for_pe1_and_pe2 = "192.100.0"

    for x in range(1, num_ce_routes+1):
        route = "{}.{}/32".format(route_prefix_for_pe1_and_pe2, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[0])
        announce_route(ptfip, neighbor2, route, nexthop, port_num[1])

    # Publish to PE3
    neighbor = "10.10.246.31"
    for x in range(1, num_ce_routes+1):
        route = "{}.{}/32".format(route_prefix_for_pe3, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[2])

    # sleep make sure all forwarding structures are settled down.
    sleep_duration_after_annournce = 60
    time.sleep(sleep_duration_after_annournce)
    logger.info(
        "Sleep {} seconds to make sure all forwarding structures are "
        "settled down".format(sleep_duration_after_annournce)
    )


#
# Testbed set up and tear down
#
@pytest.fixture(scope="module", autouse=True)
def srv6_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, ptfadapter):
    setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, ptfadapter)


#
# Test case: check number of Ethnernet interfaces
#

# --- PIC Convergence Test Constants ---

# Topology 1: Global Table Recursive Routes (applied on PE3)
TOPO1_STATIC_ROUTES = [
    "ipv6 route 1::1/128 2064:100::1d",
    "ipv6 route 1::1/128 2064:200::1e",
    "ipv6 route 2::2/128 2064:200::1e",
    "ipv6 route 3::3/128 1::1",
    "ipv6 route 3::3/128 2::2",
    "ipv6 route 4::4/128 1::1",
]

TOPO1_STATIC_ROUTES_REMOVE = [
    "no ipv6 route 1::1/128 2064:100::1d",
    "no ipv6 route 1::1/128 2064:200::1e",
    "no ipv6 route 2::2/128 2064:200::1e",
    "no ipv6 route 3::3/128 1::1",
    "no ipv6 route 3::3/128 2::2",
    "no ipv6 route 4::4/128 1::1",
]

# Topology 2: Global Table with Direct + Recursive Mix (applied on PE3)
TOPO2_STATIC_ROUTES = [
    "ipv6 route 1::1/128 2064:100::1d",
    "ipv6 route 1::1/128 2064:200::1e",
    "ipv6 route 2::2/128 fc06::2",
    "ipv6 route 3::3/128 fc08::2",
    "ipv6 route 4::4/128 2::2",
    "ipv6 route 4::4/128 3::3",
]

TOPO2_STATIC_ROUTES_REMOVE = [
    "no ipv6 route 1::1/128 2064:100::1d",
    "no ipv6 route 1::1/128 2064:200::1e",
    "no ipv6 route 2::2/128 fc06::2",
    "no ipv6 route 3::3/128 fc08::2",
    "no ipv6 route 4::4/128 2::2",
    "no ipv6 route 4::4/128 3::3",
]

# P2/P4 outbound: only advertise PE loopbacks with short AS-path (2 hops) to PE3.
# PE3 inbound: only accept PE loopbacks with short AS-path (3 hops including peer AS).
P2_OUTBOUND_FILTER = [
    "ipv6 prefix-list PE_LOOPBACKS seq 5 permit 2064:100::1d/128",
    "ipv6 prefix-list PE_LOOPBACKS seq 10 permit 2064:200::1e/128",
    "ipv6 prefix-list PE_LOOPBACKS seq 15 permit 2064:300::1f/128",
    "bgp as-path access-list SHORT_PATH_OUT permit ^[0-9]+_[0-9]+$",
    "route-map TO_PE3 permit 10",
    " match ipv6 address prefix-list PE_LOOPBACKS",
    " match as-path SHORT_PATH_OUT",
    "route-map TO_PE3 deny 20",
    " match ipv6 address prefix-list PE_LOOPBACKS",
    "route-map TO_PE3 permit 30",
    "router bgp 65102",
    " address-family ipv6 unicast",
    "  neighbor fc08::1 route-map TO_PE3 out",
]

P2_OUTBOUND_FILTER_REMOVE = [
    "router bgp 65102",
    " address-family ipv6 unicast",
    "  neighbor fc08::1 route-map pass_all out",
    "exit-address-family",
    "exit",
    "no route-map TO_PE3",
    "no ipv6 prefix-list PE_LOOPBACKS",
    "no bgp as-path access-list SHORT_PATH_OUT",
]

P4_OUTBOUND_FILTER = [
    "ipv6 prefix-list PE_LOOPBACKS seq 5 permit 2064:100::1d/128",
    "ipv6 prefix-list PE_LOOPBACKS seq 10 permit 2064:200::1e/128",
    "ipv6 prefix-list PE_LOOPBACKS seq 15 permit 2064:300::1f/128",
    "bgp as-path access-list SHORT_PATH_OUT permit ^[0-9]+_[0-9]+$",
    "route-map TO_PE3 permit 10",
    " match ipv6 address prefix-list PE_LOOPBACKS",
    " match as-path SHORT_PATH_OUT",
    "route-map TO_PE3 deny 20",
    " match ipv6 address prefix-list PE_LOOPBACKS",
    "route-map TO_PE3 permit 30",
    "router bgp 65103",
    " address-family ipv6 unicast",
    "  neighbor fc06::1 route-map TO_PE3 out",
]

P4_OUTBOUND_FILTER_REMOVE = [
    "router bgp 65103",
    " address-family ipv6 unicast",
    "  neighbor fc06::1 route-map pass_all out",
    "exit-address-family",
    "exit",
    "no route-map TO_PE3",
    "no ipv6 prefix-list PE_LOOPBACKS",
    "no bgp as-path access-list SHORT_PATH_OUT",
]

PE3_INBOUND_FILTER = [
    "ipv6 prefix-list PE_LOOPBACKS seq 5 permit 2064:100::1d/128",
    "ipv6 prefix-list PE_LOOPBACKS seq 10 permit 2064:200::1e/128",
    "bgp as-path access-list SHORT_PATH permit ^[0-9]+_[0-9]+_[0-9]+$",
    "route-map FILTER_IN permit 10",
    " match ipv6 address prefix-list PE_LOOPBACKS",
    " match as-path SHORT_PATH",
    " set ipv6 next-hop prefer-global",
    "route-map FILTER_IN deny 20",
    " match ipv6 address prefix-list PE_LOOPBACKS",
    "route-map FILTER_IN permit 30",
    " set ipv6 next-hop prefer-global",
    "router bgp 64602",
    " address-family ipv6 unicast",
    "  neighbor fc08::2 route-map FILTER_IN in",
    "  neighbor fc06::2 route-map FILTER_IN in",
]

PE3_INBOUND_FILTER_REMOVE = [
    "router bgp 64602",
    " address-family ipv6 unicast",
    "  neighbor fc08::2 route-map pass_all_in in",
    "  neighbor fc06::2 route-map pass_all_in in",
    "exit-address-family",
    "exit",
    "no route-map FILTER_IN",
    "no ipv6 prefix-list PE_LOOPBACKS",
    "no bgp as-path access-list SHORT_PATH",
]


def test_interface_on_each_node(duthosts, rand_one_dut_hostname, nbrhosts):
    for vm_name in test_vm_names:
        nbrhost = nbrhosts[vm_name]['host']
        num, hwsku = find_node_interfaces(nbrhost)
        logger.debug("Get {} interfaces on {}, hwsku {}".format(num, vm_name, hwsku))
        if hwsku == "cisco-8101-p4-32x100-vs":
            pytest_assert(num == 32)

    dut = duthosts[rand_one_dut_hostname]
    num, hwsku = find_node_interfaces(dut)
    logger.debug("Get {} interfaces on {}, hwsku {}".format(num, "dut", hwsku))
    if hwsku == "cisco-8101-p4-32x100-vs":
        pytest_assert(num == 32)


#
# Test Case: Check BGP neighbors
#
def test_check_bgp_neighbors(duthosts, rand_one_dut_hostname, nbrhosts):
    logger.info("Check BGP Neighbors")
    # From PE3
    nbrhost = nbrhosts["PE3"]['host']
    pytest_assert(
        wait_until(
            60, 10, 0, check_bgp_neighbors_func, nbrhost,
            ['2064:100::1d', '2064:200::1e', 'fc06::2', 'fc08::2']
        ),
        "wait for PE3 BGP neighbors up"
    )
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From PE1
    nbrhost = nbrhosts["PE1"]['host']
    check_bgp_neighbors(nbrhost, ['2064:300::1f', '2064:200::1e', 'fc00::71', 'fc02::2'])
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From PE2
    nbrhost = nbrhosts["PE2"]['host']
    check_bgp_neighbors(nbrhost, ['2064:300::1f', '2064:100::1d', 'fc00::75', 'fc03::2'])
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From P1
    dut = duthosts[rand_one_dut_hostname]
    check_bgp_neighbors(dut, ['fc00::72', 'fc00::76', 'fc00::7e', 'fc01::85', 'fc00::81'])
    # From P3
    nbrhost = nbrhosts["P3"]['host']
    check_bgp_neighbors(nbrhost, ['fc02::1', 'fc04::1', 'fc00::7d', 'fc03::1', 'fc09::1'])
    # From P2
    nbrhost = nbrhosts["P2"]['host']
    check_bgp_neighbors(nbrhost, ['fc00::82', 'fc09::2', 'fc07::1', 'fc08::1'])
    # From P4
    nbrhost = nbrhosts["P4"]['host']
    check_bgp_neighbors(nbrhost, ['fc01::86', 'fc04::2', 'fc07::2', 'fc06::1'])


#
# Test Case: Check VPN routes both local learnt and remote learnt and core routes
#
def test_check_routes(duthosts, rand_one_dut_hostname, nbrhosts):
    global_route = ""
    is_v6 = True

    # From PE3
    nbrhost = nbrhosts["PE3"]['host']
    logger.info("Check learnt vpn routes")
    # check remote learnt VPN routes via two PE1 and PE2
    dut1_ips = []
    for x in range(1, num_ce_routes+1):
        ip = "{}.{}/32".format(route_prefix_for_pe1_and_pe2, x)
        dut1_ips.append(ip)
    check_routes(nbrhost, dut1_ips, ["2064:100::1d", "2064:200::1e"], "Vrf1")

    # check local learnt VPN routes via local PE
    dut2_ips = []
    for x in range(1, num_ce_routes+1):
        ip = "{}.{}/32".format(route_prefix_for_pe3, x)
        dut2_ips.append(ip)
    check_routes(nbrhost, dut2_ips, ["10.10.246.254"], "Vrf1")
    # Check core routes
    check_routes(
        nbrhost, ["fd00:201:201:11::", "fd00:202:202:22::"],
        ["fc08::2", "fc06::2"], global_route, is_v6
    )

    # NHG chain correlation: zebra Nexthop Group ID -> APPL_STATE_DB ->
    # APPL_DB ROUTE_TABLE. Single SSH round-trip per route.
    logger.info("Check NHG chain for VRF1 SRv6 VPN routes")
    for ip in dut1_ips:
        check_vrf_route_nhg_chain(nbrhost, "Vrf1", ip)

    logger.info("Check NHG chain for global IPv6 core/loopback routes")
    for v6_prefix in ["fd00:201:201:11::", "fd00:202:202:22::",
                      "2064:100::1d", "2064:200::1e"]:
        check_v6_route_nhg_chain(nbrhost, v6_prefix)


#
# Test Case : Traffic check in Normal Case
#
def test_traffic_check_normal(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    if tbinfo["topo"]["name"] not in ["ciscovs-7nodes"]:
        pytest.skip("SRv6 data plane only available on ciscovs topologies")

    tcp_pkt0 = simple_tcp_packet(
        ip_src="192.200.0.1",
        ip_dst="192.100.0.1",
        tcp_sport=8888,
        tcp_dport=6666,
        ip_ttl=64
    )
    pkt = tcp_pkt0.copy()
    pkt['Ether'].dst = sender_mac

    exp_pkt = tcp_pkt0.copy()
    exp_pkt['IP'].ttl -= 4
    masked2recv = Mask(exp_pkt)
    masked2recv.set_do_not_care_scapy(scapy.Ether, "dst")
    masked2recv.set_do_not_care_scapy(scapy.Ether, "src")

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_check"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)

    # Add retry for debugging purpose
    count = 0
    done = False
    while count < 10 and done is False:
        try:
            runSendReceive(pkt, ptf_port_for_backplane, masked2recv, [ptf_port_for_backplane], True, ptfadapter)
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Retry round {}, Excetpion {}".format(count, e))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down"
                .format(sleep_duration_for_retry)
            )

    # Disable tcpdump
    disable_tcpdump(True)

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")


#
# Test Case : Local Link flap test with zebra debug log collecting
#
def test_traffic_check_local_link_fail_case(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    filename = "zebra_case_1_locallink_down.txt"
    docker_filename = "/tmp/{}".format(filename)
    vm = "PE3"
    pe3 = nbrhosts[vm]['host']
    p2 = nbrhosts["P2"]['host']

    logname = "zebra_case_1_locallink_down_running_log.txt"
    # Recording
    recording_fwding_chain(pe3, logname, "Before starting local link fail case")
    #
    # Turn on frr debug
    #
    turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm, True)
    #
    # shut down the link between PE3 and P2
    #
    cmd = "sudo ifconfig Ethernet4 down"
    pe3.command(cmd)
    cmd = "sudo ifconfig Ethernet12 down"
    p2.command(cmd)
    time.sleep(sleep_duration)
    # expect remaining BGP session are up on PE3
    ret1 = wait_until(
        bgp_neighbor_down_wait_time,
        10, 0, check_bgp_neighbors_func,
        pe3, ['2064:100::1d', '2064:200::1e', 'fc06::2'])

    # Recording
    recording_fwding_chain(pe3, logname, "After local link down")

    #
    # Recover local links
    #
    cmd = "sudo ifconfig Ethernet4 up"
    pe3.command(cmd)
    cmd = "sudo ifconfig Ethernet12 up"
    p2.command(cmd)
    time.sleep(sleep_duration)

    # Recording
    recording_fwding_chain(pe3, logname, "After the local link gets recovered")

    #
    # Turn off frr debug and collect debug log
    #
    turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm, False)
    collect_frr_debugfile(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm)

    # expect remaining BGP session are up on PE3
    pytest_assert(ret1, "wait for PE3 BGP neighbors to settle down")
    # expect All BGP session are up on PE3
    pytest_assert(wait_until(
        bgp_neighbor_up_wait_time,
        10, 0,
        check_bgp_neighbors_func, pe3,
        ['2064:100::1d', '2064:200::1e', 'fc08::2', 'fc06::2']),
        "wait for PE3 BGP neighbors up")


#
# Test Case : remote IGP Link flap test with zebra debug log collecting
#
def test_traffic_check_remote_igp_fail_case(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    filename = "zebra_case_2_remotelink_down.txt"
    docker_filename = "/tmp/{}".format(filename)
    vm = "PE3"
    pe3 = nbrhosts[vm]['host']

    logname = "zebra_case_2_remotelink_down_running_log.txt"
    # Recording
    recording_fwding_chain(pe3, logname, "Before starting remote link fail case")
    #
    # Turn on frr debug
    #
    turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm, True)
    #
    # shut down the link between P3 and P1, P2, P4
    #
    p1 = duthosts[rand_one_dut_hostname]
    p2 = nbrhosts["P2"]['host']
    p3 = nbrhosts["P3"]['host']
    p4 = nbrhosts["P4"]['host']

    cmd = "sudo ifconfig Ethernet124 down"
    p1.command(cmd)
    cmd = "sudo ifconfig Ethernet4 down"
    p2.command(cmd)
    cmd = "sudo ifconfig Ethernet4 down"
    p4.command(cmd)

    cmd = "sudo ifconfig Ethernet0 down"
    p3.command(cmd)
    cmd = "sudo ifconfig Ethernet12 down"
    p3.command(cmd)
    cmd = "sudo ifconfig Ethernet16 down"
    p3.command(cmd)

    time.sleep(sleep_duration)
    # expect no BGP session change on PE3
    ret1 = wait_until(
        5, 1, 0, check_bgp_neighbors_func,
        pe3, ['2064:100::1d', '2064:200::1e', 'fc08::2', 'fc06::2']
    )

    # Recording
    recording_fwding_chain(pe3, logname, "After the remote IGP link is down")
    #
    # Recover back
    #
    cmd = "sudo ifconfig Ethernet124 up"
    p1.command(cmd)
    cmd = "sudo ifconfig Ethernet4 up"
    p2.command(cmd)
    cmd = "sudo ifconfig Ethernet4 up"
    p4.command(cmd)

    cmd = "sudo ifconfig Ethernet0 up"
    p3.command(cmd)
    cmd = "sudo ifconfig Ethernet12 up"
    p3.command(cmd)
    cmd = "sudo ifconfig Ethernet16 up"
    p3.command(cmd)
    time.sleep(sleep_duration)

    # Recording
    recording_fwding_chain(pe3, logname, "After the remote IGP link gets recovered")
    #
    # Turn off frr debug and collect debug log
    #
    turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm, False)
    collect_frr_debugfile(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm)

    # expect no BGP session change on PE3
    pytest_assert(ret1, "no change in BGP sessions")

    # expect no BGP session change on PE3
    pytest_assert(wait_until(
        5, 1, 0,
        check_bgp_neighbors_func, pe3,
        ['2064:100::1d', '2064:200::1e', 'fc08::2', 'fc06::2']), "wait for PE3 BGP neighbors up")


#
# Test Case : BGP remote PE failure with zebra debug log collecting
#
def test_traffic_check_remote_bgp_fail_case(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    filename = "zebra_case_3_remote_peer_down.txt"
    docker_filename = "/tmp/{}".format(filename)
    vm = "PE3"
    pe3 = nbrhosts[vm]['host']

    logname = "zebra_case_3_remote_peer_down_running_log.txt"
    # Recording
    recording_fwding_chain(pe3, logname, "Before starting remote PE failure case")
    #
    # Turn on frr debug
    #
    turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm, True)
    #
    # shut down the link between PE1 and P1, P3
    #
    p1 = duthosts[rand_one_dut_hostname]
    pe1 = nbrhosts["PE1"]['host']
    p3 = nbrhosts["P3"]['host']

    cmd = "sudo ifconfig Ethernet112 down"
    p1.command(cmd)
    cmd = "sudo ifconfig Ethernet4 down"
    p3.command(cmd)
    cmd = "sudo ifconfig Ethernet0 down"
    pe1.command(cmd)
    cmd = "sudo ifconfig Ethernet4 down"
    pe1.command(cmd)
    time.sleep(sleep_duration)
    # expect BGP session change on PE3
    ret1 = wait_until(
        bgp_neighbor_down_wait_time, 10, 0,
        check_bgp_neighbors_func, pe3,
        ['2064:100::1d', '2064:200::1e', 'fc08::2', 'fc06::2'])

    # Recording
    recording_fwding_chain(pe3, logname, "After shutting down the remote BGP peer")
    #
    # Recover back
    #
    cmd = "sudo ifconfig Ethernet112 up"
    p1.command(cmd)
    cmd = "sudo ifconfig Ethernet4 up"
    p3.command(cmd)
    cmd = "sudo ifconfig Ethernet0 up"
    pe1.command(cmd)
    cmd = "sudo ifconfig Ethernet4 up"
    pe1.command(cmd)
    time.sleep(sleep_duration)

    # Recording
    recording_fwding_chain(pe3, logname, "After recovering the remote BGP peer")

    #
    # Turn off frr debug and collect debug log
    #
    turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm, False)
    collect_frr_debugfile(duthosts, rand_one_dut_hostname, nbrhosts, docker_filename, vm)

    # expect BGP session change on PE3
    pytest_assert(ret1, "Remote BGP PE down")
    # expect no BGP session change on PE3
    pytest_assert(wait_until(
        bgp_neighbor_up_wait_time, 10, 0,
        check_bgp_neighbors_func, pe3,
        ['2064:100::1d', '2064:200::1e', 'fc08::2', 'fc06::2']),
        "wait for PE3 BGP neighbors up")
def test_topology1_local_failure(duthosts, nbrhosts):
    """Test PIC convergence for Topology 1 when local link (Ethernet12) goes down.

    Verifies that fpmsyncd's NHT backwalk removes fc06::2 from all APPDB
    nexthop groups while keeping fc08::2 present.
    """
    duthost = nbrhosts["PE3"]['host']
    testcase_name = "t1_local"

    apply_config_cmmds_to_vtysh(duthost, TOPO1_STATIC_ROUTES)
    time.sleep(30)

    zebra_debug_file = "/tmp/zebra_log_t1_local.txt"
    test_failed = True
    try:
        assert_appdb_nexthop_present(duthost, "fc06::2")
        assert_appdb_nexthop_present(duthost, "fc08::2")

        turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", True)
        start_record_collection(duthost, testcase_name)

        trigger_ts = get_dut_timestamp(duthost)
        duthost.command("sudo ifconfig Ethernet12 down")

        assert_appdb_nexthop_removed(duthost, "fc06::2", timeout=10)
        assert_appdb_nexthop_present(duthost, "fc08::2")

        verify_nhg_before_routes(duthost, testcase_name, "fc06::2", trigger_ts)
        test_failed = False

    finally:
        # Recovery — bring interface back up
        duthost.command("sudo ifconfig Ethernet12 up")
        time.sleep(20)

        try:
            # Recovery path check: verify NHG re-notification to FPM restores
            # both nexthops in APPDB (exercises NEXTHOP_GROUP_REINSTALL_FPM_ONLY
            # when NHG exits KEEP_AROUND state). Skip if the test already failed
            # to avoid flagging a known bad state.
            if not test_failed:
                assert_appdb_nexthop_present(duthost, "fc06::2")
                assert_appdb_nexthop_present(duthost, "fc08::2")
        finally:
            # Cleanup must run even if the recovery asserts above fail.
            stop_record_collection(duthost, testcase_name)
            turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", False)
            collect_frr_debugfile(duthosts, "", nbrhosts, zebra_debug_file, "PE3")
            apply_config_cmmds_to_vtysh(duthost, TOPO1_STATIC_ROUTES_REMOVE)


def test_topology1_remote_bgp_failure(duthosts, rand_one_dut_hostname, nbrhosts):
    """Test VPN route change from 2 paths to 1 path via BGP session shutdown.

    All learnt VPN routes and IPv6 routes from 2064:100::1d would be withdrawn
    when PE1 shuts its BGP session toward PE3. This tests VPN routes changes
    from 2 paths to 1 path case.
    """
    duthost = nbrhosts["PE3"]['host']
    testcase_name = "t1_remote_bgp"

    pe1_host = nbrhosts["PE1"]['host']

    apply_config_cmmds_to_vtysh(duthost, TOPO1_STATIC_ROUTES)
    time.sleep(30)
    zebra_debug_file = "/tmp/zebra_log_t1_remote_bgp.txt"
    test_failed = True
    try:
        wait_for_vrf_route_recursive_paths(
                duthost, "Vrf1", "192.100.0.1",
                ["2064:100::1d", "2064:200::1e"],
                poll_interval=10, timeout=300,
                remote_host=pe1_host, remote_clear_target="2064:300::1f")
        assert_appdb_nexthop_present(duthost, "2064:100::1d")
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

        turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", True)
        start_record_collection(duthost, testcase_name)

        # Shut BGP session on PE1 toward PE3 — sends NOTIFICATION, immediate withdrawal
        trigger_ts = get_dut_timestamp(duthost)
        pe1_host.command("vtysh -c 'configure terminal' -c 'router bgp 64600' "
                         "-c 'neighbor 2064:300::1f shutdown'")

        assert_appdb_nexthop_removed(duthost, "2064:100::1d", timeout=10)
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

        verify_no_nhg_update(duthost, testcase_name, trigger_ts)
        test_failed = False

    finally:
        try:
            # Recovery — re-enable BGP session
            pe1_host.command("vtysh -c 'configure terminal' -c 'router bgp 64600' "
                             "-c 'no neighbor 2064:300::1f shutdown'")
            time.sleep(10)
            pe1_host.command("vtysh -c 'clear bgp 2064:300::1f'", module_ignore_errors=True)
            duthost.command("vtysh -c 'clear bgp 2064:100::1d'", module_ignore_errors=True)
            wait_for_vrf_route_recursive_paths(
                duthost, "Vrf1", "192.100.0.1",
                ["2064:100::1d", "2064:200::1e"],
                poll_interval=10, timeout=300,
                remote_host=pe1_host, remote_clear_target="2064:300::1f")

            # Recovery path check: verify NHG re-notification to FPM restores
            # both nexthops in APPDB (exercises NEXTHOP_GROUP_REINSTALL_FPM_ONLY
            # when NHG exits KEEP_AROUND state). Skip if the test already failed
            # to avoid flagging a known bad state.
            if not test_failed:
                assert_appdb_nexthop_present(duthost, "2064:100::1d")
                assert_appdb_nexthop_present(duthost, "2064:200::1e")
        finally:
            stop_record_collection(duthost, testcase_name)
            turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", False)
            collect_frr_debugfile(duthosts, "", nbrhosts, zebra_debug_file, "PE3")
            apply_config_cmmds_to_vtysh(duthost, TOPO1_STATIC_ROUTES_REMOVE)



def test_remote_igp_failure(duthosts, rand_one_dut_hostname, nbrhosts):
    """Test PIC edge convergence via IGP link failures (unfiltered, realistic).

    When PE1 loses its IGP paths, P2 and P4 briefly advertise transient longer
    AS-path routes for 2064:100::1d toward PE3 before the final withdrawal
    arrives. These transient paths trigger PE3 to process unwanted route updates
    (route-replace events) before it handles the actual :1d withdrawal. This
    test verifies that even with such transient churn, the dataplane converges
    correctly: 2064:100::1d is removed from APPDB and 2064:200::1e remains.

    No verify_pic_nhg_switch here because the transient route-replace events
    from path hunting produce additional swss record entries that make strict
    NHG ordering verification unreliable.
    """
    duthost = nbrhosts["PE3"]['host']
    p1 = duthosts[rand_one_dut_hostname]
    p3 = nbrhosts["P3"]['host']
    pe1_host = nbrhosts["PE1"]['host']
    testcase_name = "remote_igp"

    debug_cmds = [
        'debug bgp updates',
        'debug bgp neighbor-events',
        'debug bgp zebra',
        'debug zebra events',
        'debug zebra rib',
        'debug zebra rib detailed',
        'debug zebra nht',
        'debug zebra nht detailed',
        'debug zebra dplane',
        'debug zebra nexthop',
        'debug zebra nexthop detail',
        'debug zebra packet',
        'debug zebra packet detail'
    ]

    apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES)

    zebra_debug_file = "/tmp/zebra_bgp_remote_igp.txt"
    try:
        wait_for_vrf_route_recursive_paths(
                    duthost, "Vrf1", "192.100.0.1",
                    ["2064:100::1d", "2064:200::1e"],
                    poll_interval=10, timeout=300,
                    remote_host=pe1_host, remote_clear_target="2064:300::1f")
        assert_appdb_nexthop_present(duthost, "2064:100::1d")
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

        # Shut first IGP path: P1 Ethernet112 (PE1-P1 link)
        p1.command("sudo ifconfig Ethernet112 down")

        # Wait for route replace event to cool down — P2/P4 will send transient
        # longer-AS-path advertisements for :1d during this window
        time.sleep(40)

        turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", True, debug_cmds)
        start_record_collection(duthost, testcase_name)

        # Shut second IGP path: P3 Ethernet4 (PE1-P3 link)
        # This triggers full withdrawal of 2064:100::1d and PIC edge handling
        p3.command("sudo ifconfig Ethernet4 down")

        assert_appdb_nexthop_removed(duthost, "2064:100::1d", timeout=30)
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

    finally:
        try:
            # Recovery — bring interfaces back up
            p1.command("sudo ifconfig Ethernet112 up")
            p3.command("sudo ifconfig Ethernet4 up")
            time.sleep(30)
            pe1_host.command("vtysh -c 'clear bgp 2064:300::1f'", module_ignore_errors=True)
            duthost.command("vtysh -c 'clear bgp 2064:100::1d'", module_ignore_errors=True)
            wait_for_vrf_route_recursive_paths(
                duthost, "Vrf1", "192.100.0.1",
                ["2064:100::1d", "2064:200::1e"],
                poll_interval=10, timeout=300,
                remote_host=pe1_host, remote_clear_target="2064:300::1f",
                local_loopback="2064:300::1f")
            apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES_REMOVE)
        finally:
            stop_record_collection(duthost, testcase_name)
            turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", False, debug_cmds)
            collect_frr_debugfile(duthosts, "", nbrhosts, zebra_debug_file, "PE3")


def test_remote_igp_failure_filtered(duthosts, rand_one_dut_hostname, nbrhosts):
    """Test PIC edge convergence via IGP link failures (filtered, controlled).

    Uses route-map on P2/P4 (outbound) to prevent them from publishing transient
    longer AS-path routes for 2064:100::1d to PE3. Also applies inbound route-map
    on PE3 to reject any such transient paths. Additionally enables
    'bgp suppress-fib-pending' so zebra does not react to route changes until FIB
    install is confirmed, avoiding premature NHG updates.

    With these controls in place, PE3 sees a clean single withdrawal of
    2064:100::1d (no path hunting). Verifies PIC NHG switch to backup nexthop
    2064:200::1e without transient churn in swss record.
    """
    duthost = nbrhosts["PE3"]['host']
    p1 = duthosts[rand_one_dut_hostname]
    p2 = nbrhosts["P2"]['host']
    p3 = nbrhosts["P3"]['host']
    p4 = nbrhosts["P4"]['host']
    pe1_host = nbrhosts["PE1"]['host']
    testcase_name = "remote_igp_filtered"

    debug_cmds = [
        'debug bgp updates',
        'debug bgp neighbor-events',
        'debug bgp zebra',
        'debug zebra events',
        'debug zebra rib',
        'debug zebra rib detailed',
        'debug zebra nht',
        'debug zebra nht detailed',
        'debug zebra dplane',
        'debug zebra nexthop',
        'debug zebra nexthop detail',
        'debug zebra packet',
        'debug zebra packet detail'
    ]

    # Apply AS-path filters to prevent path hunting
    apply_config_cmmds_to_vtysh(p2, P2_OUTBOUND_FILTER)
    apply_config_cmmds_to_vtysh(p4, P4_OUTBOUND_FILTER)
    apply_config_cmmds_to_vtysh(duthost, PE3_INBOUND_FILTER)
    # Enable suppress-fib-pending so zebra won't react to routes until FIB confirmed
    duthost.command("vtysh -c 'configure terminal' -c 'router bgp 64602' "
                    "-c 'bgp suppress-fib-pending'")
    p2.command("sudo vtysh -c 'clear bgp ipv6 unicast fc08::1 soft out'")
    p4.command("sudo vtysh -c 'clear bgp ipv6 unicast fc06::1 soft out'")
    time.sleep(10)

    apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES)

    zebra_debug_file = "/tmp/zebra_bgp_remote_igp_filtered.txt"
    try:
        wait_for_vrf_route_recursive_paths(
                    duthost, "Vrf1", "192.100.0.1",
                    ["2064:100::1d", "2064:200::1e"],
                    poll_interval=10, timeout=300,
                    remote_host=pe1_host, remote_clear_target="2064:300::1f")
        assert_appdb_nexthop_present(duthost, "2064:100::1d")
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

        # Shut first IGP path: P1 Ethernet112 (PE1-P1 link)
        p1.command("sudo ifconfig Ethernet112 down")

        # Wait for route replace event to cool down
        time.sleep(40)

        turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", True, debug_cmds)
        start_record_collection(duthost, testcase_name)

        # Shut second IGP path: P3 Ethernet4 (PE1-P3 link)
        # This triggers full withdrawal of 2064:100::1d and PIC edge handling
        p3.command("sudo ifconfig Ethernet4 down")

        assert_appdb_nexthop_removed(duthost, "2064:100::1d", timeout=30)
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

        verify_pic_nhg_switch(duthost, testcase_name, "2064:200::1e")

    finally:
        try:
            # Recovery - bring interfaces back up
            p1.command("sudo ifconfig Ethernet112 up")
            p3.command("sudo ifconfig Ethernet4 up")
            time.sleep(30)
            # Remove suppress-fib-pending and AS-path filters
            duthost.command("vtysh -c 'configure terminal' -c 'router bgp 64602' "
                            "-c 'no bgp suppress-fib-pending'")
            apply_config_cmmds_to_vtysh(p2, P2_OUTBOUND_FILTER_REMOVE)
            apply_config_cmmds_to_vtysh(p4, P4_OUTBOUND_FILTER_REMOVE)
            apply_config_cmmds_to_vtysh(duthost, PE3_INBOUND_FILTER_REMOVE)
            p2.command("sudo vtysh -c 'clear bgp ipv6 unicast fc08::1 soft out'")
            p4.command("sudo vtysh -c 'clear bgp ipv6 unicast fc06::1 soft out'")
            pe1_host.command("vtysh -c 'clear bgp 2064:300::1f'", module_ignore_errors=True)
            duthost.command("vtysh -c 'clear bgp 2064:100::1d'", module_ignore_errors=True)
            wait_for_vrf_route_recursive_paths(
                duthost, "Vrf1", "192.100.0.1",
                ["2064:100::1d", "2064:200::1e"],
                poll_interval=10, timeout=300,
                remote_host=pe1_host, remote_clear_target="2064:300::1f",
                local_loopback="2064:300::1f")
            apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES_REMOVE)
        finally:
            stop_record_collection(duthost, testcase_name)
            turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", False, debug_cmds)
            collect_frr_debugfile(duthosts, "", nbrhosts, zebra_debug_file, "PE3")


def test_topology2_local_failure(duthosts, nbrhosts):
    """Test PIC convergence for Topology 2 when local link (Ethernet12) goes down.

    Topology 2 has direct + recursive mix. Verifies fc06::2 removed from APPDB
    while fc08::2 remains.
    """
    duthost = nbrhosts["PE3"]['host']
    testcase_name = "t2_local"

    apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES)
    time.sleep(30)
    zebra_debug_file = "/tmp/zebra_log_t2_local.txt"
    test_failed = True
    try:
        assert_appdb_nexthop_present(duthost, "fc06::2")
        assert_appdb_nexthop_present(duthost, "fc08::2")

        turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", True)
        start_record_collection(duthost, testcase_name)

        trigger_ts = get_dut_timestamp(duthost)
        duthost.command("sudo ifconfig Ethernet12 down")

        assert_appdb_nexthop_removed(duthost, "fc06::2", timeout=10)
        assert_appdb_nexthop_present(duthost, "fc08::2")

        verify_nhg_before_routes(duthost, testcase_name, "fc06::2", trigger_ts)
        test_failed = False

    finally:
        # Recovery — bring interface back up
        duthost.command("sudo ifconfig Ethernet12 up")
        time.sleep(20)

        try:
            # Recovery path check: verify NHG re-notification to FPM restores
            # both nexthops in APPDB (exercises NEXTHOP_GROUP_REINSTALL_FPM_ONLY
            # when NHG exits KEEP_AROUND state). Skip if the test already failed
            # to avoid flagging a known bad state.
            if not test_failed:
                assert_appdb_nexthop_present(duthost, "fc06::2")
                assert_appdb_nexthop_present(duthost, "fc08::2")
        finally:
            # Cleanup must run even if the recovery asserts above fail.
            stop_record_collection(duthost, testcase_name)
            turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", False)
            collect_frr_debugfile(duthosts, "", nbrhosts, zebra_debug_file, "PE3")
            apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES_REMOVE)


def test_topology2_remote_bgp_failure(duthosts, rand_one_dut_hostname, nbrhosts):
    """Test VPN route change from 2 paths to 1 path via BGP session shutdown (Topology 2).

    All learnt VPN routes and IPv6 routes from 2064:100::1d would be withdrawn
    when PE1 shuts its BGP session toward PE3. Topology 2 has direct + recursive
    mix. This tests VPN routes changes from 2 paths to 1 path case.
    """
    duthost = nbrhosts["PE3"]['host']
    testcase_name = "t2_remote"

    pe1_host = nbrhosts["PE1"]['host']

    apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES)
    time.sleep(30)
    zebra_debug_file = "/tmp/zebra_log_t2_remote_bgp.txt"
    test_failed = True
    try:
        assert_appdb_nexthop_present(duthost, "2064:100::1d")
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

        turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", True)
        start_record_collection(duthost, testcase_name)

        # Shut BGP session on PE1 toward PE3 — sends NOTIFICATION, immediate withdrawal
        trigger_ts = get_dut_timestamp(duthost)
        pe1_host.command("vtysh -c 'configure terminal' -c 'router bgp 64600' "
                         "-c 'neighbor 2064:300::1f shutdown'")

        assert_appdb_nexthop_removed(duthost, "2064:100::1d", timeout=10)
        assert_appdb_nexthop_present(duthost, "2064:200::1e")

        verify_no_nhg_update(duthost, testcase_name, trigger_ts)
        test_failed = False

    finally:
        try:
            # Recovery — re-enable BGP session
            pe1_host.command("vtysh -c 'configure terminal' -c 'router bgp 64600' "
                             "-c 'no neighbor 2064:300::1f shutdown'")
            time.sleep(10)
            pe1_host.command("vtysh -c 'clear bgp 2064:300::1f'", module_ignore_errors=True)
            duthost.command("vtysh -c 'clear bgp 2064:100::1d'", module_ignore_errors=True)
            wait_for_vrf_route_recursive_paths(
                duthost, "Vrf1", "192.100.0.1",
                ["2064:100::1d", "2064:200::1e"],
                poll_interval=10, timeout=300,
                remote_host=pe1_host, remote_clear_target="2064:300::1f",
                local_loopback="2064:300::1f")

            # Recovery path check: verify NHG re-notification to FPM restores
            # both nexthops in APPDB (exercises NEXTHOP_GROUP_REINSTALL_FPM_ONLY
            # when NHG exits KEEP_AROUND state). Skip if the test already failed
            # to avoid flagging a known bad state.
            if not test_failed:
                assert_appdb_nexthop_present(duthost, "2064:100::1d")
                assert_appdb_nexthop_present(duthost, "2064:200::1e")
        finally:
            stop_record_collection(duthost, testcase_name)
            turn_on_off_frr_debug(duthosts, "", nbrhosts, zebra_debug_file, "PE3", False)
            collect_frr_debugfile(duthosts, "", nbrhosts, zebra_debug_file, "PE3")
            apply_config_cmmds_to_vtysh(duthost, TOPO2_STATIC_ROUTES_REMOVE)



