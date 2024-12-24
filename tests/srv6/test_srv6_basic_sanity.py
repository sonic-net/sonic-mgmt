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
from srv6_utils import recording_fwding_chain
from srv6_utils import turn_on_off_frr_debug
from srv6_utils import collect_frr_debugfile

from common_utils import enable_tcpdump
from common_utils import disable_tcpdump

logger = logging.getLogger(__name__)


#
# Add --skip_sanity when running pytest to avoid current pytest use /etc/sonic/minigraph.xml
# The running option could be removed once the pytest sanity check is enhancemed on using
# this file.
#
pytestmark = [
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("any"),
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
def setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost):
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
def srv6_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost):
    setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost)


#
# Test case: check number of Ethnernet interfaces
#
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
        nbrhost, ["fd00:201:201:fff1:11::", "fd00:202:202:fff2:22::"],
        ["fc08::2", "fc06::2"], global_route, is_v6
    )


#
# Test Case : Traffic check in Normal Case
#
def test_traffic_check(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    #
    # Create a packet sending to 192.100.0.1
    #
    # establish_and_configure_bfd(nbrhosts)
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
