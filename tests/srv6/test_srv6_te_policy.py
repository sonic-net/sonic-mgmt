import time
import logging
import pytest

import ptf.packet as scapy
from ptf.testutils import simple_tcp_packet
from ptf.mask import Mask

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from common_utils import setup_config_for_testbed
from common_utils import enable_tcpdump
from common_utils import disable_tcpdump

from srv6_utils import check_bgp_neighbors
from srv6_utils import runSendReceive
from srv6_utils import check_bfd_status
from srv6_utils import find_node_interfaces
from srv6_utils import announce_route
from srv6_utils import check_bgp_neighbors_func
from srv6_utils import Get_route_group_id
from srv6_utils import check_vpn_route_info
from srv6_utils import check_route_nexthop_group

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("ciscovs-7nodes"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health,
]

test_vm_names = ["PE1", "PE2", "PE3", "P2", "P3", "P4"]
sender_mac = "52:54:00:df:1c:5e"  # From PE3

#
# The port used by ptf to connect with backplane. This number is different from 3 ndoe case.
#
ptf_port_for_backplane = 18
ptf_port_for_pe21_to_p21 = 39

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

    setup_config_for_testbed(
        duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, test_vm_names, "7nodes_te"
    )

    time.sleep(300)
    logger.info("Announce routes from CEs")
    ptfip = ptfhost.mgmt_ip
    nexthop = "10.10.246.254"
    port_num = [5000, 5001, 5002]

    # Publish to PE1
    neighbor = "10.10.246.29"
    # Publish to PE2
    neighbor2 = "10.10.246.30"
    for x in range(1, num_ce_routes + 1):
        route = "{}.{}/32".format(route_prefix_for_pe1_and_pe2, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[0])
        announce_route(ptfip, neighbor2, route, nexthop, port_num[1])

    # Publish to PE3
    neighbor = "10.10.246.31"
    for x in range(1, num_ce_routes + 1):
        route = "{}.{}/32".format(route_prefix_for_pe3, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[2])

    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'bfd' "
        "-c 'peer 2064:300::1f  bfd-mode sbfd-echo  bfd-name bfd-b local-address 2064:300::1f "
        "encap-type SRv6 encap-data fd00:205:205:fff5:5:: source-ipv6 2064:300::1f'  "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'bfd' "
        "-c 'peer 2064:300::1f  bfd-mode sbfd-echo  bfd-name bfd-c local-address 2064:300::1f "
        "encap-type SRv6 encap-data fd00:206:206:fff6:6:: source-ipv6 2064:300::1f'  "
    )

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
def srv6_te_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost):
    setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost)


def test_interface_on_each_node(duthosts, rand_one_dut_hostname, nbrhosts):
    for vm_name in test_vm_names:
        nbrhost = nbrhosts[vm_name]["host"]
        num, hwsku = find_node_interfaces(nbrhost)
        logger.debug("Get {} interfaces on {}, hwsku {}".format(num, vm_name, hwsku))
        if hwsku == "cisco-8101-p4-32x100-vs":
            pytest_assert(num == 32)

    dut = duthosts[rand_one_dut_hostname]
    num, hwsku = find_node_interfaces(dut)
    logger.debug("Get {} interfaces on {}, hwsku {}".format(num, "dut", hwsku))
    if hwsku == "cisco-8101-p4-32x100-vs":
        pytest_assert(num == 32)


def test_check_bgp_neighbors(duthosts, rand_one_dut_hostname, nbrhosts):
    logger.info("Check BGP Neighbors")
    # From PE3
    nbrhost = nbrhosts["PE3"]["host"]
    pytest_assert(
        wait_until(
            60,
            10,
            0,
            check_bgp_neighbors_func,
            nbrhost,
            ["2064:100::1d", "2064:200::1e", "fc06::2", "fc08::2"],
        ),
        "wait for PE3 BGP neighbors up",
    )
    check_bgp_neighbors(nbrhost, ["10.10.246.254"], "Vrf1")
    # From PE1
    nbrhost = nbrhosts["PE1"]["host"]
    check_bgp_neighbors(
        nbrhost, ["2064:300::1f", "2064:200::1e", "fc00::71", "fc02::2"]
    )
    check_bgp_neighbors(nbrhost, ["10.10.246.254"], "Vrf1")
    # From PE2
    nbrhost = nbrhosts["PE2"]["host"]
    check_bgp_neighbors(
        nbrhost, ["2064:300::1f", "2064:100::1d", "fc00::75", "fc03::2"]
    )
    check_bgp_neighbors(nbrhost, ["10.10.246.254"], "Vrf1")
    # From P1
    dut = duthosts[rand_one_dut_hostname]
    check_bgp_neighbors(
        dut, ["fc00::72", "fc00::76", "fc00::7e", "fc01::85", "fc00::81"]
    )
    # From P3
    nbrhost = nbrhosts["P3"]["host"]
    check_bgp_neighbors(
        nbrhost, ["fc02::1", "fc04::1", "fc00::7d", "fc03::1", "fc09::1"]
    )
    # From P2
    nbrhost = nbrhosts["P2"]["host"]
    check_bgp_neighbors(nbrhost, ["fc00::82", "fc09::2", "fc07::1", "fc08::1"])
    # From P4
    nbrhost = nbrhosts["P4"]["host"]
    check_bgp_neighbors(nbrhost, ["fc01::86", "fc04::2", "fc07::2", "fc06::1"])


def test_check_te_policy_route_info(nbrhosts):
    logger.info("Check route information")
    nbrhost = nbrhosts["PE3"]["host"]
    check_vpn_route_info(
        nbrhost,
        ["192.100.0.1/32", "192.100.0.2/32"],
        "01:3",
        "2064:200::1e",
        "3",
        "Vrf1",
    )
    check_vpn_route_info(
        nbrhost,
        ["192.100.0.1/32", "192.100.0.2/32"],
        "01:1",
        "2064:100::1d",
        "1",
        "Vrf1",
    )
    logger.info("Check nexthop group information")
    nexthop_id, pic_id = Get_route_group_id(nbrhost, "192.100.0.1/32", False, "Vrf1")
    check_route_nexthop_group(nbrhost, nexthop_id, 6)
    check_route_nexthop_group(nbrhost, pic_id, 2)
    logger.info("End test_check_te_policy_route_info")


def test_traffic_single_policy_check_1(
    tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter
):
    tcp_pkt0 = simple_tcp_packet(
        ip_src="192.200.0.2",
        ip_dst="192.100.0.1",
        tcp_sport=8888,
        tcp_dport=6666,
        ip_ttl=64,
    )
    pkt = tcp_pkt0.copy()
    pkt["Ether"].dst = sender_mac
    exp_pkt = tcp_pkt0.copy()
    exp_pkt["IP"].ttl -= 4
    masked2recv = Mask(exp_pkt)
    masked2recv.set_do_not_care_packet(scapy.Ether, "dst")
    masked2recv.set_do_not_care_packet(scapy.Ether, "src")

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_single_policy_check_1"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)

    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 3 endpoint 2064:200::1e' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 100 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 1 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 2 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'"
    )

    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )
    time.sleep(2)
    # Add retry for debugging purpose
    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")

    nbrhosts["P2"]["host"].shell(
        "sudo vtysh -c  'configure terminal' -c 'router bgp 65102' "
        "-c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'"
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["down", "up"],
        ),
        "Bfd not established!",
    )

    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")
    # Disable tcpdump
    disable_tcpdump(True)
    nbrhosts["P2"]["host"].shell(
        "sudo vtysh -c  'configure terminal' -c 'router bgp 65102' "
        "-c 'address-family ipv6 unicast' "
        "-c 'redistribute static route-map srv6_r'"
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )


def test_traffic_single_policy_check_2(
    tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter
):
    tcp_pkt0 = simple_tcp_packet(
        ip_src="192.200.0.2",
        ip_dst="192.100.0.1",
        tcp_sport=8888,
        tcp_dport=6666,
        ip_ttl=64,
    )
    pkt = tcp_pkt0.copy()
    pkt["Ether"].dst = sender_mac

    exp_pkt = tcp_pkt0.copy()
    exp_pkt["IP"].ttl -= 4
    masked2recv = Mask(exp_pkt)
    masked2recv.set_do_not_care_packet(scapy.Ether, "dst")
    masked2recv.set_do_not_care_packet(scapy.Ether, "src")

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_single_policy_check_2"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)
    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 3 endpoint 2064:200::1e' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 1 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'"
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )

    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            logger.info("Exception {}".format(e))
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )
    # Disable tcpdump
    disable_tcpdump(True)
    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")


def test_traffic_multi_policy_check_3(
    tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter
):
    tcp_pkt0 = simple_tcp_packet(
        ip_src="192.200.0.2",
        ip_dst="192.100.0.1",
        tcp_sport=8888,
        tcp_dport=6666,
        ip_ttl=64,
    )
    pkt = tcp_pkt0.copy()
    pkt["Ether"].dst = sender_mac

    exp_pkt = tcp_pkt0.copy()
    exp_pkt["IP"].ttl -= 4
    masked2recv = Mask(exp_pkt)
    masked2recv.set_do_not_care_packet(scapy.Ether, "dst")
    masked2recv.set_do_not_care_packet(scapy.Ether, "src")

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_multi_policy_check_3"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)
    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 3 endpoint 2064:200::1e' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 1 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 3 endpoint 2064:200::1e' "
        "-c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'"
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )
    # Add retry for debugging purpose
    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    # Disable tcpdump
    disable_tcpdump(True)
    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")


def test_traffic_multi_policy_check_4(
    tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter
):
    tcp_pkt0 = simple_tcp_packet(
        ip_src="192.200.0.2",
        ip_dst="192.100.0.1",
        tcp_sport=8888,
        tcp_dport=6666,
        ip_ttl=64,
    )
    pkt = tcp_pkt0.copy()
    pkt["Ether"].dst = sender_mac

    exp_pkt = tcp_pkt0.copy()
    exp_pkt["IP"].ttl -= 4
    masked2recv = Mask(exp_pkt)
    masked2recv.set_do_not_care_packet(scapy.Ether, "dst")
    masked2recv.set_do_not_care_packet(scapy.Ether, "src")

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_multi_policy_check_4"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)
    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 3 endpoint 2064:200::1e' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 1 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 3 endpoint 2064:200::1e' "
        "-c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'"
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )

    # Add retry for debugging purpose
    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    # Disable tcpdump
    disable_tcpdump(True)
    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")

    nbrhosts["P2"]["host"].shell(
        "sudo vtysh -c  'configure terminal' -c 'router bgp 65102' "
        "-c 'address-family ipv6 unicast' "
        "-c 'no redistribute static route-map srv6_r'"
    )
    pytest_assert(
        wait_until(
            100, 1, 0, check_bfd_status, nbrhosts["PE3"]["host"], ["b"], ["down"]
        ),
        "Bfd not established!",
    )

    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")
    nbrhosts["P2"]["host"].shell(
        "sudo vtysh -c  'configure terminal' -c 'router bgp 65102' "
        "-c 'address-family ipv6 unicast' -c ' redistribute static route-map srv6_r'"
    )
    pytest_assert(
        wait_until(100, 1, 0, check_bfd_status, nbrhosts["PE3"]["host"], ["b"], ["up"]),
        "Bfd not established!",
    )


def test_traffic_multi_policy_check_5(
    tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter
):
    tcp_pkt0 = simple_tcp_packet(
        ip_src="192.200.0.2",
        ip_dst="192.100.0.1",
        tcp_sport=8888,
        tcp_dport=6666,
        ip_ttl=64,
    )
    pkt = tcp_pkt0.copy()
    pkt["Ether"].dst = sender_mac

    exp_pkt = tcp_pkt0.copy()
    exp_pkt["IP"].ttl -= 4
    masked2recv = Mask(exp_pkt)
    masked2recv.set_do_not_care_packet(scapy.Ether, "dst")
    masked2recv.set_do_not_care_packet(scapy.Ether, "src")

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_multi_policy_check_5"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)

    time.sleep(2)
    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 3 endpoint 2064:200::1e' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 1 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1  bfd-name bfd-b'"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1  bfd-name bfd-c'"
    )

    dut = duthosts[rand_one_dut_hostname]
    dut.command(
        "sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    dut.command(
        "sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right_to_05 seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P2"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P3"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P3"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'ipv6 prefix-list srv6_right_to_06 seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P4"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' "
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )
    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")

    nbrhosts["P4"]["host"].shell(
        "sudo vtysh -c  'configure terminal' -c 'router bgp 65103' "
        "-c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'"
    )
    nbrhosts["P2"]["host"].shell(
        "sudo vtysh -c 'configure terminal' -c 'router bgp 65102' "
        "-c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'"
    )

    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["down", "down"],
        ),
        "Bfd not established!",
    )

    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))

            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")

    dut.command(
        "sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    dut.command(
        "sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right_to_05 seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P2"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'no ipv6 prefix-list srv6_right seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P3"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'no ipv6 prefix-list srv6_right seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P3"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'no ipv6 prefix-list srv6_right_to_06 seq 50 "
        "permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhosts["P4"]["host"].command(
        "sudo vtysh -c 'configure terminal' "
        "-c 'no ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' "
    )
    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 1 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 3 endpoint 2064:200::1e' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name a explicit-srv6 segment-list a weight 1 '"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 '"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 3 endpoint 2064:200::1e' "
        "-c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 '"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 3 endpoint 2064:200::1e' "
        "-c ' candidate-path preference 1 name d explicit-srv6 segment-list d weight 1 '"
    )
    nbrhosts["P4"]["host"].shell(
        "sudo vtysh -c  'configure terminal' -c 'router bgp 65103' "
        "-c 'address-family ipv6 unicast' -c 'redistribute static route-map srv6_r'"
    )
    nbrhosts["P2"]["host"].shell(
        "sudo vtysh -c 'configure terminal' -c 'router bgp 65102' "
        "-c 'address-family ipv6 unicast' -c ' redistribute static route-map srv6_r'"
    )

    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )


def test_traffic_multi_policy_check_6(
    tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter
):
    tcp_pkt0 = simple_tcp_packet(
        ip_src="192.200.0.2",
        ip_dst="192.100.0.1",
        tcp_sport=8888,
        tcp_dport=6666,
        ip_ttl=64,
    )
    pkt = tcp_pkt0.copy()
    pkt["Ether"].dst = sender_mac

    exp_pkt = tcp_pkt0.copy()
    exp_pkt["IP"].ttl -= 4
    masked2recv = Mask(exp_pkt)
    masked2recv.set_do_not_care_packet(scapy.Ether, "dst")
    masked2recv.set_do_not_care_packet(scapy.Ether, "src")

    # Enable tcpdump for debugging purpose, file_loc is host file location

    nbrhost = nbrhosts["PE3"]["host"]
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'no policy color 3 endpoint 2064:200::1e' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng'"
        " -c 'no policy color 1 endpoint 2064:100::1d' "
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1  bfd-name bfd-b'"
    )
    nbrhost.command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' "
        "-c 'policy color 1 endpoint 2064:100::1d' "
        "-c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1  bfd-name bfd-c'"
    )
    nbrhosts["PE2"]["host"].command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' "
        "-c 'no locator lsid1' "
    )
    nbrhosts["PE2"]["host"].command(
        "sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' "
        "-c 'locator lsid1 ' "
        "-c 'prefix fd00:202:202::/48 block-len 32  node-len 16 func-bits 32'  "
        "-c 'opcode ::fff2:2:0:0:0  end-dt46 vrf Vrf1' "
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "up"],
        ),
        "Bfd not established!",
    )
    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")

    nbrhosts["P4"]["host"].shell(
        "sudo vtysh -c 'configure terminal' -c 'router bgp 65103' "
        "-c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'"
    )
    pytest_assert(
        wait_until(
            100,
            1,
            0,
            check_bfd_status,
            nbrhosts["PE3"]["host"],
            ["b", "c"],
            ["up", "down"],
        ),
        "Bfd not established!",
    )

    count = 0
    done = False
    while count < 10 and not done:
        try:
            runSendReceive(
                pkt,
                ptf_port_for_backplane,
                masked2recv,
                [ptf_port_for_backplane],
                True,
                ptfadapter,
            )
            logger.info("Done with traffic run")
            done = True
        except Exception as e:
            count = count + 1
            logger.info("Failed {}, Retry round {}".format(e, count))
            # sleep make sure all forwarding structures are settled down.
            sleep_duration_for_retry = 60
            time.sleep(sleep_duration_for_retry)
            logger.info(
                "Sleep {} seconds to make sure all forwarding structures are settled down".format(
                    sleep_duration_for_retry
                )
            )

    logger.info("Done {} count {}".format(done, count))
    if not done:
        raise Exception("Traffic test failed")
