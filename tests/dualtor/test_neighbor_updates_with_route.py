import pytest
import logging
import random
import ipaddress

from ptf import testutils
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.dualtor.dual_tor_mock import set_mux_state
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import get_ptf_server_intf_index
from tests.common.dualtor.dual_tor_utils import add_nexthop_routes
from tests.common.fixtures.ptfhost_utils import run_icmp_responder              # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service                # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory         # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses            # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type                     # noqa F401


"""
Tests a corner case where neighbor entry is learned on mux but routes are also advertised on
up/downstream with same prefix

    1. Neighbor learned on standby mux
    2. Neighbor learned on active mux
    3. Route advertised on Vlan
    4. Route advertised on PortChannel

These steps are repeated for 20 iterations.

Expectation:
    When neighbor is resolved, a neighbor entry should be added and configured for respective mux status
        - Standby: neighbor is disabled and route entry created pointing to tunnel nexthop
        - Active: neighbor is disabled and route entry should not exist

    When a route is learned, route entry should match the learned route

    Orchagent should not crash.
"""

ACTIVE = 'active'
STANDBY = 'standby'

pytestmark = [
    pytest.mark.topology('dualtor'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'run_garp_service',
                            'run_icmp_responder')
]


@pytest.fixture(params=['ipv4', 'ipv6'])
def ip_version(request):
    """Traffic IP version to test."""
    return request.param


def get_show_arp(dut):
    """
    returns
    """
    interface_mac_dict = {}
    arp = dut.shell("show arp")["stdout"].splitlines()
    for line in arp:
        entry = line.split()
        interface_mac_dict[entry[2]] = entry[1]
    return interface_mac_dict


def get_show_ndp(dut):
    """
    returns
    """
    interface_mac_dict = {}
    arp = dut.shell("show ndp")["stdout"].splitlines()
    for line in arp:
        entry = line.split()
        interface_mac_dict[entry[2]] = entry[1]
    return interface_mac_dict


@pytest.fixture
def testbed_setup(
    ip_version,
    tbinfo,
    tor_mux_intfs,
    rand_selected_dut,
    toggle_all_simulator_ports
):
    """
    Sets up test facts for test_neighbor_update_route_set.

    Returns:
        dict: dictionary of test details in the form below:

        {
            "active": {
                "iface": <interface name>,
                "neighbor_mac": <neighbor mac on interface>,
                "server_ip": <server ip on interface>,
                "ptf_index": <ptf index of interface>,
            },
            "standby": {
                "iface": <interface name>,
                "neighbor_mac": <neighbor mac on interface>,
                "server_ip": <server ip on interface>,
                "ptf_index": <ptf index of interface>,
            },
            "portchannels": {
                "nexthops": [list of nexthops]
            }
        }
    """
    dut = rand_selected_dut

    server_ip = mux_cable_server_ip(dut)
    if ip_version == "ipv4":
        neighbor_mac_map = get_show_arp(dut)
    elif ip_version == "ipv6":
        neighbor_mac_map = get_show_ndp(dut)

    mux_intfs = random.sample(tor_mux_intfs, k=2)
    logging.info(f"Randomly selected {mux_intfs} for testing")

    test_facts = {}

    ipversion = str(ip_version)[-1]

    # Get downstream interface info
    for i, state in enumerate([ACTIVE, STANDBY]):
        iface = mux_intfs[i]
        test_facts[state] = {}
        test_facts[state]["iface"] = iface
        test_facts[state]["neighbor_mac"] = neighbor_mac_map[iface]
        test_facts[state]['server_ip'] = str(server_ip[iface][f"server_{ip_version}"]).split("/")[0]
        test_facts[state]['ptf_index'] = get_ptf_server_intf_index(dut, tbinfo, iface)

    active_port = test_facts[ACTIVE]["iface"]
    standby_port = test_facts[STANDBY]["iface"]
    logging.info(f"Testing active {active_port}, standby {standby_port}")

    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    portchannel_interfaces = mg_facts["minigraph_portchannel_interfaces"]
    # Get upstream interface info
    test_facts["portchannels"] = {}
    nexthops = []
    for iface in portchannel_interfaces:
        # iface_name = iface["attachto"]
        if ipaddress.ip_address(iface["addr"]).version == ipversion:
            nexthops.append(iface["addr"])

    test_facts["portchannels"]["nexthops"] = nexthops

    # Set mux ports to Standby and active
    logging.info(f"Set {active_port} to {ACTIVE} state")
    set_mux_state(dut, tbinfo, ACTIVE, [active_port], toggle_all_simulator_ports)

    logging.info(f"Set {standby_port} to {STANDBY} state")
    set_mux_state(dut, tbinfo, STANDBY, [standby_port], toggle_all_simulator_ports)

    logging.info(f"Test details: {test_facts}")
    return test_facts


def send_garp(ptfadapter, ip, src_mac, iface):
    pkt = testutils.simple_arp_packet(
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_src=src_mac,
                arp_op=2,
                ip_snd=ip,
                ip_tgt=ip,
                hw_snd=src_mac,
                hw_tgt='ff:ff:ff:ff:ff:ff'
            )

    logging.info("Sending GARP for target {} from PTF interface {}".format(ip, iface))
    testutils.send_packet(ptfadapter, iface, pkt)


def test_neighbor_update_with_route_set(
    ptfhost,
    tbinfo,
    ip_version,
    ptfadapter,
    testbed_setup,
    rand_selected_dut,
    iterations=20
):
    if ip_version == "ipv4":
        ip = "25.66.230.0"
        prefix = f"{ip}/32"
    elif ip_version == "ipv6":
        ip = "2025::ffff"
        prefix = f"{ip}/128"

    dut = rand_selected_dut
    active_port = testbed_setup[ACTIVE]["iface"]
    standby_port = testbed_setup[STANDBY]["iface"]

    # Start test loop:
    for i in range(iterations):
        logging.info(f"Start test iteration {i}")

        logging.info(f"Add neighbor {ip} to standby mux port {standby_port}")
        send_garp(ptfadapter, ip, testbed_setup[STANDBY]['neighbor_mac'], testbed_setup[STANDBY]['ptf_index'])

        logging.info(f"Add neighbor {ip} to active mux port {active_port}")
        send_garp(ptfadapter, ip, testbed_setup[ACTIVE]['neighbor_mac'], testbed_setup[ACTIVE]['ptf_index'])

        nexthops = [testbed_setup[ACTIVE]["server_ip"]]
        logging.info(f"Set route {prefix} with nexthop(s) {nexthops}")
        add_nexthop_routes(dut, ip, nexthops=nexthops)

        nexthops = testbed_setup["portchannels"]["nexthops"]
        logging.info(f"Set route {prefix} with nexthop(s) {nexthops}")
        add_nexthop_routes(dut, ip, nexthops=nexthops)

        verify_orchagent_running_or_assert(dut)
