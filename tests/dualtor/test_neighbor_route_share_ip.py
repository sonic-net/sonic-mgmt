import pytest
import logging
import random
import ipaddress

from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import get_ptf_server_intf_index
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.dualtor.dual_tor_utils import force_active_tor, force_standby_tor     # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                      # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service                        # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                 # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                    # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type                             # noqa F401


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
TEST_SCRIPT_SRC = "scripts/dualtor_neighbor_route_share_ip.py"
TEST_SCRIPT_DST = "/tmp/dualtor_neighbor_route_share_ip.py"

pytestmark = [
    pytest.mark.topology('dualtor'),
    pytest.mark.usefixtures('run_garp_service',
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
    force_active_tor, force_standby_tor,    # noqa F811
):
    """
    Sets up test facts for test_neighbor_update_route_set.

    Returns:
        dict: dictionary of test details in the form below:

        {
            "vlan": <vlan>
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
                "if_names": [list of if_names]
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
    vlan = list(mg_facts["minigraph_vlans"].keys())[0]
    # Get upstream interface info
    test_facts["vlan"] = vlan
    test_facts["portchannels"] = {}
    if_names = []
    nexthops = []
    for iface in portchannel_interfaces:
        version = ipaddress.ip_address(iface["peer_addr"]).version
        if str(version) == str(ipversion):
            peer_addr = iface["peer_addr"]
            attachto = iface["attachto"]
            nexthops.append(peer_addr)
            if_names.append(attachto)

    test_facts["portchannels"]["nexthops"] = ",".join(nexthops)
    test_facts["portchannels"]["if_names"] = ",".join(if_names)

    # Set mux ports to Standby and active
    logging.info(f"Set {active_port} to {ACTIVE} state")
    force_active_tor(dut, [active_port])

    logging.info(f"Set {standby_port} to {STANDBY} state")
    force_standby_tor(dut, [standby_port])

    logging.info(f"Test details: {test_facts}")
    return test_facts


def test_neighbor_route_share_ip(
    ptfhost,
    tbinfo,
    ip_version,
    ptfadapter,
    testbed_setup,
    rand_selected_dut,
    rand_unselected_dut,
    iterations=20
):
    if ip_version == "ipv4":
        ip = "25.66.230.0"
    elif ip_version == "ipv6":
        ip = "2025::ffff"

    vlan = testbed_setup["vlan"]
    neighbor_standby = testbed_setup[STANDBY]['neighbor_mac']
    neighbor_active = testbed_setup[ACTIVE]['neighbor_mac']
    vlan_nexthop_standby = testbed_setup[STANDBY]["server_ip"]
    vlan_nexthop_active = testbed_setup[ACTIVE]["server_ip"]
    portchannel_nexthops = testbed_setup["portchannels"]["nexthops"]
    portchannel_interfaces = testbed_setup["portchannels"]["if_names"]

    logging.info(f"Copy test script to duthosts, src: {TEST_SCRIPT_SRC} dst: {TEST_SCRIPT_DST}")
    rand_selected_dut.copy(src=TEST_SCRIPT_SRC, dest=TEST_SCRIPT_DST)
    rand_unselected_dut.copy(src=TEST_SCRIPT_SRC, dest=TEST_SCRIPT_DST)

    # Start test loop:
    logging.info(f"Start test {TEST_SCRIPT_DST} with {iterations} iterations")
    with SafeThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(rand_selected_dut.shell, f"python {TEST_SCRIPT_DST} \
            --vlan-if {vlan}                                                \
            --portchannel-if {portchannel_interfaces}                       \
            --standby-mac {neighbor_standby}                                \
            --active-mac {neighbor_active}                                  \
            --ip {ip}                                                       \
            --vlan-nexthops {vlan_nexthop_active}                           \
            --portchannel-nexthops {portchannel_nexthops}                   \
            --iterations {iterations}")

        # on peer tor, active and standby neighbor are switched
        executor.submit(rand_unselected_dut.shell, f"python {TEST_SCRIPT_DST}   \
            --vlan-if {vlan}                                                    \
            --portchannel-if {portchannel_interfaces}                           \
            --standby-mac {neighbor_active}                                     \
            --active-mac {neighbor_standby}                                     \
            --ip {ip}                                                           \
            --vlan-nexthops {vlan_nexthop_standby}                              \
            --portchannel-nexthops {portchannel_nexthops}                       \
            --iterations {iterations}")

    verify_orchagent_running_or_assert(rand_selected_dut)
    verify_orchagent_running_or_assert(rand_unselected_dut)
