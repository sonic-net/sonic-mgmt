import ipaddress
import pytest
import random
import time

from ptf import testutils

from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import upper_tor_host
from tests.common.dualtor.dual_tor_utils import lower_tor_host
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import force_active_tor                                                # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.fixtures.ptfhost_utils import run_icmp_responder
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                                            # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory
from tests.common.helpers import bgp
from tests.common.utilities import is_ipv4_address


pytestmark = [
    pytest.mark.topology("dualtor")
]


TEST_DEVICE_INTERFACE = "Loopback3"
NEIGHBOR_TYPE = "LeafRouter"
NEIGHBOR_ASN_UPPER_TOR = 61000
NEIGHBOR_ASN_LOWER_TOR = 61000
EXABGP_PORT_UPPER_TOR = 11000
EXABGP_PORT_LOWER_TOR = 11001
ANNOUNCED_SUBNET = u"10.10.100.0/27"


@pytest.fixture
def setup_interfaces(ptfhost, upper_tor_host, lower_tor_host, tbinfo):
    """Setup the interfaces used by the new BGP sessions on PTF."""

    def _find_test_lo_interface(mg_facts):
        for loopback in mg_facts["minigraph_lo_interfaces"]:
            if loopback["name"] == TEST_DEVICE_INTERFACE:
                return loopback

    def _find_ipv4_vlan(mg_facts):
        for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
            if is_ipv4_address(vlan_intf["addr"]):
                return vlan_intf

    # find the DUT interface ip used in the bgp session
    upper_tor_mg_facts = upper_tor_host.get_extended_minigraph_facts(tbinfo)
    lower_tor_mg_facts = lower_tor_host.get_extended_minigraph_facts(tbinfo)
    upper_tor_intf = _find_test_lo_interface(upper_tor_mg_facts)
    lower_tor_intf = _find_test_lo_interface(lower_tor_mg_facts)
    assert upper_tor_intf
    assert lower_tor_intf
    upper_tor_intf_addr = "%s/%s" % (upper_tor_intf["addr"], upper_tor_intf["prefixlen"])
    lower_tor_intf_addr = "%s/%s" % (lower_tor_intf["addr"], lower_tor_intf["prefixlen"])

    # find the server ip used in the bgp session
    mux_configs = mux_cable_server_ip(upper_tor_host)
    test_iface = random.choice(mux_configs.keys())
    test_server = mux_configs[test_iface]
    test_server_ip = test_server["server_ipv4"]
    upper_tor_server_ptf_intf_idx = upper_tor_mg_facts["minigraph_port_indices"][test_iface]
    lower_tor_server_ptf_intf_idx = lower_tor_mg_facts["minigraph_port_indices"][test_iface]
    upper_tor_server_ptf_intf = "eth%s" % upper_tor_server_ptf_intf_idx
    lower_tor_server_ptf_intf = "eth%s" % lower_tor_server_ptf_intf_idx
    assert upper_tor_server_ptf_intf == lower_tor_server_ptf_intf

    # find the vlan interface ip, used as next-hop for routes added on ptf
    upper_tor_vlan = _find_ipv4_vlan(upper_tor_mg_facts)
    lower_tor_vlan = _find_ipv4_vlan(lower_tor_mg_facts)
    assert upper_tor_vlan
    assert lower_tor_vlan
    assert upper_tor_vlan["addr"] == lower_tor_vlan["addr"]
    vlan_intf_addr = upper_tor_vlan["addr"]
    vlan_intf_prefixlen = upper_tor_vlan["prefixlen"]

    # construct the server ip with the vlan prefix length
    upper_tor_server_ip = "%s/%s" % (test_server_ip.split("/")[0], vlan_intf_prefixlen)
    lower_tor_server_ip = "%s/%s" % (test_server_ip.split("/")[0], vlan_intf_prefixlen)

    # find ToRs' ASNs
    upper_tor_asn = upper_tor_mg_facts["minigraph_bgp_asn"]
    lower_tor_asn = lower_tor_mg_facts["minigraph_bgp_asn"]
    assert upper_tor_asn == lower_tor_asn

    connections = {
        "upper_tor": {
            "localhost": upper_tor_host,
            "local_intf": TEST_DEVICE_INTERFACE,
            "local_addr": upper_tor_intf_addr,
            "local_asn": upper_tor_asn,
            "test_intf": test_iface,
            "neighbor_intf": upper_tor_server_ptf_intf,
            "neighbor_addr": upper_tor_server_ip,
            "neighbor_asn": NEIGHBOR_ASN_UPPER_TOR,
            "neighbor_type": NEIGHBOR_TYPE,
            "exabgp_port": EXABGP_PORT_UPPER_TOR,
        },
        "lower_tor": {
            "localhost": lower_tor_host,
            "local_intf": TEST_DEVICE_INTERFACE,
            "local_addr": lower_tor_intf_addr,
            "local_asn": lower_tor_asn,
            "test_intf": test_iface,
            "neighbor_intf": lower_tor_server_ptf_intf,
            "neighbor_addr": lower_tor_server_ip,
            "neighbor_asn": NEIGHBOR_ASN_LOWER_TOR,
            "neighbor_type": NEIGHBOR_TYPE,
            "exabgp_port": EXABGP_PORT_LOWER_TOR,
        }
    }

    try:
        ptfhost.shell("ifconfig %s %s" % (upper_tor_server_ptf_intf, upper_tor_server_ip))
        for conn in connections.values():
            ptfhost.shell("ip route add %s via %s" % (conn["local_addr"], vlan_intf_addr))
        yield connections
    finally:
        for conn in connections.values():
            ptfhost.shell("ifconfig %s 0.0.0.0" % conn["neighbor_intf"], module_ignore_errors=True)
            ptfhost.shell("ip route del %s" % conn["local_addr"], module_ignore_errors=True)


@pytest.fixture
def bgp_neighbors(upper_tor_host, lower_tor_host, ptfhost, setup_interfaces):
    """Build the bgp neighbor objects used to start new bgp sessions."""
    # allow ebgp neighbors that are multiple hops away
    is_quagga = True
    connections = setup_interfaces
    neighbors = {}
    for dut, conn in connections.items():
        neighbors[dut] = bgp.BGPNeighbor(
            conn["localhost"],
            ptfhost,
            "slb_%s" % dut,
            conn["neighbor_addr"].split("/")[0],
            conn["neighbor_asn"],
            conn["local_addr"].split("/")[0],
            conn["local_asn"],
            conn["exabgp_port"],
            conn["neighbor_type"],
            is_quagga=is_quagga
        )
    return neighbors


@pytest.fixture
def constants(setup_interfaces):
    class _C(object):
        """Dummy class to save test constants."""
        pass

    connections = setup_interfaces
    assert connections["upper_tor"]["neighbor_addr"] == connections["lower_tor"]["neighbor_addr"]
    nexthop = connections["upper_tor"]["neighbor_addr"].split("/")[0]
    _constants = _C()
    _constants.route = {
        "prefix": ANNOUNCED_SUBNET,
        "nexthop": nexthop
    }
    _constants.bgp_establish_sleep_interval = 30
    _constants.bgp_update_sleep_interval = 10
    _constants.mux_state_change_sleep_interval = 5
    return _constants


def test_orchagent_slb(
    bgp_neighbors, constants, conn_graph_facts,
    force_active_tor,
    upper_tor_host, lower_tor_host,
    ptfadapter, ptfhost, setup_interfaces,
    toggle_all_simulator_ports_to_upper_tor, tbinfo,
    tunnel_traffic_monitor,
    vmhost
):

    def verify_bgp_session(duthost, bgp_neighbor):
        """Verify the bgp session to the DUT is established."""
        bgp_facts = duthost.bgp_facts()["ansible_facts"]
        assert bgp_neighbor.ip in bgp_facts["bgp_neighbors"]
        assert bgp_facts["bgp_neighbors"][bgp_neighbor.ip]["state"] == "established"

    def verify_route(duthost, route, existing=True):
        """Verify the route's existence in the DUT."""
        prefix = ipaddress.ip_network(route["prefix"])
        existing_route = duthost.get_ip_route_info(dstip=prefix)
        if existing:
            assert route["nexthop"] in [str(_[0]) for _ in existing_route["nexthops"]]
        else:
            assert len(existing_route["nexthops"]) == 0

    def verify_traffic(duthost, connection, route, is_duthost_active=True, is_route_existed=True):
        prefix = ipaddress.ip_network(route["prefix"])
        dst_host = str(random.choice(list(prefix.hosts())))
        pkt, exp_pkt = build_packet_to_server(duthost, ptfadapter, dst_host)
        ptf_t1_intf = random.choice(get_t1_ptf_ports(duthost, tbinfo))
        ptf_t1_intf_index = int(ptf_t1_intf.strip("eth"))
        is_tunnel_traffic_existed = is_route_existed and not is_duthost_active
        is_server_traffic_existed = is_route_existed and is_duthost_active
        tunnel_monitor = tunnel_traffic_monitor(duthost, existing=is_tunnel_traffic_existed)
        server_traffic_monitor = ServerTrafficMonitor(
            duthost, ptfhost, vmhost, tbinfo, connection["test_intf"],
            conn_graph_facts, exp_pkt, existing=is_server_traffic_existed
        )
        with tunnel_monitor, server_traffic_monitor:
            testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)

    connections = setup_interfaces

    upper_tor_bgp_neighbor = bgp_neighbors["upper_tor"]
    lower_tor_bgp_neighbor = bgp_neighbors["lower_tor"]

    try:
        # STEP 1: create peer sessions with both ToRs
        lower_tor_bgp_neighbor.start_session()
        upper_tor_bgp_neighbor.start_session()

        time.sleep(constants.bgp_establish_sleep_interval)

        verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor)
        verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor)

        # STEP 2: announce a route to both ToRs
        upper_tor_bgp_neighbor.announce_route(constants.route)
        lower_tor_bgp_neighbor.announce_route(constants.route)

        time.sleep(constants.bgp_update_sleep_interval)

        verify_route(upper_tor_host, constants.route, existing=True)
        verify_route(lower_tor_host, constants.route, existing=True)

        # STEP 3: verify the route by sending some downstream traffic
        verify_traffic(
            upper_tor_host, connections["upper_tor"], constants.route,
            is_duthost_active=True, is_route_existed=True
        )
        verify_traffic(
            lower_tor_host, connections["lower_tor"], constants.route,
            is_duthost_active=False, is_route_existed=True
        )

        # STEP 4: withdraw the announced route to both ToRs
        upper_tor_bgp_neighbor.withdraw_route(constants.route)
        lower_tor_bgp_neighbor.withdraw_route(constants.route)

        time.sleep(constants.bgp_update_sleep_interval)

        verify_route(upper_tor_host, constants.route, existing=False)
        verify_route(lower_tor_host, constants.route, existing=False)

        # STEP 5: verify the route is removed by verifying that downstream traffic is dropped
        verify_traffic(
            upper_tor_host, connections["upper_tor"], constants.route,
            is_duthost_active=True, is_route_existed=False
        )
        verify_traffic(
            lower_tor_host, connections["lower_tor"], constants.route,
            is_duthost_active=False, is_route_existed=False
        )

        # STEP 6: toggle mux state change
        force_active_tor(lower_tor_host, 'all')

        time.sleep(constants.mux_state_change_sleep_interval)

        verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor)
        verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor)

        # STEP 7: announce the route to both ToRs after mux state change
        upper_tor_bgp_neighbor.announce_route(constants.route)
        lower_tor_bgp_neighbor.announce_route(constants.route)

        time.sleep(constants.bgp_update_sleep_interval)

        verify_route(upper_tor_host, constants.route, existing=True)
        verify_route(lower_tor_host, constants.route, existing=True)

        # STEP 8: verify the route by sending some downstream traffic
        verify_traffic(
            upper_tor_host, connections["upper_tor"], constants.route,
            is_duthost_active=False, is_route_existed=True
        )
        verify_traffic(
            lower_tor_host, connections["lower_tor"], constants.route,
            is_duthost_active=True, is_route_existed=True
        )

        # STEP 9: verify teardown
        upper_tor_bgp_neighbor.stop_session()

        verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor)
        verify_route(lower_tor_host, constants.route, existing=True)

        lower_tor_bgp_neighbor.stop_session()

    finally:
        upper_tor_bgp_neighbor.stop_session()
        lower_tor_bgp_neighbor.stop_session()
        upper_tor_host.shell("ip route flush %s" % constants.route["prefix"])
        lower_tor_host.shell("ip route flush %s" % constants.route["prefix"])
