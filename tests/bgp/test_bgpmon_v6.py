import pytest
import logging
import ipaddress
from netaddr import IPNetwork
from jinja2 import Template
import json
import random
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # noqa F401
from tests.common.helpers.generators import generate_ip_through_default_route, generate_ip_through_default_v6_route
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import wait_tcp_connection
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME, BGP_MONITOR_PORT

pytestmark = [
    pytest.mark.topology('t2'),
]

BGP_PORT = 179
BGP_CONNECT_TIMEOUT = 121
MAX_TIME_FOR_BGPMON = 180
ZERO_ADDR = r'0.0.0.0/0'
ZERO_V6_ADDR = r'::/0'
logger = logging.getLogger(__name__)


# This API gets the ptf indices list and the local interfaces list for uplink LC
def get_all_uplink_ptf_recv_ports(duthosts, tbinfo):
    """
    This function returns ptf indices and local ports from dut which has connectivity to T3 (RNG/AZH) layer.
    """
    ptf_port_indices = []
    local_dut_ports = []
    recv_neigh_list = []

    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue

        # First get all T3 neighbors, which are of type RegionalHub, AZNGHub
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        device_neighbor_metadata = config_facts['DEVICE_NEIGHBOR_METADATA']
        for k, v in device_neighbor_metadata.items():
            # if this duthost has peer of type RH/AZNG, then it is uplink LC
            if v['type'] == "RegionalHub" or v['type'] == "AZNGHub":
                recv_neigh_list.append(k)

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for port, neighbor in mg_facts["minigraph_neighbors"].items():
            if neighbor['name'] in recv_neigh_list and port in mg_facts["minigraph_ptf_indices"]:
                if 'PortChannel' in port:
                    for member in mg_facts['minigraph_portchannels'][port]['members']:
                        ptf_port_indices.append(mg_facts['minigraph_ptf_indices'][member])
                        local_dut_ports.append(member)
                else:
                    ptf_port_indices.append(mg_facts['minigraph_ptf_indices'][port])
                    local_dut_ports.append(port)

    return ptf_port_indices, local_dut_ports


def get_uplink_route_mac(duthosts, port):
    """
    This function returns the router mac of dut/asic which has connectivity to T3 (RNG/AZH) layer,
    based on the input local dut interface.
    """
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue

        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        device_neighbor_metadata = config_facts['DEVICE_NEIGHBOR_METADATA']
        for k, v in device_neighbor_metadata.items():
            # if this duthost has peer of type RH/AZNG, then it is uplink LC
            # return the router mac for that duthost/asic
            if v['type'] == "RegionalHub" or v['type'] == "AZNGHub":
                # Get the router_mac based on which asic the port belongs to in this dut
                return duthost.get_port_asic_instance(port).get_router_mac() \
                                    if duthost.is_multi_asic else duthost.facts["router_mac"]


@pytest.fixture
def common_v6_setup_teardown(duthosts, tbinfo, enum_rand_one_per_hwsku_frontend_hostname,
                             enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    peer_addr = generate_ip_through_default_v6_route(duthost)
    router_id = generate_ip_through_default_route(duthost)
    pytest_assert(peer_addr, "Failed to generate ip address for test")
    peer_addr = str(IPNetwork(peer_addr).ip)
    peer_ports, local_ports = get_all_uplink_ptf_recv_ports(duthosts, tbinfo)

    # Get loopback4096 address
    if enum_rand_one_frontend_asic_index:
        cfg_facts = duthost.config_facts(
                        source='persistent', asic_index='all')[enum_rand_one_frontend_asic_index]['ansible_facts']
    else:
        cfg_facts = duthost.config_facts(source='persistent', asic_index='all')[0]['ansible_facts']

    if 'Loopback4096' in cfg_facts['LOOPBACK_INTERFACE']:
        lbs4096 = list(cfg_facts['LOOPBACK_INTERFACE']['Loopback4096'].keys())
        for lb4096 in lbs4096:
            lb4096intf = ipaddress.ip_interface(lb4096)
            if lb4096intf.ip.version == 6:
                if "/" in lb4096:
                    local_addr = lb4096.split("/")[0]
                    break
                else:
                    local_addr = lb4096

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    # Assign peer addr to an interface on ptf
    logger.info("Generated peer address {}".format(peer_addr))
    bgpmon_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': peer_addr,
        'asn': mg_facts['minigraph_bgp_asn'],
        'local_addr': local_addr,
        'peer_name': BGP_MONITOR_NAME
    }
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    duthost.copy(content=bgpmon_template.render(**bgpmon_args),
                 dest=BGPMON_CONFIG_FILE)
    yield local_addr, peer_addr, peer_ports, local_ports, mg_facts['minigraph_bgp_asn'], router_id
    # Cleanup bgp monitor
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(peer_addr), asic_index='all')
    duthost.file(path=BGPMON_CONFIG_FILE, state='absent')


def bgpmon_peer_connected(asichost, bgpmon_peer):
    try:
        bgp_summary = json.loads(asichost.run_vtysh("-c 'show bgp summary json'")['stdout'])
        return bgp_summary['ipv6Unicast']['peers'][bgpmon_peer]["state"] == "Established"
    except Exception:
        logger.info('Unable to get bgp status')
        return False


def test_bgpmon_v6(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname,
                   enum_rand_one_frontend_asic_index, common_v6_setup_teardown,
                   set_timeout_for_bgpmon, ptfadapter, ptfhost):
    """
    Add a bgp monitor on ptf and verify that DUT is attempting to establish connection to it
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    local_addr, peer_addr, peer_ports, local_ports, asn, router_id = common_v6_setup_teardown
    pytest_assert(peer_ports is not None, "No upstream neighbors in the testbed")

    # Flush dataplane
    ptfadapter.dataplane.flush()
    # Load bgp monitor config
    logger.info("Configured BGPMON on {}".format(duthost))
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)

    port_index = random.randint(0, len(peer_ports)-1)
    logger.info("Configured route to from PTF to LC on PTF port {}".format(peer_ports[port_index]))
    router_mac = get_uplink_route_mac(duthosts, local_ports[port_index])
    ptf_interface = "eth" + str(peer_ports[port_index])
    ptfhost.shell("ip -6 addr add {} dev {}".format(peer_addr + "/128", ptf_interface))
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip -6 route add %s dev %s" % (local_addr + "/128", ptf_interface))

    logger.info("Starting BGP Monitor on PTF")
    ptfhost.exabgp(name=BGP_MONITOR_NAME,
                   state="started",
                   local_ip=peer_addr,
                   router_id=router_id,
                   peer_ip=local_addr,
                   local_asn=asn,
                   peer_asn=asn,
                   port=BGP_MONITOR_PORT)

    try:
        pytest_assert(wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
                      "Failed to start bgp monitor session on PTF")
        pytest_assert(wait_until(MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, asichost, peer_addr),
                      "BGPMon Peer connection not established")
    finally:
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        ptfhost.shell("ip -6 route del %s dev %s" % (local_addr + "/128", ptf_interface))
        ptfhost.shell("ip -6 neigh del %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
        ptfhost.shell("ip -6 addr del %s dev %s" % (peer_addr + "/128", ptf_interface))


def test_bgpmon_no_ipv6_resolve_via_default(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                                            enum_rand_one_frontend_asic_index, common_v6_setup_teardown, ptfadapter):
    """
    Verify no syn for BGP is sent when 'ipv6 nht resolve-via-default' is disabled.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    local_addr, peer_addr, peer_ports, local_ports, asn, router_id = common_v6_setup_teardown
    pytest_assert(peer_ports is not None, "No upstream neighbors in the testbed")

    # Flush dataplane
    ptfadapter.dataplane.flush()
    # Load bgp monitor config
    logger.info("Configured BGPMON on {}".format(duthost))
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)

    port_index = random.randint(0, len(peer_ports)-1)
    logger.info("Configured route to from PTF to LC on PTF port {}".format(peer_ports[port_index]))
    router_mac = get_uplink_route_mac(duthosts, local_ports[port_index])
    ptf_interface = "eth" + str(peer_ports[port_index])
    ptfhost.shell("ip -6 addr add {} dev {}".format(peer_addr + "/128", ptf_interface))
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip -6 route add %s dev %s" % (local_addr + "/128", ptf_interface))
    try:
        # Flush dataplane
        ptfadapter.dataplane.flush()
        asichost.write_to_config_db(BGPMON_CONFIG_FILE)
        # Disable resolve-via-default
        duthost.run_vtysh("-c \"configure terminal\" -c \"no ipv6 nht resolve-via-default\"", asic_index='all')
        ptfhost.exabgp(name=BGP_MONITOR_NAME,
                       state="started",
                       local_ip=peer_addr,
                       router_id=router_id,
                       peer_ip=local_addr,
                       local_asn=asn,
                       peer_asn=asn,
                       port=BGP_MONITOR_PORT)
        pytest_assert(wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
                      "Failed to start bgp monitor session on PTF")
        pytest_assert(not wait_until(MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, asichost, peer_addr),
                      "BGPMon Peer connection is established when it shouldn't be")
    finally:
        # Re-enable resolve-via-default
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        ptfhost.shell("ip -6 route del %s dev %s" % (local_addr + "/128", ptf_interface))
        ptfhost.shell("ip -6 neigh del %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
        ptfhost.shell("ip -6 addr del %s dev %s" % (peer_addr + "/128", ptf_interface))
        duthost.run_vtysh("-c \"configure terminal\" -c \"ipv6 nht resolve-via-default\"", asic_index='all')
