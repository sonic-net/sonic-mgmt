import pytest
import logging
import ipaddress
from netaddr import IPNetwork
from jinja2 import Template
import json
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa:F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # noqa:F401
from tests.common.helpers.generators import generate_ip_through_default_route, generate_ip_through_default_v6_route
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bgp import get_asic_config_facts
from tests.common.utilities import wait_until
from tests.common.utilities import wait_tcp_connection
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME, BGP_MONITOR_PORT

pytestmark = [
    pytest.mark.topology('t2', 'lrh', 'urh'),
]

BGP_PORT = 179
BGP_CONNECT_TIMEOUT = 121
MAX_TIME_FOR_BGPMON = 180
logger = logging.getLogger(__name__)


def get_all_uplink_ptf_recv_ports(duthosts, tbinfo):
    """
    Return PTF indices and local ports from DUT(s) with connectivity to T3 (RH/AZNG).

    On T2, BGPMON may be configured on any frontend ASIC, but the SYN toward a
    default-route peer egresses an uplink LC. Capture must include every RH/AZNG
    member in the chassis, not only ports on the selected DUT/ASIC.
    """
    ptf_port_indices = []
    local_dut_ports = []

    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue

        # First get all T3 neighbors, which are of type RegionalHub, AZNGHub
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        device_neighbor_metadata = config_facts['DEVICE_NEIGHBOR_METADATA']
        recv_neigh_list = []
        for k, v in device_neighbor_metadata.items():
            # if this duthost has peer of type RH/AZNG, then it is uplink LC
            if v['type'] == "RegionalHub" or v['type'] == "AZNGHub":
                recv_neigh_list.append(k)

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for port, neighbor in mg_facts["minigraph_neighbors"].items():
            if neighbor['name'] in recv_neigh_list and port in mg_facts["minigraph_ptf_indices"]:
                if 'PortChannel' in port:
                    members = mg_facts['minigraph_portchannels'][port]['members']
                else:
                    members = [port]

                for member in members:
                    ptf_port_indices.append(mg_facts['minigraph_ptf_indices'][member])
                    local_dut_ports.append(member)

    return ptf_port_indices, local_dut_ports


def get_uplink_route_mac(duthosts, port):
    """Return the router MAC for the ASIC that owns the given local DUT interface."""
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        for asic in duthost.asics:
            if asic.port_exists(port):
                return asic.get_router_mac() if duthost.is_multi_asic else duthost.facts["router_mac"]
    pytest_assert(False, "Failed to find router MAC for uplink port {}".format(port))


def build_syn_pkt(local_addr, peer_addr):
    """Build an IPv6 TCP SYN expectation for BGP (port 179)."""
    pkt = testutils.simple_tcpv6_packet(
        pktlen=74,
        ipv6_src=local_addr,
        ipv6_dst=peer_addr,
        tcp_dport=BGP_PORT,
        tcp_flags="S"
    )
    exp_packet = Mask(pkt)
    exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_packet.set_do_not_care_scapy(scapy.Ether, "src")

    exp_packet.set_do_not_care_scapy(scapy.IPv6, "version")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "tc")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "fl")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "plen")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "nh")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "hlim")

    exp_packet.set_do_not_care_scapy(scapy.TCP, "sport")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "seq")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "ack")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "reserved")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "dataofs")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "window")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "urgptr")

    exp_packet.set_ignore_extra_bytes()
    return exp_packet


@pytest.fixture
def common_v6_setup_teardown(duthosts, tbinfo, enum_rand_one_per_hwsku_frontend_hostname,
                             enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    peer_addr = generate_ip_through_default_v6_route(duthost)
    router_id = generate_ip_through_default_route(duthost)
    pytest_assert(peer_addr, "Failed to generate ip address for test")
    peer_addr = str(IPNetwork(peer_addr).ip)
    peer_ports, local_ports = get_all_uplink_ptf_recv_ports(duthosts, tbinfo)
    pytest_assert(peer_ports, "No upstream RH/AZNG neighbors in the testbed")

    # Get loopback4096 address for the selected frontend ASIC
    cfg_facts = get_asic_config_facts(duthost, enum_rand_one_frontend_asic_index)

    local_addr = None
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
    pytest_assert(local_addr, "Failed to get Loopback4096 IPv6 address for selected ASIC")

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    # Assign peer addr to an interface on ptf.
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

    exp_packet = build_syn_pkt(local_addr, peer_addr)
    # Flush dataplane
    ptfadapter.dataplane.flush()
    # Load bgp monitor config
    logger.info("Configured BGPMON on {} and verifying SYN on {}".format(duthost, peer_ports))
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)

    # Use the chassis uplink that received the BGP SYN instead of guessing among ECMP members
    (rcvd_port_index, rcvd_pkt) = testutils.verify_packet_any_port(
        test=ptfadapter, pkt=exp_packet, ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT
    )
    ptf_interface = "eth" + str(peer_ports[rcvd_port_index])
    router_mac = get_uplink_route_mac(duthosts, local_ports[rcvd_port_index])
    logger.info("BGP SYN received on PTF port {}, attaching monitor there".format(peer_ports[rcvd_port_index]))

    res = ptfhost.shell('cat /sys/class/net/{}/address'.format(ptf_interface))
    original_mac = res['stdout']
    ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, scapy.Ether(rcvd_pkt).dst))
    ptfhost.shell("ip -6 addr add {} dev {}".format(peer_addr + "/128", ptf_interface))
    ptfhost.shell("ip -6 neigh add %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip -6 route replace %s dev %s" % (local_addr + "/128", ptf_interface))

    logger.info("Starting BGP Monitor on PTF")
    ptfhost.exabgp(name=BGP_MONITOR_NAME,
                   state="started",
                   local_ip=peer_addr,
                   router_id=router_id,
                   peer_ip=local_addr,
                   local_asn=asn,
                   peer_asn=asn,
                   port=BGP_MONITOR_PORT,
                   passive=True)

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
        ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, original_mac))


def test_bgpmon_no_ipv6_resolve_via_default(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                            enum_rand_one_frontend_asic_index, common_v6_setup_teardown,
                                            ptfadapter):
    """
    Verify no SYN for BGP is sent when 'ipv6 nht resolve-via-default' is disabled.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    local_addr, peer_addr, peer_ports, _, _, _ = common_v6_setup_teardown
    exp_packet = build_syn_pkt(local_addr, peer_addr)

    try:
        # Disable resolve-via-default
        duthost.run_vtysh("-c \"configure terminal\" -c \"no ipv6 nht resolve-via-default\"", asic_index='all')
        # Flush dataplane
        ptfadapter.dataplane.flush()
        asichost.write_to_config_db(BGPMON_CONFIG_FILE)

        # Verify no syn packet is received (same approach as test_bgpmon.py)
        pytest_assert(
            0 == testutils.count_matched_packets_all_ports(
                test=ptfadapter, exp_packet=exp_packet, ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT
            ),
            "Syn packets is captured when resolve-via-default is disabled"
        )
    finally:
        # Re-enable resolve-via-default
        duthost.run_vtysh("-c \"configure terminal\" -c \"ipv6 nht resolve-via-default\"", asic_index='all')
