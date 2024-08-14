import pytest
import logging
from netaddr import IPNetwork
import ptf.testutils as testutils
from jinja2 import Template
import ptf.packet as scapy
from ptf.mask import Mask
import json
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # noqa F401
from tests.common.helpers.generators import generate_ip_through_default_route
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import wait_tcp_connection
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME, BGP_MONITOR_PORT

pytestmark = [
    pytest.mark.topology('any'),
]

BGP_PORT = 179
BGP_CONNECT_TIMEOUT = 121
MAX_TIME_FOR_BGPMON = 180
ZERO_ADDR = r'0.0.0.0/0'
logger = logging.getLogger(__name__)


def get_default_route_ports(host, tbinfo, default_addr=ZERO_ADDR):
    mg_facts = host.get_extended_minigraph_facts(tbinfo)
    route_info = json.loads(host.shell("show ip route {} json".format(default_addr))['stdout'])
    ports = []
    for route in route_info[default_addr]:
        if route['protocol'] != 'bgp':
            continue
        for itfs in route['nexthops']:
            if 'interfaceName' in itfs and '-IB' not in itfs['interfaceName']:
                ports.append(itfs['interfaceName'])
    port_indices = []
    for port in ports:
        if 'PortChannel' in port:
            for member in mg_facts['minigraph_portchannels'][port]['members']:
                port_indices.append(mg_facts['minigraph_ptf_indices'][member])
        else:
            port_indices.append(mg_facts['minigraph_ptf_indices'][port])

    return port_indices


@pytest.fixture
def common_setup_teardown(dut_with_default_route,  tbinfo):
    duthost = dut_with_default_route
    peer_addr = generate_ip_through_default_route(duthost)
    pytest_assert(peer_addr, "Failed to generate ip address for test")
    peer_addr = str(IPNetwork(peer_addr).ip)
    peer_ports = get_default_route_ports(duthost, tbinfo)
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    local_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
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
    yield local_addr, peer_addr, peer_ports, mg_facts['minigraph_bgp_asn']
    # Cleanup bgp monitor
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(peer_addr), asic_index='all')
    duthost.file(path=BGPMON_CONFIG_FILE, state='absent')


def build_syn_pkt(local_addr, peer_addr):
    pkt = testutils.simple_tcp_packet(
        pktlen=54,
        ip_src=local_addr,
        ip_dst=peer_addr,
        tcp_dport=BGP_PORT,
        tcp_flags="S"
    )
    exp_packet = Mask(pkt)
    exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_packet.set_do_not_care_scapy(scapy.Ether, "src")

    exp_packet.set_do_not_care_scapy(scapy.IP, "version")
    exp_packet.set_do_not_care_scapy(scapy.IP, "ihl")
    exp_packet.set_do_not_care_scapy(scapy.IP, "tos")
    exp_packet.set_do_not_care_scapy(scapy.IP, "len")
    exp_packet.set_do_not_care_scapy(scapy.IP, "flags")
    exp_packet.set_do_not_care_scapy(scapy.IP, "id")
    exp_packet.set_do_not_care_scapy(scapy.IP, "frag")
    exp_packet.set_do_not_care_scapy(scapy.IP, "ttl")
    exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.IP, "options")

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


def test_bgpmon(dut_with_default_route, localhost, enum_rand_one_frontend_asic_index,
                common_setup_teardown, set_timeout_for_bgpmon, ptfadapter, ptfhost):
    """
    Add a bgp monitor on ptf and verify that DUT is attempting to establish connection to it
    """
    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    def bgpmon_peer_connected(duthost, bgpmon_peer):
        try:
            bgp_summary = json.loads(asichost.run_vtysh("-c 'show bgp summary json'")['stdout'])
            return bgp_summary['ipv4Unicast']['peers'][bgpmon_peer]["state"] == "Established"
        except Exception:
            logger.info('Unable to get bgp status')
            return False

    local_addr, peer_addr, peer_ports, asn = common_setup_teardown
    exp_packet = build_syn_pkt(local_addr, peer_addr)
    # Flush dataplane
    ptfadapter.dataplane.flush()
    # Load bgp monitor config
    logger.info("Configured bgpmon and verifying packet on {}".format(peer_ports))
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)
    # Verify syn packet on ptf
    (rcvd_port_index, rcvd_pkt) = testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_packet,
                                                                   ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT)
    # ip as BGMPMON IP , mac as the neighbor mac(mac for default nexthop that was used for sending syn packet) ,
    # add the neighbor entry and the default route for dut loopback
    ptf_interface = "eth" + str(peer_ports[rcvd_port_index])
    res = ptfhost.shell('cat /sys/class/net/{}/address'.format(ptf_interface))
    original_mac = res['stdout']
    ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, scapy.Ether(rcvd_pkt).dst))
    ptfhost.shell("ip add add %s dev %s" % (peer_addr + "/24", ptf_interface))
    ptfhost.exabgp(name=BGP_MONITOR_NAME,
                   state="started",
                   local_ip=peer_addr,
                   router_id=peer_addr,
                   peer_ip=local_addr,
                   local_asn=asn,
                   peer_asn=asn,
                   port=BGP_MONITOR_PORT, passive=True)
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, duthost.facts["router_mac"], ptf_interface))
    ptfhost.shell("ip route replace %s dev %s" % (local_addr + "/32", ptf_interface))
    try:
        pytest_assert(wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
                      "Failed to start bgp monitor session on PTF")
        pytest_assert(wait_until(MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, duthost, peer_addr),
                      "BGPMon Peer connection not established")
    finally:
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        ptfhost.shell("ip route del %s dev %s" % (local_addr + "/32", ptf_interface))
        ptfhost.shell("ip neigh del %s lladdr %s dev %s" % (local_addr, duthost.facts["router_mac"], ptf_interface))
        ptfhost.shell("ip add del %s dev %s" % (peer_addr + "/24", ptf_interface))
        ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, original_mac))


def test_bgpmon_no_resolve_via_default(dut_with_default_route, enum_rand_one_frontend_asic_index,
                                       common_setup_teardown, ptfadapter):
    """
    Verify no syn for BGP is sent when 'ip nht resolve-via-default' is disabled.
    """
    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    local_addr, peer_addr, peer_ports, asn = common_setup_teardown
    exp_packet = build_syn_pkt(local_addr, peer_addr)
    # Load bgp monitor config
    logger.info("Configured bgpmon and verifying no packet on {} when resolve-via-default is disabled"
                .format(peer_ports))
    try:
        # Disable resolve-via-default
        duthost.run_vtysh(" -c \"configure terminal\" -c \"no ip nht resolve-via-default\"", asic_index='all')
        # Flush dataplane
        ptfadapter.dataplane.flush()
        asichost.write_to_config_db(BGPMON_CONFIG_FILE)

        # Verify no syn packet is received
        pytest_assert(0 == testutils.count_matched_packets_all_ports(test=ptfadapter, exp_packet=exp_packet,
                                                                     ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT),
                      "Syn packets is captured when resolve-via-default is disabled")
    finally:
        # Re-enable resolve-via-default
        duthost.run_vtysh("-c \"configure terminal\" -c \"ip nht resolve-via-default\"", asic_index='all')
