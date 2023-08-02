import pytest
import logging
import ipaddress
from netaddr import IPNetwork
import ptf.testutils as testutils
from jinja2 import Template
import ptf.packet as scapy
from ptf.mask import Mask
import json
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # noqa F401
from tests.common.helpers.generators import generate_ip_through_default_route, generate_ip_through_default_v6_route
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, get_plt_reboot_ctrl
from tests.common.utilities import wait_tcp_connection
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME, BGP_MONITOR_PORT
from test_bgpmon import get_default_route_ports, dut_with_default_route, set_timeout_for_bgpmon
pytestmark = [
    pytest.mark.topology('t2'),
]

BGP_PORT = 179
BGP_CONNECT_TIMEOUT = 121
MAX_TIME_FOR_BGPMON = 180
ZERO_ADDR = r'0.0.0.0/0'
ZERO_V6_ADDR = r'::/0'
logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def common_v6_setup_teardown(dut_with_default_route, tbinfo, enum_rand_one_frontend_asic_index):
    duthost = dut_with_default_route
    peer_addr = generate_ip_through_default_v6_route(duthost)
    router_id = generate_ip_through_default_route(duthost)
    pytest_assert(peer_addr, "Failed to generate ip address for test")
    peer_addr = str(IPNetwork(peer_addr).ip)
    peer_ports = get_default_route_ports(duthost, tbinfo, ZERO_V6_ADDR)
    
    # Get loopback4096 address    
    if enum_rand_one_frontend_asic_index:
        cfg_facts = duthost.config_facts(source='persistent', asic_index='all')[enum_rand_one_frontend_asic_index]['ansible_facts']
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
    #local_addr = mg_facts['minigraph_lo_interfaces'][1]['addr']
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
    yield local_addr, peer_addr, peer_ports, mg_facts['minigraph_bgp_asn'], router_id
    # Cleanup bgp monitor
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(peer_addr), asic_index='all')
    duthost.file(path=BGPMON_CONFIG_FILE, state='absent')


def build_v6_syn_pkt(local_addr, peer_addr):
    pkt = testutils.simple_tcpv6_packet(
        ipv6_src=local_addr,
        ipv6_dst=peer_addr,
        pktlen=40,
        tcp_dport=BGP_PORT,
        tcp_flags="S"
    )

    exp_packet = Mask(pkt)
    exp_packet.set_ignore_extra_bytes()

    exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_packet.set_do_not_care_scapy(scapy.Ether, "src")

    exp_packet.set_do_not_care_scapy(scapy.IPv6, "version")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "tc")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "fl")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "plen")
    exp_packet.set_do_not_care_scapy(scapy.IPv6, "hlim")

    exp_packet.set_do_not_care_scapy(scapy.TCP, "sport")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "seq")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "ack")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "reserved")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "dataofs")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "window")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "urgptr")

    return exp_packet


def test_bgpmon_v6(dut_with_default_route, localhost, enum_rand_one_frontend_asic_index,
                common_v6_setup_teardown, set_timeout_for_bgpmon, ptfadapter, ptfhost):
    """
    Add a bgp monitor on ptf and verify that DUT is attempting to establish connection to it
    """

    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    def bgpmon_peer_connected(duthost, bgpmon_peer):
        try:
            bgp_summary = json.loads(asichost.run_vtysh("-c 'show bgp summary json'")['stdout'])
            return bgp_summary['ipv6Unicast']['peers'][bgpmon_peer]["state"] == "Established"
        except Exception:
            logger.info('Unable to get bgp status')
            return False

    local_addr, peer_addr, peer_ports, asn, router_id = common_v6_setup_teardown
    exp_packet = build_v6_syn_pkt(local_addr, peer_addr)
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
    ptfhost.shell("ip -6 addr add %s dev %s" % (peer_addr + "/128", ptf_interface))
    ptfhost.exabgp(name=BGP_MONITOR_NAME,
                   state="started",
                   local_ip=peer_addr,
                   router_id=router_id,
                   peer_ip=local_addr,
                   local_asn=asn,
                   peer_asn=asn,
                   port=BGP_MONITOR_PORT, passive=True)
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, duthost.facts["router_mac"], ptf_interface))
    ptfhost.shell("ip -6 route add %s dev %s" % (local_addr + "/128", ptf_interface))
    try:
        pytest_assert(wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
                      "Failed to start bgp monitor session on PTF")
        pytest_assert(wait_until(MAX_TIME_FOR_BGPMON, 5, 0, bgpmon_peer_connected, duthost, peer_addr),
                      "BGPMon Peer connection not established")
    finally:
        ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
        ptfhost.shell("ip -6 route del %s dev %s" % (local_addr + "/128", ptf_interface))
        ptfhost.shell("ip -6 neigh del %s lladdr %s dev %s" % (local_addr, duthost.facts["router_mac"], ptf_interface))
        ptfhost.shell("ip -6 addr del %s dev %s" % (peer_addr + "/128", ptf_interface))
        ptfhost.shell("ifconfig %s hw ether %s" % (ptf_interface, original_mac))


def test_bgpmon_no_ipv6_resolve_via_default(dut_with_default_route, enum_rand_one_frontend_asic_index,
                                       common_v6_setup_teardown, ptfadapter):
    """
    Verify no syn for BGP is sent when 'ip nht resolve-via-default' is disabled.
    """
    duthost = dut_with_default_route
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    local_addr, peer_addr, peer_ports, _, _ = common_v6_setup_teardown
    exp_packet = build_v6_syn_pkt(local_addr, peer_addr)
    # Load bgp monitor config
    logger.info("Configured bgpmon and verifying no packet on {} when resolve-via-default is disabled"
                .format(peer_ports))
    try:
        # Disable resolve-via-default
        duthost.run_vtysh(" -c \"configure terminal\" -c \"no ipv6 nht resolve-via-default\"", asic_index='all')
        # Flush dataplane
        ptfadapter.dataplane.flush()
        asichost.write_to_config_db(BGPMON_CONFIG_FILE)

        # Verify no syn packet is received
        pytest_assert(0 == testutils.count_matched_packets_all_ports(test=ptfadapter, exp_packet=exp_packet,
                                                                     ports=peer_ports, timeout=BGP_CONNECT_TIMEOUT),
                      "Syn packets is captured when resolve-via-default is disabled")
    finally:
        # Re-enable resolve-via-default
        duthost.run_vtysh("-c \"configure terminal\" -c \"ipv6 nht resolve-via-default\"", asic_index='all')
