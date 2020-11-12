import pytest
import logging
from netaddr import IPAddress, IPNetwork
import ptf.testutils as testutils
from jinja2 import Template
import ptf.packet as scapy
from ptf.mask import Mask
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]
from tests.common.helpers.generators import generate_ips as generate_ips

pytestmark = [
    pytest.mark.topology('any'),
]

BGPMON_TEMPLATE_FILE = 'bgp/bgpmon.j2'
BGPMON_CONFIG_FILE = '/tmp/bgpmon.json'
BGP_PORT = 179
BGP_CONNECT_TIMEOUT = 120

logger = logging.getLogger(__name__)

@pytest.fixture
def common_setup_teardown(duthost, ptfhost):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    peer_addr = generate_ips(1, "%s/%s" % (mg_facts['minigraph_vlan_interfaces'][0]['addr'],
                                           mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']),
                             [IPAddress(mg_facts['minigraph_vlan_interfaces'][0]['addr'])])[0]
    peer_addr = str(IPNetwork(peer_addr).ip)
    peer_port = mg_facts['minigraph_port_indices'][mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['members'][0]]
    local_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
    # Assign peer addr to an interface on ptf
    ptfhost.shell("ifconfig eth{} {}".format(peer_port, peer_addr))
    logger.info("Generated peer address {} and assigned to eth{} on ptf".format(peer_addr, peer_port))
    bgpmon_args = {
        'peer_addr': peer_addr,
        'asn': mg_facts['minigraph_bgp_asn'],
        'local_addr': local_addr,
        'peer_name': 'bgp_monitor'
    }
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    duthost.copy(content=bgpmon_template.render(**bgpmon_args),
                 dest=BGPMON_CONFIG_FILE)
    yield local_addr, peer_addr, peer_port
    # Cleanup bgp monitor
    duthost.shell("redis-cli -n 4 -c DEL 'BGP_MONITORS|{}'".format(peer_addr))
    duthost.file(path=BGPMON_CONFIG_FILE, state='absent')

def build_syn_pkt(local_addr, peer_addr, peer_port):
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

def test_bgpmon(duthost, common_setup_teardown, ptfadapter):
    """
    Add a bgp monitor on ptf and verify that DUT is attempting to establish connection to it
    """
    local_addr, peer_addr, peer_port = common_setup_teardown
    exp_packet = build_syn_pkt(local_addr, peer_addr, peer_port)
    # Load bgp monitor config
    logger.info("Configured bgpmon and verifying packet")
    duthost.command("sonic-cfggen -j {} -w".format(BGPMON_CONFIG_FILE))
    # Verify syn packet on ptf
    testutils.verify_packet(ptfadapter, exp_packet, peer_port, BGP_CONNECT_TIMEOUT)

