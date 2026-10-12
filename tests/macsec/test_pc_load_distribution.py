'''

This script is to test load balancing between the ports in a port-channel.

    1) send traffic
    2) check traffic (traffic load on links)

'''
import pytest
import logging
import ipaddress
from netaddr import IPNetwork
import random

# Packet Test Framework imports
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_random_side            # noqa F401
from tests.common.dualtor.dual_tor_utils import config_active_active_dualtor_active_standby                 # noqa F401
from tests.common.dualtor.dual_tor_utils import validate_active_active_dualtor_setup                        # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports                                        # noqa F401


percentVariance = 25

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.macsec_required
]


@pytest.fixture(scope='module')
def loopback_ips(duthosts, duts_running_config_facts):             # noqa F811
    lo_ips = []
    lo_ipv6s = []
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        cfg_facts = duts_running_config_facts[duthost.hostname]
        lo_ip = None
        lo_ipv6 = None
        # Loopback0 IP is same on all ASICs
        for addr in cfg_facts[0][1]["LOOPBACK_INTERFACE"]['Loopback0']:
            ip = IPNetwork(addr).ip
            if ip.version == 4 and not lo_ip:
                lo_ip = str(ip)
            elif ip.version == 6 and not lo_ipv6:
                lo_ipv6 = str(ip)
        lo_ips.append(lo_ip)
        lo_ipv6s.append(lo_ipv6)
    return {'lo_ips': lo_ips, 'lo_ipv6s': lo_ipv6s}


@pytest.fixture(scope='module')
def setup(tbinfo, duthosts, loopback_ips, enum_frontend_dut_hostname):
    duthost = duthosts[enum_frontend_dut_hostname]
    duthost.shell(cmd='sonic-clear counters', module_ignore_errors=True)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    mg_pocs = list(mg_facts['minigraph_portchannels'].keys())
    POC = mg_pocs[0]
    mg_poc_intfs = list(mg_facts["minigraph_portchannels"][POC]["members"])

    local_addrs = []
    peer_addrs = []
    for poc_int in mg_facts["minigraph_portchannel_interfaces"]:
        if poc_int['attachto'] == POC:
            mg_facts["minigraph_portchannels"]
            local_addrs.append(poc_int['addr'])
            peer_addrs.append(poc_int['peer_addr'])

    router_mac = duthost.facts["router_mac"]

    logger.info(duthost.shell(cmd='show interfaces portchannel', module_ignore_errors=True)['stdout'])
    logger.info(duthost.shell(cmd='show lldp table', module_ignore_errors=True)['stdout'])

    setup_info = {
        'duthost': duthost,
        'portchannel': POC,
        'portchannel-members': mg_poc_intfs,
        'neighbor_info': '',
        'local_addrs': local_addrs,
        'neighbor_addrs': peer_addrs,
        'port-channels': mg_pocs,
        'router_mac': router_mac,
        'lo0_ipv4': loopback_ips['lo_ips'][0],
        'lo0_ipv6': loopback_ips['lo_ipv6s'][0]
    }

    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info


def generate_packet(src_ip, dst_ip, dst_mac):
    """
    Build ipv4 and ipv6 packets/expected_packets for testing
    """
    if ipaddress.ip_network(src_ip.encode().decode(), False).version == 4:
        pkt = testutils.simple_ip_packet(eth_dst=dst_mac, ip_src=src_ip, ip_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_packet(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac, ipv6_src=src_ip, ipv6_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_packet(scapy.IPv6, "hlim")

    exp_pkt.set_do_not_care_packet(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_packet(scapy.Ether, "src")

    return pkt, exp_pkt


def send_packet(ptfadapter, pkt, exp_pkt, tx_port, rx_port):
    """
    Send packet with ptfadapter
    """
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=tx_port, count=20000)


def test_ptf(ptfhost, setup, ptfadapter, rand_selected_dut, tbinfo):
    mg_facts = setup['duthost'].get_extended_minigraph_facts(tbinfo)
    portchannel_members = []
    for _, v in list(mg_facts["minigraph_portchannels"].items()):
        portchannel_members += v['members']

    ptf_interfaces = []
    for port in portchannel_members:
        ptf_interfaces.append(mg_facts['minigraph_ptf_indices'][port])

    tx_port = random.choice(ptf_interfaces)

    command = "show interfaces counters | grep U"
    output = setup['duthost'].shell(cmd=command, module_ignore_errors=True)['stdout']
    logger.info(f"Starting counters:\n{output}")

    pkt, exp_pkt = generate_packet(tbinfo['ptf_ip'], setup['lo0_ipv4'], setup["router_mac"])
    for i in range(50):
        send_packet(ptfadapter, pkt, exp_pkt, tx_port, tx_port)

    command = "show interfaces counters | grep U"
    output = setup['duthost'].shell(cmd=command, module_ignore_errors=True)['stdout']
    logger.info(f"After traffic counters: \n{output}")
    out_split = output.split("\n")
    tx_total = 0.0
    tx_list = []
    for inter in out_split:
        inter_split = [x for x in inter.split(" ") if x]
        if inter_split[0] in portchannel_members:
            tx_total = tx_total + float(inter_split[10])
            tx_list.append(float(inter_split[10]))
    avg_tx = tx_total / len(tx_list)
    logger.info(f"Total TX: {tx_total} with average of {avg_tx} over {len(tx_list)} members.")
    for x in tx_list:
        diff_pct = (abs(avg_tx - x) / avg_tx) * 100
        logger.info(f"Percentage difference: {diff_pct}")
        assert percentVariance >= diff_pct
