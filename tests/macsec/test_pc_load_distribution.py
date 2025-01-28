'''

This script is to test load balancing between the ports in a port-channel.

    1) send traffic
    2) check traffic (packet count on links)

'''
import pytest
import logging
import time
import ipaddress
from netaddr import IPNetwork
import random
from datetime import datetime
from tests.common.utilities import wait

# Packet Test Framework imports
import ptf
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf import config
from ptf.mask import Mask
from ptf.base_tests import BaseTest
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active, ptf_test_port_map
from tests.ptf_runner import ptf_runner
from tests.common.dualtor.mux_simulator_control import mux_server_url
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_random_side            # noqa F401
from tests.common.dualtor.dual_tor_utils import config_active_active_dualtor_active_standby                 # noqa F401
from tests.common.dualtor.dual_tor_utils import validate_active_active_dualtor_setup                        # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports                                        # noqa F401
from tests.common.utilities import is_ipv4_address

from tests.common.fixtures.fib_utils import fib_info_files_per_function
from tests.common.fixtures.fib_utils import single_fib_for_duts
from tests.common.helpers.assertions import pytest_require
PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'

config_apply = 5
counter_clear_time = 60
percentVariance = 5
PTFRUNNER_QLEN = 1000
PTF_QLEN = 20000
DEFAULT_MUX_SERVER_PORT = 8080

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('t2'),
    # pytest.mark.macsec_required
    # pytest.mark.sanity_check(skip_sanity=True)
]


def configure_portchannel(dut, portchannel_to_configure, command):
    # sudo config interface shutdown portchannelXXX
    cmd = "sudo config interface {} {}".format(command, portchannel_to_configure)
    logger.info(dut.shell(cmd, module_ignore_errors=True)['stdout'])


def get_interface_counters(dut, po_ports):
    # dut.shell("show interfaces counters", module_ignore_errors=True)['stdout']
    greps = ' \|'.join(po_ports)
    command = "show interfaces counters | grep \"IFACE\|---\|%s \""%greps
    output = dut.shell(cmd=command, module_ignore_errors=True)['stdout']
    logger.info(output)
    tx_bps = []
    for item in output:
        if 'Ethernet' in item: 
            rates = item.split()
            tx_bps.append(rates[9])
    return tx_bps


def clear_interface_counters(dut):
    dut.shell("sonic clear counters")
    time.sleep(counter_clear_time)


@pytest.fixture(scope="module")
def updated_tbinfo(tbinfo):
    if tbinfo['topo']['name'] == 't0-56-po2vlan':
        # skip ifaces from PortChannel 201 iface
        ifaces_po_201 = tbinfo['topo']['properties']['topology']['DUT']['portchannel_config']['PortChannel201']['intfs']
        for iface in ifaces_po_201:
            ptf_map_iface_index = tbinfo['topo']['ptf_map']['0'][str(iface)]
            tbinfo['topo']['ptf_map_disabled']['0'].update(
                {str(iface): ptf_map_iface_index})
            tbinfo['topo']['properties']['topology']['disabled_host_interfaces'].append(
                iface)
    return tbinfo


@pytest.fixture(scope="module")
def ignore_ttl(duthosts):
    # on the multi asic devices, the packet can have different ttl based on how the packet is routed
    # within in the device. So set this flag to mask the ttl in the ptf test
    for duthost in duthosts:
        if duthost.sonichost.is_multi_asic:
            return True
    return False


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
        # Loopback0 ip is same on all ASICs
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
def setup(request, tbinfo, duthost, loopback_ips):
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

    logger.info(duthost.shell(cmd='show interfaces portchannel', module_ignore_errors=True['stdout']))
    logger.info(duthost.shell(cmd='show lldp table', module_ignore_errors=True['stdout']))

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
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac, ipv6_src=src_ip, ipv6_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")

    return pkt, exp_pkt


def send_and_verify_packet(ptfadapter, pkt, exp_pkt, tx_port, rx_port):
    """
    Send packet with ptfadapter and verify if packet is forwarded or dropped as expected
    """
    ptfadapter.dataplane.flush()
    wait(3)
    testutils.send(ptfadapter, pkt=pkt, port_id=tx_port, count=20000)
    # testutils.verify_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=5)


def test_ptf(duthost, ptfhost, setup, ptfadapter, rand_selected_dut, tbinfo):
    # duthost = setup['duthost']
    ptf_mgmt_ip = ptfhost.mgmt_ip
    # local_add = setup["local_addrs"][0]
    logger.info("ptf hostname: {}".format(ptfhost.hostname))
    logger.info("ptf mgmt ip: {}".format(ptf_mgmt_ip))
    # logger.info("local add: {}".format(local_add))
    # logger.info(duthost.shell("show ip route | grep 10.250.0.109"))

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    mg_facts_ptf = mg_facts['minigraph_ptf_indices']
    logger.info("mg_facts_ptf: {}".format(mg_facts_ptf))
    # portchannel_members = []
    # for _, v in list(mg_facts["minigraph_portchannels"].items()):
    #     portchannel_members += v['members']
    # logger.info(portchannel_members)

    # ptf_interfaces = []
    # for port in portchannel_members:
    #     ptf_interfaces.append(mg_facts['minigraph_ptf_indices'][port])
    # logger.info("ptf ints: {}".format(ptf_interfaces))

    # tx_port = random.choice(ptf_interfaces)
    # tx_port = int(0)
    # logger.info("tx_port: {}".format(tx_port))

    # for poc in setup['port-channels']:
    #     if poc != setup['portchannel']:
    #         configure_portchannel(duthost, poc, "shutdown")
    # configure_portchannel(duthost, "Ethernet0", "startup")
    # ret_code = duthost.no_shutdown("Ethernet0")

    command = "show interfaces counters | grep U"
    output = duthost.shell(cmd=command, module_ignore_errors=True)['stdout']
    logger.info(output)

    # interf_counters = duthost.show_interface(command="counter")
    # logger.info("Interface Counters: {}".format(interf_counters))

    pkt, exp_pkt = generate_packet('10.250.0.106', '10.250.0.109', setup["router_mac"])
    # pkt, exp_pkt = generate_packet('10.250.0.106', setup['lo0_ipv4'], setup["router_mac"])
    send_and_verify_packet(ptfadapter, pkt, exp_pkt, tx_port, tx_port)

    command = "show interfaces counters | grep U"
    output = duthost.shell(cmd=command, module_ignore_errors=True)['stdout']
    logger.info(output)

    # interf_counters = duthost.show_interface(command="counter")
    # logger.info("Interface Counters: {}".format(interf_counters))

    # for poc in setup['port-channels']:
    #     configure_portchannel(duthost, poc, "startup")
    # configure_portchannel(duthost, "Ethernet0", "shutdown")
    ret_code = duthost.shutdown("Ethernet0")
