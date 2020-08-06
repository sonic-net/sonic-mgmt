import pytest
import ptf.testutils as testutils
from ipaddress import ip_address
import logging

from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]

TOPO_LIST = {'t0', 't1', 't1-lag'}
PORTS_TOPO = {'t1'}
LAG_TOPO = {'t0', 't1-lag'}
DEFAULT_HLIM_TTL = 64
WAIT_EXPECTED_PACKET_TIMEOUT = 5

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


def lag_facts(dut, mg_facts):
    facts = {}

    if not mg_facts['minigraph_portchannels']:
        pytest.fail("minigraph_portchannels is not defined")
    host_facts = dut.setup()['ansible_facts']
    # minigraph facts
    src_lag = mg_facts['minigraph_portchannel_interfaces'][2]['attachto']
    dst_lag = mg_facts['minigraph_portchannel_interfaces'][0]['attachto']
    facts['src_port'] = src_lag
    facts['dst_port'] = dst_lag
    logger.info("src_lag is {}, dst_lag is {}".format(src_lag, dst_lag))
    # lldp facts
    lldp_facts = dut.lldp()['ansible_facts']['lldp']
    facts['dst_host_mac'] = lldp_facts[mg_facts['minigraph_portchannels'][dst_lag]['members'][0]]['chassis']['mac']
    facts['src_host_mac'] = lldp_facts[mg_facts['minigraph_portchannels'][src_lag]['members'][0]]['chassis']['mac']
    facts['dst_router_mac'] = host_facts['ansible_' + dst_lag]['macaddress']
    facts['src_router_mac'] = host_facts['ansible_' + src_lag]['macaddress']
    facts['dst_router_ipv4'] = host_facts['ansible_' + dst_lag]['ipv4']['address']
    dst_ipv6 = host_facts['ansible_' + dst_lag]['ipv6']
    facts['dst_router_ipv6'] = [(item['address']) for item in dst_ipv6 if item['scope'] == 'global'][0]

    dst_port_list = []
    src_port_list = []
    dst_len = len(mg_facts['minigraph_portchannels'][dst_lag]['members'])
    src_len = len(mg_facts['minigraph_portchannels'][src_lag]['members'])
    for i in range(dst_len):
        dst_port_list.append(mg_facts['minigraph_port_indices'][mg_facts['minigraph_portchannels'][dst_lag]['members'][i]])
    facts['dst_port_ids'] = dst_port_list
    for i in range(src_len):
        src_port_list.append(mg_facts['minigraph_port_indices'][mg_facts['minigraph_portchannels'][src_lag]['members'][i]])
    facts['src_port_ids'] = src_port_list

    return facts


def port_facts(dut, mg_facts):
    facts = {}

    if not mg_facts['minigraph_interfaces']:
        pytest.fail("minigraph_interfaces is not defined.")
    host_facts = dut.setup()['ansible_facts']
    # minigraph facts
    src_port = mg_facts['minigraph_interfaces'][2]['attachto']
    dst_port = mg_facts['minigraph_interfaces'][0]['attachto']
    facts['src_port'] = src_port
    facts['dst_port'] = dst_port
    logger.info("src_port is {}, dst_port is {}".format(src_port, dst_port))
    # lldp facts
    lldp_facts = dut.lldp()['ansible_facts']['lldp']
    facts['dst_host_mac'] = lldp_facts[dst_port]['chassis']['mac']
    facts['src_host_mac'] = lldp_facts[src_port]['chassis']['mac']
    facts['dst_router_mac'] = host_facts['ansible_' + dst_port]['macaddress']
    facts['src_router_mac'] = host_facts['ansible_' + src_port]['macaddress']
    facts['dst_router_ipv4'] = host_facts['ansible_' + dst_port]['ipv4']['address']
    dst_ipv6 = host_facts['ansible_' + dst_port]['ipv6']
    facts['dst_router_ipv6'] = [(item['address']) for item in dst_ipv6 if item['scope'] == 'global'][0]
    facts['dst_port_ids'] = [mg_facts['minigraph_port_indices'][dst_port]]
    facts['src_port_ids'] = [mg_facts['minigraph_port_indices'][src_port]]

    return facts


@pytest.fixture(scope='function')
def gather_facts(testbed, duthost):
    facts = {}
    topo = testbed['topo']['name']
    if topo not in TOPO_LIST:
        pytest.skip("Unsupported topology")
    logger.info("Gathering facts on DUT ...")
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    # if minigraph_portchannel_interfaces is not empty - topology with lag
    if mg_facts['minigraph_portchannel_interfaces']:
        facts = lag_facts(duthost, mg_facts)
    else:
        facts = port_facts(duthost, mg_facts)

    logger.info("Facts gathered successfully")

    yield facts


def run_test_ipv6(ptfadapter, gather_facts):
    logger.info("Running test with ipv6 packets")
    dst_host_ipv6 = str(ip_address(unicode(gather_facts['dst_router_ipv6']))+1)

    pkt = testutils.simple_udpv6_packet(
        eth_dst=gather_facts['src_router_mac'],
        eth_src=gather_facts['src_host_mac'],
        ipv6_src=dst_host_ipv6,
        ipv6_dst=dst_host_ipv6,
        ipv6_hlim=DEFAULT_HLIM_TTL

    )
    logger.info("\nSend Packet:\neth_dst: {}, eth_src: {}, ipv6 ip: {}".format(
        gather_facts['src_router_mac'], gather_facts['src_host_mac'], dst_host_ipv6)
    )

    testutils.send(ptfadapter, int(gather_facts['src_port_ids'][0]), pkt)

    pkt = testutils.simple_udpv6_packet(
        eth_dst=gather_facts['dst_host_mac'],
        eth_src=gather_facts['dst_router_mac'],
        ipv6_src=dst_host_ipv6,
        ipv6_dst=dst_host_ipv6,
        ipv6_hlim=DEFAULT_HLIM_TTL-1
    )
    logger.info("\nExpect Packet:\neth_dst: {}, eth_src: {}, ipv6 ip: {}".format(
        gather_facts['dst_host_mac'], gather_facts['dst_router_mac'], dst_host_ipv6)
    )

    port_list = [int(port) for port in gather_facts['dst_port_ids']]
    testutils.verify_packet_any_port(ptfadapter, pkt, port_list, timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def run_test_ipv4(ptfadapter, gather_facts):
    logger.info("Running test with ipv4 packets")
    dst_host_ipv4 = str(ip_address(unicode(gather_facts['dst_router_ipv4'])) + 1)
    pkt = testutils.simple_udp_packet(
        eth_dst=gather_facts['src_router_mac'],
        eth_src=gather_facts['src_host_mac'],
        ip_src=dst_host_ipv4,
        ip_dst=dst_host_ipv4,
        ip_ttl=DEFAULT_HLIM_TTL
    )
    logger.info("\nSend Packet:\neth_dst: {}, eth_src: {}, ipv6 ip: {}".format(
        gather_facts['src_router_mac'], gather_facts['src_host_mac'], dst_host_ipv4)
    )

    testutils.send(ptfadapter, int(gather_facts['src_port_ids'][0]), pkt)

    pkt = testutils.simple_udp_packet(
        eth_dst=gather_facts['dst_host_mac'],
        eth_src=gather_facts['dst_router_mac'],
        ip_src=dst_host_ipv4,
        ip_dst=dst_host_ipv4,
        ip_ttl=DEFAULT_HLIM_TTL-1
    )
    logger.info("\nExpect Packet:\neth_dst: {}, eth_src: {}, ipv6 ip: {}".format(
        gather_facts['dst_host_mac'], gather_facts['dst_router_mac'], dst_host_ipv4)
    )

    port_list = [int(port) for port in gather_facts['dst_port_ids']]
    testutils.verify_packet_any_port(ptfadapter, pkt, port_list, timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def test_dip_sip(request, gather_facts):
    ptfadapter = request.getfixturevalue('ptfadapter')
    ptfadapter.reinit()

    run_test_ipv4(ptfadapter, gather_facts)
    run_test_ipv6(ptfadapter, gather_facts)
