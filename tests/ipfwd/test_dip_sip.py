import pytest
import ptf.testutils as testutils
from ipaddress import ip_address
import logging
import json

from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]

DEFAULT_HLIM_TTL = 64
WAIT_EXPECTED_PACKET_TIMEOUT = 5

pytestmark = [
    pytest.mark.topology('t0', 't1')
]

logger = logging.getLogger(__name__)


def lag_facts(dut, mg_facts):
    facts = {}

    if not mg_facts['minigraph_portchannels']:
        pytest.fail("minigraph_portchannels is not defined")

    # minigraph facts
    src_lag = mg_facts['minigraph_portchannel_interfaces'][2]['attachto']
    dst_lag = mg_facts['minigraph_portchannel_interfaces'][0]['attachto']
    logger.info("src_lag is {}, dst_lag is {}".format(src_lag, dst_lag))

    # lldp facts
    lldp_facts = dut.lldp()['ansible_facts']['lldp']
    facts['dst_host_mac'] = lldp_facts[mg_facts['minigraph_portchannels'][dst_lag]['members'][0]]['chassis']['mac']
    facts['src_host_mac'] = lldp_facts[mg_facts['minigraph_portchannels'][src_lag]['members'][0]]['chassis']['mac']

    facts['dst_router_mac'] = dut.facts['router_mac']
    facts['src_router_mac'] = dut.facts['router_mac']

    for intf in mg_facts['minigraph_portchannel_interfaces']:
        if intf['attachto'] == dst_lag:
            addr = ip_address(unicode(intf['addr']))
            if addr.version == 4:
                facts['dst_router_ipv4'] = intf['addr']
                facts['dst_host_ipv4'] = intf['peer_addr']
            elif addr.version == 6:
                facts['dst_router_ipv6'] = intf['addr']
                facts['dst_host_ipv6'] = intf['peer_addr']

    facts['dst_port_ids'] = []
    for intf in mg_facts['minigraph_portchannels'][dst_lag]['members']:
        facts['dst_port_ids'].append(mg_facts['minigraph_port_indices'][intf])

    facts['src_port_ids'] = []
    for intf in mg_facts['minigraph_portchannels'][src_lag]['members']:
        facts['src_port_ids'].append(mg_facts['minigraph_port_indices'][intf])

    return facts


def port_facts(dut, mg_facts):
    facts = {}

    if not mg_facts['minigraph_interfaces']:
        pytest.fail("minigraph_interfaces is not defined.")

    # minigraph facts
    src_port = mg_facts['minigraph_interfaces'][2]['attachto']
    dst_port = mg_facts['minigraph_interfaces'][0]['attachto']
    logger.info("src_port is {}, dst_port is {}".format(src_port, dst_port))

    # lldp facts
    lldp_facts = dut.lldp()['ansible_facts']['lldp']
    facts['dst_host_mac'] = lldp_facts[dst_port]['chassis']['mac']
    facts['src_host_mac'] = lldp_facts[src_port]['chassis']['mac']

    facts['dst_router_mac'] = dut.facts['router_mac']
    facts['src_router_mac'] = dut.facts['router_mac']

    for intf in mg_facts['minigraph_interfaces']:
        if intf['attachto'] == dst_port:
            addr = ip_address(unicode(intf['addr']))
            if addr.version == 4:
                facts['dst_router_ipv4'] = intf['addr']
                facts['dst_host_ipv4'] = intf['peer_addr']
            elif addr.version == 6:
                facts['dst_router_ipv6'] = intf['addr']
                facts['dst_host_ipv6'] = intf['peer_addr']

    facts['dst_port_ids'] = [mg_facts['minigraph_port_indices'][dst_port]]
    facts['src_port_ids'] = [mg_facts['minigraph_port_indices'][src_port]]

    return facts


@pytest.fixture(scope='function')
def gather_facts(tbinfo, duthost):
    facts = {}

    topo_type = tbinfo['topo']['type']
    if topo_type not in ('t0', 't1'):
        pytest.skip("Unsupported topology")

    logger.info("Gathering facts on DUT ...")
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    # if minigraph_portchannel_interfaces is not empty - topology with lag
    if mg_facts['minigraph_portchannel_interfaces']:
        facts = lag_facts(duthost, mg_facts)
    else:
        facts = port_facts(duthost, mg_facts)

    logger.info("gathered_facts={}".format(json.dumps(facts, indent=2)))

    yield facts


def run_test_ipv6(ptfadapter, facts):
    logger.info("Running test with ipv6 packets")

    pkt = testutils.simple_udpv6_packet(
        eth_dst=facts['src_router_mac'],
        eth_src=facts['src_host_mac'],
        ipv6_src=facts['dst_host_ipv6'],
        ipv6_dst=facts['dst_host_ipv6'],
        ipv6_hlim=DEFAULT_HLIM_TTL

    )
    logger.info("\nSend Packet:\neth_dst: {}, eth_src: {}, ipv6 ip: {}".format(
        facts['src_router_mac'], facts['src_host_mac'], facts['dst_host_ipv6'])
    )

    testutils.send(ptfadapter, facts['src_port_ids'][0], pkt)

    exp_pkt = testutils.simple_udpv6_packet(
        eth_dst=facts['dst_host_mac'],
        eth_src=facts['dst_router_mac'],
        ipv6_src=facts['dst_host_ipv6'],
        ipv6_dst=facts['dst_host_ipv6'],
        ipv6_hlim=DEFAULT_HLIM_TTL-1
    )
    logger.info("\nExpect Packet:\neth_dst: {}, eth_src: {}, ipv6 ip: {}".format(
        facts['dst_host_mac'], facts['dst_router_mac'], facts['dst_host_ipv6'])
    )

    testutils.verify_packet_any_port(ptfadapter, exp_pkt, facts['dst_port_ids'], timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def run_test_ipv4(ptfadapter, facts):
    logger.info("Running test with ipv4 packets")
    pkt = testutils.simple_udp_packet(
        eth_dst=facts['src_router_mac'],
        eth_src=facts['src_host_mac'],
        ip_src=facts['dst_host_ipv4'],
        ip_dst=facts['dst_host_ipv4'],
        ip_ttl=DEFAULT_HLIM_TTL
    )
    logger.info("\nSend Packet:\neth_dst: {}, eth_src: {}, ipv4 ip: {}".format(
        facts['src_router_mac'], facts['src_host_mac'], facts['dst_host_ipv4'])
    )

    testutils.send(ptfadapter, facts['src_port_ids'][0], pkt)

    exp_pkt = testutils.simple_udp_packet(
        eth_dst=facts['dst_host_mac'],
        eth_src=facts['dst_router_mac'],
        ip_src=facts['dst_host_ipv4'],
        ip_dst=facts['dst_host_ipv4'],
        ip_ttl=DEFAULT_HLIM_TTL-1
    )
    logger.info("\nExpect Packet:\neth_dst: {}, eth_src: {}, ipv4 ip: {}".format(
        facts['dst_host_mac'], facts['dst_router_mac'], facts['dst_host_ipv4'])
    )

    testutils.verify_packet_any_port(ptfadapter, exp_pkt, facts['dst_port_ids'], timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def test_dip_sip(ptfadapter, gather_facts):
    ptfadapter.reinit()
    run_test_ipv4(ptfadapter, gather_facts)
    run_test_ipv6(ptfadapter, gather_facts)
