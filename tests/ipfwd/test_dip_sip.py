import pytest
import ptf.testutils as testutils
import logging

from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]

DEFAULT_HLIM_TTL = 64
WAIT_EXPECTED_PACKET_TIMEOUT = 5

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2')
]

@pytest.fixture(scope="module", autouse="True")
def lldp_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, patch_lldpctl, unpatch_lldpctl, localhost):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    patch_lldpctl(localhost, duthost)
    yield
    unpatch_lldpctl(localhost, duthost)

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


def test_dip_sip(tbinfo, ptfadapter, gather_facts, enum_frontend_asic_index):
    ptfadapter.reinit()
    run_test_ipv4(ptfadapter, gather_facts)
    run_test_ipv6(ptfadapter, gather_facts)
