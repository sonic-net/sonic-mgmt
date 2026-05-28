'''
Helper functions for ERSPAN sampled port mirroring with truncation tests.
'''

import time
import logging
import ptf.testutils as testutils
import ptf.packet as packet
from ptf.mask import Mask

logger = logging.getLogger(__name__)

# Sampling verification constants (aligned with sFlow test pattern:
# NUM_SAMPLES=100, tolerance +-40%, proven stable in CI)
NUM_SAMPLES = 100
MIN_EXPECTED_SAMPLES = int(0.6 * NUM_SAMPLES)
MAX_EXPECTED_SAMPLES = int(1.4 * NUM_SAMPLES)

# ERSPAN outer header size: Ether + IP + GRE (same as everflow)
OUTER_HEADER_SIZE = len(packet.Ether()) + len(packet.IP()) + len(packet.GRE())


def build_expected_erspan_packet(mirror_session_info, router_mac, inner_pkt):
    '''
    Build an expected ERSPAN GRE packet with appropriate Mask fields.

    Args:
        mirror_session_info: dict with src_ip, dst_ip, dscp, ttl, gre_type
        router_mac: DUT router MAC (used as outer eth_src)
        inner_pkt: the inner packet that was mirrored

    Returns:
        Mask: masked expected packet for use with verify_packet_any_port
    '''
    expected = testutils.simple_gre_packet(
        eth_src=router_mac,
        ip_src=mirror_session_info['src_ip'],
        ip_dst=mirror_session_info['dst_ip'],
        ip_dscp=int(mirror_session_info['dscp']),
        ip_id=0,
        ip_ttl=int(mirror_session_info['ttl']),
        inner_frame=inner_pkt
    )
    expected["GRE"].proto = int(mirror_session_info['gre_type'], 16)

    expected = Mask(expected)
    expected.set_do_not_care_packet(packet.Ether, "dst")
    expected.set_do_not_care_packet(packet.IP, "ihl")
    expected.set_do_not_care_packet(packet.IP, "len")
    expected.set_do_not_care_packet(packet.IP, "flags")
    expected.set_do_not_care_packet(packet.IP, "chksum")
    expected.set_do_not_care_packet(packet.IP, "id")
    expected.set_do_not_care_packet(packet.IP, "tos")
    # Mask off inner payload (variable fields after GRE encap)
    expected.set_do_not_care(OUTER_HEADER_SIZE * 8, len(inner_pkt) * 8)

    return expected


def collect_erspan_packets(ptfadapter, gre_egress_ports, expected_mirror_pkt, timeout=15):
    '''
    Collect ERSPAN packets matching the expected pattern on gre_egress_ports.

    Args:
        ptfadapter: ptfadapter fixture
        gre_egress_ports: list of ptf port indices where GRE packets may arrive
        expected_mirror_pkt: Mask object for matching
        timeout: seconds to keep collecting

    Returns:
        list: raw packet bytes for each matched ERSPAN packet
    '''
    packets = []
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            result = testutils.verify_packet_any_port(
                ptfadapter, expected_mirror_pkt, ports=gre_egress_ports, timeout=1
            )
            if isinstance(result, tuple):
                _, received_pkt = result
                packets.append(received_pkt)
            else:
                break
        except AssertionError:
            break
    logger.info("Collected %d ERSPAN packets on ports %s", len(packets), gre_egress_ports)
    return packets
