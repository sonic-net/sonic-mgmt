'''
Helper functions for ERSPAN sampled port mirroring with truncation tests.
'''

import time
import logging
import ptf.packet as packet

logger = logging.getLogger(__name__)

# Sampling verification constants.
# We send NUM_SAMPLES * sample_rate packets so that the expected mirrored
# packets are within the expected range.
NUM_SAMPLES = 100
MIN_EXPECTED_SAMPLES = int(0.75 * NUM_SAMPLES)
MAX_EXPECTED_SAMPLES = int(1.25 * NUM_SAMPLES)

# ERSPAN outer header size: Ether + IP + GRE (same as everflow)
OUTER_HEADER_SIZE = len(packet.Ether()) + len(packet.IP()) + len(packet.GRE())


def collect_erspan_packets(ptfadapter, gre_egress_ports, mirror_session_info, timeout=15):
    '''
    Drain packets on gre_egress_ports and return only those that look like
    ERSPAN frames for THIS mirror session.

    Identification:
        - parse with scapy Ether()
        - has IP + GRE layers
        - outer IP.src == session src_ip
        - outer IP.dst == session dst_ip
        - GRE.proto    == session gre_type
        - IP.proto     == 47 (GRE)

    Args:
        ptfadapter:           ptfadapter fixture
        gre_egress_ports:     list of PTF port indices to drain
        mirror_session_info:  dict with src_ip, dst_ip, gre_type (hex string like "0x8949")
        timeout:              seconds to keep polling

    Returns:
        list of raw packet bytes for each matching ERSPAN frame.
    '''
    from scapy.layers.inet import IP, GRE
    from scapy.layers.l2 import Ether

    src_ip = mirror_session_info['src_ip']
    dst_ip = mirror_session_info['dst_ip']
    gre_proto = int(mirror_session_info['gre_type'], 16)

    matched = []
    total_seen = 0
    skipped_reasons = {'parse_fail': 0, 'no_ip_gre': 0, 'wrong_ip': 0, 'wrong_gre_proto': 0}

    end_time = time.time() + timeout
    while time.time() < end_time:
        any_pkt_this_round = False
        for port in gre_egress_ports:
            r = ptfadapter.dataplane.poll(device_number=0, port_number=port, timeout=0.1)
            if r is None:
                continue
            # poll returns (port, pkt, ts) or (dev, port, pkt, ts) depending on PTF version
            raw = r[-2]
            if raw is None:
                continue
            any_pkt_this_round = True
            total_seen += 1
            try:
                pkt = Ether(raw)
            except Exception:
                skipped_reasons['parse_fail'] += 1
                continue
            if not pkt.haslayer(IP) or not pkt.haslayer(GRE):
                skipped_reasons['no_ip_gre'] += 1
                continue
            ip = pkt[IP]
            gre = pkt[GRE]
            if ip.src != src_ip or ip.dst != dst_ip:
                skipped_reasons['wrong_ip'] += 1
                continue
            if int(gre.proto) != gre_proto:
                skipped_reasons['wrong_gre_proto'] += 1
                continue
            matched.append(bytes(raw))

        if not any_pkt_this_round:
            time.sleep(0.05)

    logger.info(
        "Collected %d ERSPAN packets on ports %s (seen=%d, skipped=%s)",
        len(matched), gre_egress_ports, total_seen, skipped_reasons
    )
    return matched
