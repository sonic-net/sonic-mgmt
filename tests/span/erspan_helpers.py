'''
Helper functions for ERSPAN sampled port mirroring with truncation tests.
'''

import time
import logging
from socket import IPPROTO_GRE, IPPROTO_TCP

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli, SonicDbCli
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Sampling verification constants.
# We send NUM_SAMPLES * sample_rate packets so that the expected mirrored
# packets are within the expected range.
NUM_SAMPLES = 10000
SAMPLE_COUNT_TOLERANCE = 0.05
MIN_EXPECTED_SAMPLES = int((1 - SAMPLE_COUNT_TOLERANCE) * NUM_SAMPLES)
MAX_EXPECTED_SAMPLES = int((1 + SAMPLE_COUNT_TOLERANCE) * NUM_SAMPLES)

# Estimated encapsulation overhead for length checks, not an inner-frame offset.
ENCAP_OVERHEAD = 62

# Allowance (bytes) for trailing padding / alignment some platforms add.
MIRROR_LEN_TOLERANCE = 8

# Destination MAC (6B), source MAC (6B), and EtherType (2B).
ETHERNET_HEADER_LEN = 14

# Mellanox GRE payload starts with 22 bytes of metadata.
MIRROR_GRE_PROTOCOL = 0x8949
MIRROR_GRE_METADATA_LEN = 22


def expected_mirror_len(original_len, truncate_size=0):
    '''
    Expected length of a mirrored ERSPAN frame as seen on the collector.

    The inner (mirrored) payload is the original packet capped at truncate_size
    when truncation is enabled (truncate_size > 0); otherwise the full original.
    '''
    inner = original_len if truncate_size <= 0 else min(original_len, truncate_size)
    return ENCAP_OVERHEAD + inner


def _matches_probe(raw, expected_probe, metadata_len):
    '''Match inner IP addresses and TCP ports against the sent test packet.'''
    from scapy.layers.inet import IP, TCP, GRE
    from scapy.layers.l2 import Ether

    outer = Ether(raw)
    gre = outer[IP].payload
    pytest_assert(isinstance(gre, GRE) and gre.proto == MIRROR_GRE_PROTOCOL,
                  'Unsupported GRE encapsulation for inner probe matching')
    frame = bytes(gre.payload)[metadata_len:]
    pytest_assert(len(frame) >= ETHERNET_HEADER_LEN, 'Incomplete mirrored Ethernet header')
    inner = Ether(frame)
    if IP not in inner:
        return False
    ip = inner[IP]
    if (ip.src, ip.dst, ip.proto) != (expected_probe[IP].src, expected_probe[IP].dst, IPPROTO_TCP):
        return False
    pytest_assert(isinstance(ip.payload, TCP), 'Matching probe has an incomplete TCP header')
    return (ip[TCP].sport, ip[TCP].dport) == (expected_probe[TCP].sport, expected_probe[TCP].dport)


def collect_erspan_packets(ptfadapter, gre_egress_ports, mirror_session_info, timeout=15, expected_probe=None):
    '''
    Drain packets on gre_egress_ports and return only those that look like
    ERSPAN frames for THIS mirror session.

    Identification:
        - parse with scapy Ether()
        - has IP + GRE layers
        - outer IP.src == session src_ip
        - outer IP.dst == session dst_ip
        - GRE.proto    == session gre_type
        - IP.proto     == IPPROTO_GRE (when inner probe filtering is enabled)

    Args:
        ptfadapter:           ptfadapter fixture
        gre_egress_ports:     list of PTF port indices to drain
        mirror_session_info:  dict with src_ip, dst_ip, gre_type (hex string like "0x8949")
                              and platform-selected gre_metadata_len for probe filtering.
        timeout:              seconds to keep polling
        expected_probe:       Sent test packet used to match inner IPs/TCP ports.
                              If None, only filter by the outer mirror-session headers.

    Returns:
        list of raw packet bytes for each matching ERSPAN frame.
    '''
    from scapy.all import IP, GRE
    from scapy.layers.l2 import Ether

    src_ip = mirror_session_info['src_ip']
    dst_ip = mirror_session_info['dst_ip']
    gre_proto = int(mirror_session_info['gre_type'], 16)

    matched = []
    total_seen = 0
    skipped_reasons = {'parse_fail': 0, 'no_ip_gre': 0, 'wrong_ip': 0, 'wrong_gre_proto': 0}
    if expected_probe is not None:
        pytest_assert('gre_metadata_len' in mirror_session_info,
                      'Probe filtering requires a platform-selected GRE metadata length')
        metadata_len = mirror_session_info['gre_metadata_len']
        skipped_reasons['not_test_traffic'] = 0

    end_time = time.time() + timeout
    while time.time() < end_time:
        any_pkt_this_round = False
        for port in gre_egress_ports:
            # Drain active collector members without waiting on idle LAG members.
            poll_timeout = 0 if len(gre_egress_ports) > 1 else 0.1
            r = ptfadapter.dataplane.poll(device_number=0, port_number=port, timeout=poll_timeout)
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
            if expected_probe is not None and (ip.proto != IPPROTO_GRE or not isinstance(ip.payload, GRE)):
                skipped_reasons['no_ip_gre'] += 1
                continue
            if ip.src != src_ip or ip.dst != dst_ip:
                skipped_reasons['wrong_ip'] += 1
                continue
            if int(gre.proto) != gre_proto:
                skipped_reasons['wrong_gre_proto'] += 1
                continue
            if expected_probe is not None and not _matches_probe(raw, expected_probe, metadata_len):
                skipped_reasons['not_test_traffic'] += 1
                continue
            matched.append(bytes(raw))

        if not any_pkt_this_round:
            time.sleep(0.05)

    logger.info(
        "Collected %d ERSPAN packets on ports %s (seen=%d, skipped=%s)",
        len(matched), gre_egress_ports, total_seen, skipped_reasons
    )
    return matched


# ---------------------------------------------------------------------------
# ERSPAN endpoint constants
# ---------------------------------------------------------------------------
ERSPAN_SESSION_NAME = "erspan_sample_trunc"
ERSPAN_SRC_IP = "10.1.0.32"
ERSPAN_DST_IP = "10.20.0.33"
ERSPAN_DST_PREFIX = "10.20.0.33/32"
ERSPAN_DSCP = "8"
# The collector captures before its peer routes the packet; prevent a return hop.
ERSPAN_TTL = "1"
ERSPAN_GRE_TYPE = "0x8949"
ERSPAN_QUEUE = "0"
ERSPAN_DEFAULT_DIRECTION = "rx"


def remove_mirror_session(duthost, session_name):
    '''Remove bindings owned by this test session before deleting the export.'''
    for (port, direction), entry in sample_bindings(duthost).items():
        if entry['mirror_session'] == session_name:
            duthost.command('config mirror_session sample remove {} {} {}'.format(session_name, port, direction))
    if config_db_key_exists(duthost, 'MIRROR_SESSION|' + session_name):
        duthost.command('config mirror_session remove {}'.format(session_name))


def sample_bindings(duthost):
    db = SonicDbCli(duthost, 'CONFIG_DB')
    keys = db.get_keys('PORT_MIRROR_SAMPLE|*', raise_error_when_not_found=False)
    return {tuple(key.split('|')[1:]): db.hget_all(key) for key in keys if key}


def wait_for_sample_binding(duthost, port, direction, enabled=True):
    '''The export can be active before the source attachment is programmed.'''
    asic = AsicDbCli(duthost)
    oid = SonicDbCli(duthost, 'COUNTERS_DB').hget_key_value('COUNTERS_PORT_NAME_MAP', port)
    stages = {'rx': ['INGRESS'], 'tx': ['EGRESS'], 'both': ['INGRESS', 'EGRESS']}[direction]

    def ready():
        fields = asic.hget_all('{}:{}'.format(asic.ASIC_PORT_TABLE, oid))
        for stage in stages:
            prefix = 'SAI_PORT_ATTR_' + stage
            sample = fields.get(prefix + '_SAMPLEPACKET_ENABLE', 'oid:0x0')
            mirror = fields.get(prefix + '_SAMPLE_MIRROR_SESSION', '0:null')
            if enabled and (sample == 'oid:0x0' or not mirror.startswith('1:oid:')):
                return False
            if not enabled and (sample != 'oid:0x0' or mirror not in ('0:', '0:null')):
                return False
        return bool(fields)

    pytest_assert(wait_until(30, 1, 0, ready), 'Sample binding {} {} did not converge (enabled={})'.format(
        port, direction, enabled))


def config_db_key_exists(duthost, key):
    '''Return True if the CONFIG_DB key exists.'''
    output = duthost.shell(
        'redis-cli -n 4 exists "{}"'.format(key))
    return output['stdout'].strip() == '1'


def assert_mirror_session_config_db_fields(duthost, session_name, expected_fields):
    '''Assert export fields; None means the field must be absent, not just empty.'''
    fields = SonicDbCli(duthost, 'CONFIG_DB').hget_all('MIRROR_SESSION|' + session_name)
    for field, expected in expected_fields.items():
        actual = fields.get(field)
        pytest_assert(
            actual == expected,
            "CONFIG_DB MIRROR_SESSION|{} field '{}' should be {!r}, got {!r}".format(
                session_name, field, expected, actual))


def create_erspan_session_config(duthost, session_name, source_port, direction, sample_rate=None,
                                 truncate_size=None, module_ignore_errors=False):
    '''Create a destination-only export, then return the result of the binding CLI (also used by negative tests).'''
    cmd = 'config mirror_session erspan add {} {} {} {} {} {} {}'.format(
        session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
        ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE)
    duthost.command(cmd)
    cmd = 'config mirror_session sample add {} {} {}'.format(session_name, source_port, direction)
    if sample_rate is not None:
        cmd += ' --sample_rate {}'.format(sample_rate)
    if truncate_size is not None:
        cmd += ' --truncate_size {}'.format(truncate_size)
    return duthost.command(cmd, module_ignore_errors=module_ignore_errors)
