'''
Helper functions for ERSPAN sampled port mirroring with truncation tests.
'''

import json
import time
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Sampling verification constants.
# We send NUM_SAMPLES * sample_rate packets so that the expected mirrored
# packets are within the expected range.
NUM_SAMPLES = 1000
MIN_EXPECTED_SAMPLES = int(0.95 * NUM_SAMPLES)
MAX_EXPECTED_SAMPLES = int(1.05 * NUM_SAMPLES)

# ERSPAN encapsulation overhead, measured on hardware (see the test plan section
# "ERSPAN Packet Structure"). A mirrored frame prepends:
#   Outer Ethernet (14B) + Outer IP (20B) + GRE + vendor/ERSPAN shim (28B) = 62B.
# So a mirrored frame length = ENCAP_OVERHEAD + min(original_len, truncate_size)
ENCAP_OVERHEAD = 62

# Allowance (bytes) for trailing padding / alignment some platforms add.
MIRROR_LEN_TOLERANCE = 8


def expected_mirror_len(original_len, truncate_size=0):
    '''
    Expected length of a mirrored ERSPAN frame as seen on the collector.

    The inner (mirrored) payload is the original packet capped at truncate_size
    when truncation is enabled (truncate_size > 0); otherwise the full original.
    '''
    inner = original_len if truncate_size <= 0 else min(original_len, truncate_size)
    return ENCAP_OVERHEAD + inner


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


# ---------------------------------------------------------------------------
# ERSPAN endpoint constants
# ---------------------------------------------------------------------------
ERSPAN_SESSION_NAME = "erspan_sample_trunc"
ERSPAN_SRC_IP = "10.1.0.32"
ERSPAN_DST_IP = "10.20.0.33"
ERSPAN_DST_PREFIX = "10.20.0.33/32"
ERSPAN_DSCP = "8"
ERSPAN_TTL = "64"
ERSPAN_GRE_TYPE = "0x8949"
ERSPAN_QUEUE = "0"
ERSPAN_DEFAULT_DIRECTION = "rx"

# Synthetic unicast destination MAC for ERSPAN sampling probe traffic. A static FDB
# entry pins this MAC to the mirror source port so probes are unicast to a single port
# RX probes injected on the source port are ingress-sampled then same-port dropped;
# TX probes injected on the tx_ingress peer are forwarded out the source port (egress-sampled).
PROBE_UNICAST_DST_MAC = "02:11:22:33:44:55"


def apply_static_fdb(duthost, vlan_id, port, mac, op="SET", ignore_errors=False):
    '''
    Program (op="SET") or remove (op="DEL") a static FDB entry mapping `mac` to
    `port` in Vlan<vlan_id> via swssconfig, so unicast frames destined to `mac`
    are forwarded only out `port` instead of being flooded to the whole VLAN.
    '''
    fdb_mac = mac.replace(":", "-")
    entry = [{
        "FDB_TABLE:Vlan{}:{}".format(vlan_id, fdb_mac): {
            "port": port,
            "type": "static",
        },
        "OP": op,
    }]
    dut_json = "/tmp/erspan_fdb_{}.json".format(fdb_mac)
    ctr_json = "/erspan_fdb_{}.json".format(fdb_mac)
    duthost.copy(content=json.dumps(entry), dest=dut_json)
    duthost.command("docker cp {} swss:{}".format(dut_json, ctr_json),
                    module_ignore_errors=ignore_errors)
    duthost.command("docker exec -i swss swssconfig {}".format(ctr_json),
                    module_ignore_errors=ignore_errors)
    duthost.command("docker exec -i swss rm -f {}".format(ctr_json), module_ignore_errors=True)
    duthost.command("rm -f {}".format(dut_json), module_ignore_errors=True)

    if ignore_errors:
        return

    def _fdb_applied():
        count = int(duthost.shell(
            "show mac | grep -i {} | grep -w {} | wc -l".format(mac, port))["stdout"])
        return count >= 1 if op == "SET" else count == 0

    pytest_assert(
        wait_until(10, 1, 0, _fdb_applied),
        "Static FDB {} for {} was not applied".format(op, mac))


def remove_mirror_session(duthost, session_name):
    '''Remove a mirror session, ignoring errors if it does not exist.'''
    duthost.command(
        'config mirror_session remove {}'.format(session_name),
        module_ignore_errors=True)


def get_mirror_session_config_db_field(duthost, session_name, field):
    '''Return a CONFIG_DB MIRROR_SESSION field value (empty string when unset).'''
    output = duthost.shell(
        'redis-cli -n 4 hget "MIRROR_SESSION|{}" "{}"'.format(session_name, field))
    return output['stdout'].strip()


def mirror_session_config_db_exists(duthost, session_name):
    '''Return True if the CONFIG_DB MIRROR_SESSION key for session_name exists.'''
    output = duthost.shell(
        'redis-cli -n 4 exists "MIRROR_SESSION|{}"'.format(session_name))
    return output['stdout'].strip() == '1'


def assert_mirror_session_config_db_fields(duthost, session_name, expected_fields):
    '''Assert each CONFIG_DB MIRROR_SESSION field matches its expected value.'''
    for field, expected in expected_fields.items():
        actual = get_mirror_session_config_db_field(duthost, session_name, field)
        pytest_assert(
            actual == str(expected),
            "CONFIG_DB MIRROR_SESSION|{} field '{}' should be {!r}, got {!r}".format(
                session_name, field, str(expected), actual))


def create_erspan_session_config(duthost, session_name, sample_rate=None,
                                 truncate_size=None, source_port=None,
                                 direction=None, module_ignore_errors=False):
    '''
    Create an ERSPAN mirror session via the config CLI using the shared ERSPAN_*
    endpoint constants.

    A leftover session with the same name (e.g. from a previously crashed run) is
    removed first so the create always starts from a clean slate.

    source_port / direction are appended as positional CLI args when provided
    (direction is only appended together with source_port, matching the CLI's
    positional order). sample_rate / truncate_size are appended as --flags only
    when not None (note that 0 IS appended, since the CLI accepts 0 to mean
    "disabled"). When module_ignore_errors is True the non-zero rc is returned
    instead of raising, so negative tests can inspect it.

    Returns the duthost.command result dict.
    '''
    if direction is not None and source_port is None:
        raise ValueError(
            'direction is only applied together with source_port; pass source_port too')
    remove_mirror_session(duthost, session_name)
    cmd = 'config mirror_session erspan add {} {} {} {} {} {} {}'.format(
        session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
        ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE)
    if source_port is not None:
        cmd += ' {}'.format(source_port)
        if direction is not None:
            cmd += ' {}'.format(direction)
    if sample_rate is not None:
        cmd += ' --sample_rate {}'.format(sample_rate)
    if truncate_size is not None:
        cmd += ' --truncate_size {}'.format(truncate_size)
    return duthost.command(cmd, module_ignore_errors=module_ignore_errors)
