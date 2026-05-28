'''
Test ERSPAN sampled port mirroring with truncation on SONiC.
'''

import time
import pytest
import logging

import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert
from erspan_helpers import (
    NUM_SAMPLES,
    MIN_EXPECTED_SAMPLES,
    MAX_EXPECTED_SAMPLES,
    OUTER_HEADER_SIZE,
    build_expected_erspan_packet,
    collect_erspan_packets,
)
from tests.span.conftest import (
    ERSPAN_SRC_IP,
    ERSPAN_DST_IP,
    ERSPAN_DSCP,
    ERSPAN_TTL,
    ERSPAN_GRE_TYPE,
    ERSPAN_QUEUE,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
]

DEFAULT_TRUNCATE_SIZE = 128
DEFAULT_SAMPLE_RATE = 50000


# ---------------------------------------------------------------------------
# Group 1: Capability Discovery
# ---------------------------------------------------------------------------

def test_sampling_capability_reported(erspan_capabilities):
    '''
    Verify STATE_DB reports sampling capability keys.

    Steps:
        1. Read switch capabilities from STATE_DB
        2. Check PORT_INGRESS_SAMPLE_MIRROR_CAPABLE exists and is true/false
        3. Check PORT_EGRESS_SAMPLE_MIRROR_CAPABLE exists and is true/false

    Pass Criteria: Both capability keys exist with valid boolean values.
    '''
    for key in ["PORT_INGRESS_SAMPLE_MIRROR_CAPABLE", "PORT_EGRESS_SAMPLE_MIRROR_CAPABLE"]:
        value = erspan_capabilities.get(key, "")
        pytest_assert(
            value.lower() in ('true', 'false'),
            "Capability key {} should be 'true' or 'false', got '{}'".format(key, value)
        )
        logger.info("Capability %s = %s", key, value)


def test_truncation_capability_reported(erspan_capabilities):
    '''
    Verify STATE_DB reports truncation capability key.

    Steps:
        1. Read switch capabilities from STATE_DB
        2. Check SAMPLEPACKET_TRUNCATION_CAPABLE exists and is true/false

    Pass Criteria: Capability key exists with a valid boolean value.
    '''
    key = "SAMPLEPACKET_TRUNCATION_CAPABLE"
    value = erspan_capabilities.get(key, "")
    pytest_assert(
        value.lower() in ('true', 'false'),
        "Capability key {} should be 'true' or 'false', got '{}'".format(key, value)
    )
    logger.info("Capability %s = %s", key, value)


def test_all_capabilities_reported(erspan_capabilities):
    '''
    Verify STATE_DB reports all 5 mirror capability keys defined in HLD.

    Steps:
        1. Read switch capabilities from STATE_DB
        2. Verify all HLD-defined keys are present with valid values

    Pass Criteria: All 5 capability keys exist with 'true' or 'false' values.
    '''
    expected_keys = [
        "PORT_INGRESS_MIRROR_CAPABLE",
        "PORT_EGRESS_MIRROR_CAPABLE",
        "PORT_INGRESS_SAMPLE_MIRROR_CAPABLE",
        "PORT_EGRESS_SAMPLE_MIRROR_CAPABLE",
        "SAMPLEPACKET_TRUNCATION_CAPABLE",
    ]
    for key in expected_keys:
        value = erspan_capabilities.get(key, "")
        pytest_assert(
            value.lower() in ('true', 'false'),
            "Capability key {} should be 'true' or 'false', got '{}'".format(key, value)
        )
        logger.info("Capability %s = %s", key, value)


# ---------------------------------------------------------------------------
# Group 2: CLI & CONFIG_DB Validation
# ---------------------------------------------------------------------------

def test_create_erspan_session_with_sample_rate(
        duthosts,
        rand_one_dut_hostname,
        skip_if_sampling_unsupported):
    '''
    Verify ERSPAN session with --sample_rate is written to CONFIG_DB.

    Steps:
        1. Create ERSPAN mirror session with --sample_rate 50000
        2. Read sample_rate from CONFIG_DB
        3. Remove session

    Pass Criteria: CONFIG_DB MIRROR_SESSION entry has correct sample_rate value.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_sr_session"
    try:
        duthost.command(
            'config mirror_session erspan add {} {} {} {} {} {} {} --sample_rate {}'.format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE,
                DEFAULT_SAMPLE_RATE
            )
        )
        result = duthost.shell(
            'redis-cli -n 4 hget "MIRROR_SESSION|{}" "sample_rate"'.format(session_name)
        )
        pytest_assert(
            result['stdout'].strip() == str(DEFAULT_SAMPLE_RATE),
            "CONFIG_DB sample_rate should be {}, got '{}'".format(
                DEFAULT_SAMPLE_RATE, result['stdout'].strip())
        )
    finally:
        duthost.command('config mirror_session remove {}'.format(session_name),
                        module_ignore_errors=True)


def test_create_erspan_session_with_truncate_size(
        duthosts,
        rand_one_dut_hostname,
        skip_if_truncation_unsupported):
    '''
    Verify ERSPAN session with --truncate_size is written to CONFIG_DB.

    Steps:
        1. Create ERSPAN mirror session with --truncate_size 128
        2. Read truncate_size from CONFIG_DB
        3. Remove session

    Pass Criteria: CONFIG_DB MIRROR_SESSION entry has correct truncate_size value.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_ts_session"
    try:
        duthost.command(
            'config mirror_session erspan add {} {} {} {} {} {} {} --truncate_size {}'.format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE,
                DEFAULT_TRUNCATE_SIZE
            )
        )
        result = duthost.shell(
            'redis-cli -n 4 hget "MIRROR_SESSION|{}" "truncate_size"'.format(session_name)
        )
        pytest_assert(
            result['stdout'].strip() == str(DEFAULT_TRUNCATE_SIZE),
            "CONFIG_DB truncate_size should be {}, got '{}'".format(
                DEFAULT_TRUNCATE_SIZE, result['stdout'].strip())
        )
    finally:
        duthost.command('config mirror_session remove {}'.format(session_name),
                        module_ignore_errors=True)


def test_create_erspan_session_with_both(
        duthosts,
        rand_one_dut_hostname,
        skip_if_sampling_unsupported,
        skip_if_truncation_unsupported):
    '''
    Verify ERSPAN session with both sample_rate and truncate_size in CONFIG_DB.

    Steps:
        1. Create ERSPAN session with --sample_rate 50000 --truncate_size 128
        2. Read both fields from CONFIG_DB
        3. Remove session

    Pass Criteria: Both fields are present with correct values in CONFIG_DB.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_both_session"
    try:
        duthost.command(
            'config mirror_session erspan add {} {} {} {} {} {} {}'
            ' --sample_rate {} --truncate_size {}'.format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE,
                DEFAULT_SAMPLE_RATE, DEFAULT_TRUNCATE_SIZE
            )
        )
        sr = duthost.shell(
            'redis-cli -n 4 hget "MIRROR_SESSION|{}" "sample_rate"'.format(session_name)
        )['stdout'].strip()
        ts = duthost.shell(
            'redis-cli -n 4 hget "MIRROR_SESSION|{}" "truncate_size"'.format(session_name)
        )['stdout'].strip()
        pytest_assert(sr == str(DEFAULT_SAMPLE_RATE),
                      "sample_rate mismatch: expected {}, got {}".format(DEFAULT_SAMPLE_RATE, sr))
        pytest_assert(ts == str(DEFAULT_TRUNCATE_SIZE),
                      "truncate_size mismatch: expected {}, got {}".format(DEFAULT_TRUNCATE_SIZE, ts))
    finally:
        duthost.command('config mirror_session remove {}'.format(session_name),
                        module_ignore_errors=True)


def test_remove_erspan_session_with_sampling(
        duthosts,
        rand_one_dut_hostname,
        skip_if_sampling_unsupported):
    '''
    Verify CONFIG_DB is cleaned up after removing a sampled ERSPAN session.

    Steps:
        1. Create ERSPAN session with --sample_rate 256
        2. Remove the session
        3. Check CONFIG_DB key no longer exists

    Pass Criteria: MIRROR_SESSION key is removed from CONFIG_DB.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_remove_session"
    duthost.command(
        'config mirror_session erspan add {} {} {} {} {} {} {} --sample_rate {}'.format(
            session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
            ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE, 256
        )
    )
    duthost.command('config mirror_session remove {}'.format(session_name))
    result = duthost.shell(
        'redis-cli -n 4 exists "MIRROR_SESSION|{}"'.format(session_name)
    )
    pytest_assert(
        result['stdout'].strip() == '0',
        "MIRROR_SESSION|{} should not exist after removal".format(session_name)
    )


@pytest.mark.parametrize("invalid_rate", [100, 255, 8388609])
def test_invalid_sample_rate_rejected(duthosts, rand_one_dut_hostname, invalid_rate):
    '''
    Verify CLI rejects sample_rate outside valid range (256-8388608).

    Steps:
        1. Attempt to create ERSPAN session with invalid sample_rate
        2. Verify command fails

    Pass Criteria: CLI returns non-zero exit code.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_invalid_sr"
    result = duthost.command(
        'config mirror_session erspan add {} {} {} {} {} {} {} --sample_rate {}'.format(
            session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
            ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE, invalid_rate
        ),
        module_ignore_errors=True
    )
    pytest_assert(
        result['rc'] != 0,
        "CLI should reject invalid sample_rate={} but command succeeded".format(invalid_rate)
    )
    duthost.command('config mirror_session remove {}'.format(session_name),
                    module_ignore_errors=True)


@pytest.mark.parametrize("invalid_size", [32, 63, 9217])
def test_invalid_truncate_size_rejected(duthosts, rand_one_dut_hostname, invalid_size):
    '''
    Verify CLI rejects truncate_size outside valid range (64-9216).

    Steps:
        1. Attempt to create ERSPAN session with invalid truncate_size
        2. Verify command fails

    Pass Criteria: CLI returns non-zero exit code.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_invalid_ts"
    result = duthost.command(
        'config mirror_session erspan add {} {} {} {} {} {} {} --truncate_size {}'.format(
            session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
            ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE, invalid_size
        ),
        module_ignore_errors=True
    )
    pytest_assert(
        result['rc'] != 0,
        "CLI should reject invalid truncate_size={} but command succeeded".format(invalid_size)
    )
    duthost.command('config mirror_session remove {}'.format(session_name),
                    module_ignore_errors=True)


def test_sample_rate_zero_disables_sampling(duthosts, rand_one_dut_hostname):
    """
    Verify sample_rate=0 is accepted and semantically equivalent to omitting the flag:
    the field MUST NOT be written to CONFIG_DB. orchagent treats absence as "no sampling".
    """
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_sr_zero"
    try:
        result = duthost.command(
            "config mirror_session erspan add {} {} {} {} {} {} {} --sample_rate 0".format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE
            ),
            module_ignore_errors=True
        )
        pytest_assert(
            result["rc"] == 0,
            "CLI should accept sample_rate=0 (disabled), got rc={} stderr={}".format(
                result["rc"], result.get("stderr", "")
            )
        )
        field = duthost.shell(
            'redis-cli -n 4 hget "MIRROR_SESSION|{}" sample_rate'.format(session_name)
        )["stdout"].strip()
        pytest_assert(
            field == "",
            "sample_rate=0 should NOT be written to CONFIG_DB, got: {!r}".format(field)
        )
    finally:
        duthost.command("config mirror_session remove {}".format(session_name),
                        module_ignore_errors=True)


def test_truncate_size_zero_disables_truncation(duthosts, rand_one_dut_hostname):
    """
    Verify truncate_size=0 is accepted and semantically equivalent to omitting the flag:
    the field MUST NOT be written to CONFIG_DB. orchagent treats absence as "no truncation".
    Must be paired with a valid sample_rate, since truncate_size without sample_rate is
    rejected per HLD (see test_truncate_without_sample_rate_rejected).
    """
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_ts_zero"
    try:
        result = duthost.command(
            "config mirror_session erspan add {} {} {} {} {} {} {} "
            "--sample_rate 256 --truncate_size 0".format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE
            ),
            module_ignore_errors=True
        )
        pytest_assert(
            result["rc"] == 0,
            "CLI should accept truncate_size=0 (disabled), got rc={} stderr={}".format(
                result["rc"], result.get("stderr", "")
            )
        )
        field = duthost.shell(
            'redis-cli -n 4 hget "MIRROR_SESSION|{}" truncate_size'.format(session_name)
        )["stdout"].strip()
        pytest_assert(
            field == "",
            "truncate_size=0 should NOT be written to CONFIG_DB, got: {!r}".format(field)
        )
    finally:
        duthost.command("config mirror_session remove {}".format(session_name),
                        module_ignore_errors=True)



def test_truncate_without_sample_rate_rejected(duthosts, rand_one_dut_hostname):
    '''
    Verify truncate_size without sample_rate is rejected by orchagent (HLD requirement).

    Validation is implemented in SwSS orchagent (MirrorOrch::createEntry), not in CLI.
    CLI will accept the config and write CONFIG_DB; orchagent then rejects it as
    task_invalid_entry, so the session never reaches STATE_DB status="active".

    Steps:
        1. Create ERSPAN session with only --truncate_size (no --sample_rate). CLI rc must be 0.
        2. Wait briefly for orchagent processing.
        3. Verify STATE_DB MIRROR_SESSION_TABLE status is NOT "active".

    Pass Criteria: orchagent rejects the session and status never becomes active.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_trunc_no_sr"
    try:
        result = duthost.command(
            'config mirror_session erspan add {} {} {} {} {} {} {} --truncate_size 128'.format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE
            ),
            module_ignore_errors=True
        )
        pytest_assert(
            result['rc'] == 0,
            "CLI should accept the command (validation is in SwSS), got rc={} stderr={}".format(
                result['rc'], result.get('stderr', '')
            )
        )
        time.sleep(2)
        status = duthost.shell(
            'sonic-db-cli STATE_DB HGET "MIRROR_SESSION_TABLE|{}" status'.format(session_name)
        )['stdout'].strip()
        pytest_assert(
            status != 'active',
            "Session with truncate_size but no sample_rate should not be active, got status={!r}".format(status)
        )
    finally:
        duthost.command('config mirror_session remove {}'.format(session_name),
                        module_ignore_errors=True)


@pytest.mark.parametrize("direction", ["tx", "both"])
def test_sampling_non_rx_direction_rejected(
        duthosts,
        rand_one_dut_hostname,
        skip_if_sampling_unsupported,
        direction):
    '''
    Verify sampled mirroring only supports RX direction; non-RX is rejected by
    orchagent (HLD requirement).

    Validation is implemented in SwSS orchagent (MirrorOrch::createEntry), not in CLI.
    CLI will accept the config and write CONFIG_DB; orchagent then rejects it as
    task_invalid_entry, so the session never reaches STATE_DB status="active".

    Steps:
        1. Create ERSPAN session with --sample_rate and direction=tx/both. CLI rc must be 0.
        2. Wait briefly for orchagent processing.
        3. Verify STATE_DB MIRROR_SESSION_TABLE status is NOT "active".

    Pass Criteria: orchagent rejects the session and status never becomes active.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_non_rx_sr"
    try:
        result = duthost.command(
            'config mirror_session erspan add {} {} {} {} {} {} {} Ethernet0 {}'
            ' --sample_rate 256'.format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE, direction
            ),
            module_ignore_errors=True
        )
        pytest_assert(
            result['rc'] == 0,
            "CLI should accept the command (validation is in SwSS), got rc={} stderr={}".format(
                result['rc'], result.get('stderr', '')
            )
        )
        time.sleep(2)
        status = duthost.shell(
            'sonic-db-cli STATE_DB HGET "MIRROR_SESSION_TABLE|{}" status'.format(session_name)
        )['stdout'].strip()
        pytest_assert(
            status != 'active',
            "Session with sample_rate + direction={} should not be active, got status={!r}".format(
                direction, status
            )
        )
    finally:
        duthost.command('config mirror_session remove {}'.format(session_name),
                        module_ignore_errors=True)


def test_show_mirror_session_displays_new_columns(
        duthosts,
        rand_one_dut_hostname,
        skip_if_sampling_unsupported):
    '''
    Verify 'show mirror_session' output includes sample_rate and truncate_size.

    Steps:
        1. Create ERSPAN session with --sample_rate 512 --truncate_size 128
        2. Run 'show mirror_session'
        3. Check output contains the configured values
        4. Remove session

    Pass Criteria: show output contains '512' and '128'.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_show_cols"
    try:
        duthost.command(
            'config mirror_session erspan add {} {} {} {} {} {} {}'
            ' --sample_rate 512 --truncate_size 128'.format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE
            )
        )
        output = duthost.shell("show mirror_session")['stdout']
        pytest_assert(
            '512' in output,
            "show mirror_session should display sample_rate value 512"
        )
        pytest_assert(
            '128' in output,
            "show mirror_session should display truncate_size value 128"
        )
    finally:
        duthost.command('config mirror_session remove {}'.format(session_name),
                        module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Group 3: Truncation Data-Plane Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'truncate_size': 128},
                          {'sample_rate': 256, 'truncate_size': 256}],
                         indirect=True)
def test_erspan_truncation_large_packet(ptfadapter, skip_if_truncation_unsupported, erspan_session):
    '''
    Verify mirrored packet is truncated when original exceeds truncate_size.

    Steps:
        1. Create ERSPAN session with truncate_size (128 or 256)
        2. Send a 1500B TCP packet from source port
        3. Capture ERSPAN GRE packets on egress port
        4. Verify mirrored packet length is less than 1500B

    Pass Criteria: Mirrored ERSPAN packet is truncated (len < 1500B).
    '''
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=1500, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=5)
    pytest_assert(len(packets) > 0, "No ERSPAN packets received on GRE egress port")

    for pkt_bytes in packets:
        pytest_assert(
            len(pkt_bytes) < 1500,
            "Mirrored ERSPAN packet (len={}) should be < 1500B with truncation".format(
                len(pkt_bytes))
        )


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'truncate_size': 128},
                          {'sample_rate': 256, 'truncate_size': 256}],
                         indirect=True)
def test_erspan_truncation_small_packet(ptfadapter, skip_if_truncation_unsupported, erspan_session):
    '''
    Verify packets smaller than truncate_size are mirrored without truncation.

    Steps:
        1. Create ERSPAN session with truncate_size (128 or 256)
        2. Send a 64B TCP packet (smaller than truncate_size)
        3. Capture ERSPAN GRE packets on egress port
        4. Verify mirrored packet carries the full original payload

    Pass Criteria: Mirrored packet length >= 64B + GRE header overhead.
    '''
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=64, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=5)
    pytest_assert(len(packets) > 0, "No ERSPAN packets received on GRE egress port")

    for pkt_bytes in packets:
        pytest_assert(
            len(pkt_bytes) >= 64 + OUTER_HEADER_SIZE,
            "Small packet mirror (len={}) should include full 64B + headers".format(
                len(pkt_bytes))
        )


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'truncate_size': 128},
                          {'sample_rate': 256, 'truncate_size': 256}],
                         indirect=True)
def test_erspan_truncation_exact_size(ptfadapter, skip_if_truncation_unsupported, erspan_session):
    '''
    Verify behavior when packet size equals truncate_size boundary.

    Steps:
        1. Create ERSPAN session with truncate_size
        2. Send a packet with length exactly equal to truncate_size
        3. Capture ERSPAN GRE packets on egress port

    Pass Criteria: ERSPAN packet is received (boundary case handled correctly).
    '''
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']
    truncate_size = erspan_session['truncate_size']

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=truncate_size, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=5)
    pytest_assert(len(packets) > 0, "No ERSPAN packets received on GRE egress port")
    logger.info("Exact-size test: original=%dB, mirrored=%dB",
                truncate_size, len(packets[0]))


@pytest.mark.parametrize('erspan_session', [{}], indirect=True)
def test_erspan_no_truncation_without_config(ptfadapter, erspan_session):
    '''
    Verify full-size mirroring when truncate_size is not configured.

    Steps:
        1. Create ERSPAN session without truncate_size
        2. Send a 1500B packet from source port
        3. Capture ERSPAN GRE packets on egress port
        4. Verify mirrored packet carries the full 1500B payload

    Pass Criteria: ERSPAN packet length >= 1500B (no truncation applied).
    '''
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=1500, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=5)
    pytest_assert(len(packets) > 0, "No ERSPAN packets received on GRE egress port")

    for pkt_bytes in packets:
        pytest_assert(
            len(pkt_bytes) >= 1500,
            "Without truncation, ERSPAN packet (len={}) should carry full payload".format(
                len(pkt_bytes))
        )


# ---------------------------------------------------------------------------
# Group 4: Sampling Data-Plane Tests
# ---------------------------------------------------------------------------

@pytest.mark.flaky(reruns=3)
@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256},
                          {'sample_rate': 512},
                          {'sample_rate': 1024}],
                         indirect=True)
def test_erspan_sampling_dataplane(ptfadapter, skip_if_sampling_unsupported, erspan_session):
    '''
    Verify sampled mirroring rate matches expected 1:N ratio.
    Uses small rates (256/512/1024) for statistical verification.
    Follows the sFlow test pattern: send NUM_SAMPLES x rate packets,
    expect ~NUM_SAMPLES mirrored with +-40% tolerance.

    Steps:
        1. Create ERSPAN session with sample_rate
        2. Send NUM_SAMPLES x sample_rate packets from source port
        3. Collect ERSPAN GRE packets on egress port
        4. Verify mirrored count is within [60, 140] (100 +- 40%)

    Pass Criteria: Mirrored packet count within statistical tolerance.
    '''
    sample_rate = erspan_session['sample_rate']
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']
    total_packets = NUM_SAMPLES * sample_rate

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=100, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt, count=total_packets)
    logger.info("Sent %d packets from port %d", total_packets, src_port)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=20)
    mirrored_count = len(packets)

    logger.info(
        "Sampling test: rate=1:%d, sent=%d, mirrored=%d, expected=[%d, %d]",
        sample_rate, total_packets, mirrored_count,
        MIN_EXPECTED_SAMPLES, MAX_EXPECTED_SAMPLES
    )
    pytest_assert(
        MIN_EXPECTED_SAMPLES <= mirrored_count <= MAX_EXPECTED_SAMPLES,
        "Mirrored count {} outside expected range [{}, {}] for rate 1:{}".format(
            mirrored_count, MIN_EXPECTED_SAMPLES, MAX_EXPECTED_SAMPLES, sample_rate)
    )


def test_erspan_sampling_config_high_rate(
        duthosts,
        rand_one_dut_hostname,
        skip_if_sampling_unsupported):
    '''
    Verify production sample_rate (1:50000) is accepted and stored in CONFIG_DB.
    Config-only test ΓÇö no data-plane verification (would need millions of packets).

    Steps:
        1. Create ERSPAN session with --sample_rate 50000
        2. Verify CONFIG_DB has correct value
        3. Remove session

    Pass Criteria: CONFIG_DB sample_rate field equals 50000.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = "test_high_rate"
    try:
        duthost.command(
            'config mirror_session erspan add {} {} {} {} {} {} {} --sample_rate {}'.format(
                session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP,
                ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE,
                DEFAULT_SAMPLE_RATE
            )
        )
        sr = duthost.shell(
            'redis-cli -n 4 hget "MIRROR_SESSION|{}" "sample_rate"'.format(session_name)
        )['stdout'].strip()
        pytest_assert(sr == str(DEFAULT_SAMPLE_RATE),
                      "CONFIG_DB sample_rate should be {}, got {}".format(DEFAULT_SAMPLE_RATE, sr))
    finally:
        duthost.command('config mirror_session remove {}'.format(session_name),
                        module_ignore_errors=True)


@pytest.mark.parametrize('erspan_session', [{}], indirect=True)
def test_erspan_no_sampling_without_config(ptfadapter, erspan_session):
    '''
    Verify backward compatibility: session without sample_rate mirrors all packets (1:1).

    Steps:
        1. Create ERSPAN session without --sample_rate
        2. Send 100 packets from source port
        3. Collect ERSPAN GRE packets on egress port
        4. Verify at least 90% of packets are mirrored

    Pass Criteria: Mirrored count >= 90 (full mirror, no sampling).
    '''
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']
    num_packets = 100

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=100, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt, count=num_packets)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=10)
    mirrored_count = len(packets)
    min_expected = int(0.9 * num_packets)
    pytest_assert(
        mirrored_count >= min_expected,
        "Without sampling, expected >= {} mirrored packets, got {}".format(
            min_expected, mirrored_count)
    )


# ---------------------------------------------------------------------------
# Group 5: Combined Sampling + Truncation
# ---------------------------------------------------------------------------

@pytest.mark.flaky(reruns=3)
@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'truncate_size': 128}],
                         indirect=True)
def test_erspan_sampling_with_truncation(
        ptfadapter,
        erspan_session,
        skip_if_sampling_unsupported,
        skip_if_truncation_unsupported):
    '''
    Verify sampling and truncation work together.

    Steps:
        1. Create ERSPAN session with sample_rate=256 and truncate_size=128
        2. Send 25600 large (1500B) packets from source port
        3. Collect ERSPAN GRE packets on egress port
        4. Verify mirrored count is within sampling tolerance [60, 140]
        5. Verify each mirrored packet is truncated (len < 1500B)

    Pass Criteria: Correct sampling ratio AND each mirrored packet is truncated.
    '''
    sample_rate = erspan_session['sample_rate']
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']
    total_packets = NUM_SAMPLES * sample_rate

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=1500, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt, count=total_packets)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=20)
    mirrored_count = len(packets)

    logger.info("Combined test: rate=1:%d, sent=%d, mirrored=%d",
                sample_rate, total_packets, mirrored_count)

    # Verify sampling rate
    pytest_assert(
        MIN_EXPECTED_SAMPLES <= mirrored_count <= MAX_EXPECTED_SAMPLES,
        "Mirrored count {} outside expected range [{}, {}]".format(
            mirrored_count, MIN_EXPECTED_SAMPLES, MAX_EXPECTED_SAMPLES)
    )

    # Verify truncation on each packet
    for pkt_bytes in packets:
        pytest_assert(
            len(pkt_bytes) < 1500,
            "Mirrored+truncated packet (len={}) should be < 1500B".format(len(pkt_bytes))
        )


# ---------------------------------------------------------------------------
# Group 6: Session Lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256}],
                         indirect=True)
def test_erspan_session_remove_stops_mirroring(
        duthosts,
        rand_one_dut_hostname,
        ptfadapter,
        erspan_session,
        skip_if_sampling_unsupported):
    '''
    Verify removing a mirror session stops all mirrored traffic.

    Steps:
        1. Create ERSPAN session with sample_rate=256
        2. Remove the session via CLI
        3. Send 1000 packets from source port
        4. Verify no ERSPAN packets appear on egress port
        5. Re-create session for fixture teardown

    Pass Criteria: Zero ERSPAN packets received after session removal.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    router_mac = erspan_session['router_mac']

    duthost.command('config mirror_session remove {}'.format(erspan_session['session_name']))

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=100, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )
    expected = build_expected_erspan_packet(
        erspan_session['mirror_session_info'], router_mac, inner_pkt
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt, count=1000)

    packets = collect_erspan_packets(ptfadapter, gre_ports, expected, timeout=3)
    pytest_assert(
        len(packets) == 0,
        "Should not receive ERSPAN packets after session removal, got {}".format(len(packets))
    )

    # Re-create so fixture teardown succeeds
    duthost.command(
        'config mirror_session erspan add {} {} {} {} {} {} {} {} {} --sample_rate 256'.format(
            erspan_session['session_name'], ERSPAN_SRC_IP, ERSPAN_DST_IP,
            ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE,
            erspan_session['source_port'], erspan_session['direction']
        )
    )
