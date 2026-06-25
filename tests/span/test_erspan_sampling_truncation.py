'''
Test ERSPAN sampled port mirroring with truncation on SONiC.
'''

import pytest
import logging

import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert
from erspan_helpers import (
    NUM_SAMPLES,
    MIN_EXPECTED_SAMPLES,
    MAX_EXPECTED_SAMPLES,
    MIRROR_LEN_TOLERANCE,
    expected_mirror_len,
    collect_erspan_packets,
    create_erspan_session_config,
    assert_mirror_session_config_db_fields,
    mirror_session_config_db_exists,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
]

DEFAULT_TRUNCATE_SIZE = 128
DEFAULT_SAMPLE_RATE = 50000

# Number of probe packets for truncation checks
TRUNCATION_PROBE_COUNT = 100


def _assert_mirror_len(observed_len, original_len, truncate_size):
    '''
    Assert a captured ERSPAN frame length matches the expected encap + inner model
    within MIRROR_LEN_TOLERANCE.
    '''
    expected = expected_mirror_len(original_len, truncate_size)
    pytest_assert(
        abs(observed_len - expected) <= MIRROR_LEN_TOLERANCE,
        "Mirrored frame len={} not within {}B of expected {} "
        "(original={}, truncate_size={})".format(
            observed_len, MIRROR_LEN_TOLERANCE, expected, original_len, truncate_size)
    )


def _send_sampled_traffic_and_collect(ptfadapter, erspan_session, inject_index,
                                      pktlen=100, count=None, timeout=20):
    '''
    Send copies of a broadcast probe frame from PTF port `inject_index`
    into the DUT, then return the ERSPAN frames the DUT mirrors out,
    captured on the PTF port wired to the DUT's monitor port.
    '''
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, inject_index)
    total_packets = count if count is not None else NUM_SAMPLES * erspan_session['sample_rate']
    pkt = testutils.simple_tcp_packet(
        pktlen=pktlen, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, inject_index, pkt, count=total_packets)
    logger.info("Sent %d packets (pktlen=%d) from PTF port %d", total_packets, pktlen, inject_index)

    return collect_erspan_packets(
        ptfadapter, gre_ports, erspan_session['mirror_session_info'], timeout=timeout)


def _assert_sampled_count(mirrored_count, sample_rate, label=None):
    '''
    Assert mirrored_count is within [MIN_EXPECTED_SAMPLES, MAX_EXPECTED_SAMPLES]
    (NUM_SAMPLES +-5%).
    '''
    msg = "Mirrored count {} outside expected range [{}, {}] for rate 1:{}".format(
        mirrored_count, MIN_EXPECTED_SAMPLES, MAX_EXPECTED_SAMPLES, sample_rate)
    if label:
        msg = "{}: {}".format(label, msg)
    pytest_assert(MIN_EXPECTED_SAMPLES <= mirrored_count <= MAX_EXPECTED_SAMPLES, msg)


@pytest.mark.parametrize("capability_key", [
    "PORT_INGRESS_MIRROR_CAPABLE",
    "PORT_EGRESS_MIRROR_CAPABLE",
    "PORT_INGRESS_SAMPLE_MIRROR_CAPABLE",
    "PORT_EGRESS_SAMPLE_MIRROR_CAPABLE",
    "SAMPLEPACKET_TRUNCATION_CAPABLE",
])
def test_switch_capability_reported_boolean(erspan_capabilities, capability_key):
    '''
    Verify each STATE_DB SWITCH_CAPABILITY|switch mirror capability key exists
    and is 'true' or 'false'.
    '''
    value = erspan_capabilities.get(capability_key, "")
    pytest_assert(
        value.lower() in ('true', 'false'),
        "Capability key {} should exist and be 'true' or 'false', got '{}'".format(
            capability_key, value)
    )
    logger.info("Capability %s = %s", capability_key, value)


CREATE_CONFIG_DB_CASES = [
    pytest.param({"sample_rate": DEFAULT_SAMPLE_RATE}, False, id="sample_rate"),
    pytest.param({"truncate_size": DEFAULT_TRUNCATE_SIZE}, True, id="truncate_size"),
    pytest.param(
        {"sample_rate": DEFAULT_SAMPLE_RATE, "truncate_size": DEFAULT_TRUNCATE_SIZE},
        True,
        id="sample_rate_and_truncate_size",
    ),
]


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
@pytest.mark.parametrize("create_kwargs,requires_truncation", CREATE_CONFIG_DB_CASES)
def test_create_erspan_session_config_fields(
        request,
        duthosts,
        rand_one_dut_hostname,
        erspan_ports,
        mirror_session_cleanup,
        sampling_direction,
        create_kwargs,
        requires_truncation):
    '''
    Verify sampling/truncation flags and the direction are written to the CONFIG_DB
    MIRROR_SESSION entry.
    '''
    if requires_truncation:
        request.getfixturevalue("skip_if_truncation_unsupported")

    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_create_config")
    expected = dict(create_kwargs, direction=sampling_direction.upper())

    create_erspan_session_config(
        duthost, session_name,
        source_port=erspan_ports['source']['name'],
        direction=sampling_direction,
        **create_kwargs)

    assert_mirror_session_config_db_fields(duthost, session_name, expected)


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
def test_remove_erspan_session_with_sampling(
        duthosts,
        rand_one_dut_hostname,
        erspan_ports,
        mirror_session_cleanup,
        sampling_direction):
    '''
    Verify removing a sampled session deletes its CONFIG_DB MIRROR_SESSION key.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_remove_session")
    create_erspan_session_config(
        duthost, session_name, sample_rate=256,
        source_port=erspan_ports['source']['name'],
        direction=sampling_direction)
    duthost.command('config mirror_session remove {}'.format(session_name))
    pytest_assert(
        not mirror_session_config_db_exists(duthost, session_name),
        "MIRROR_SESSION|{} should not exist after removal".format(session_name)
    )


@pytest.mark.parametrize("invalid_rate", [1])
def test_invalid_sample_rate_rejected(duthosts, rand_one_dut_hostname, mirror_session_cleanup, invalid_rate):
    '''
    Verify the CLI rejects an out-of-range sample_rate (non-zero exit code).

    Steps: attempt to create a session with an invalid sample_rate; assert rc != 0.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_invalid_sr")
    result = create_erspan_session_config(
        duthost, session_name, sample_rate=invalid_rate, module_ignore_errors=True)
    pytest_assert(
        result['rc'] != 0,
        "CLI should reject invalid sample_rate={} but command succeeded".format(invalid_rate)
    )


@pytest.mark.parametrize("invalid_size", [32, 63, 9217])
def test_invalid_truncate_size_rejected(duthosts, rand_one_dut_hostname, mirror_session_cleanup, invalid_size):
    '''
    Verify the CLI rejects an out-of-range truncate_size (non-zero exit code).

    Steps: attempt to create a session with an invalid truncate_size; assert rc != 0.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_invalid_ts")
    result = create_erspan_session_config(
        duthost, session_name, truncate_size=invalid_size, module_ignore_errors=True)
    pytest_assert(
        result['rc'] != 0,
        "CLI should reject invalid truncate_size={} but command succeeded".format(invalid_size)
    )


def test_sample_rate_zero_disables_sampling(duthosts, rand_one_dut_hostname, mirror_session_cleanup):
    """
    Verify sample_rate=0 is accepted and semantically equivalent to omitting the flag:
    the field MUST NOT be written to CONFIG_DB. orchagent treats absence as "no sampling".
    """
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_sr_zero")
    result = create_erspan_session_config(
        duthost, session_name, sample_rate=0, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "CLI should accept sample_rate=0 (disabled), got rc={} stderr={}".format(
            result["rc"], result.get("stderr", "")
        )
    )
    assert_mirror_session_config_db_fields(duthost, session_name, {"sample_rate": ""})


def test_truncate_size_zero_disables_truncation(duthosts, rand_one_dut_hostname, mirror_session_cleanup):
    """
    Verify truncate_size=0 is accepted and semantically equivalent to omitting the flag:
    the field MUST NOT be written to CONFIG_DB, and orchagent treats absence as "no
    truncation".
    """
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_ts_zero")
    result = create_erspan_session_config(
        duthost, session_name, truncate_size=0, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "CLI should accept truncate_size=0 (disabled), got rc={} stderr={}".format(
            result["rc"], result.get("stderr", "")
        )
    )
    assert_mirror_session_config_db_fields(duthost, session_name, {"truncate_size": ""})


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
def test_show_mirror_session_displays_new_columns(
        duthosts,
        rand_one_dut_hostname,
        erspan_ports,
        mirror_session_cleanup,
        skip_if_truncation_unsupported,
        sampling_direction):
    '''
    Verify 'show mirror_session' lists sample_rate and truncate_size in the
    session's own row.

    Steps: create a session with sample_rate=512, truncate_size=128 and the parametrized
    direction; run 'show mirror_session'; locate the session row; assert 512 and 128
    are in its fields.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_show_cols")
    create_erspan_session_config(
        duthost, session_name, sample_rate=512, truncate_size=128,
        source_port=erspan_ports['source']['name'],
        direction=sampling_direction)
    output = duthost.shell("show mirror_session")['stdout']
    rows = [ln for ln in output.splitlines()
            if ln.split() and ln.split()[0] == session_name]
    pytest_assert(
        len(rows) == 1,
        "Expected exactly one '{}' row in show mirror_session, got:\n{}".format(
            session_name, output)
    )
    fields = rows[0].split()
    pytest_assert(
        '512' in fields,
        "Session row should list sample_rate 512, row: {!r}".format(rows[0])
    )
    pytest_assert(
        '128' in fields,
        "Session row should list truncate_size 128, row: {!r}".format(rows[0])
    )


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
def test_erspan_sampling_config_high_rate(
        duthosts,
        rand_one_dut_hostname,
        erspan_ports,
        mirror_session_cleanup,
        sampling_direction):
    '''
    Verify a sample_rate (1:50000) is accepted and stored in CONFIG_DB.

    Steps: create a session with --sample_rate 50000 and the parametrized direction;
    assert CONFIG_DB sample_rate == 50000.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_high_rate")
    create_erspan_session_config(
        duthost, session_name, sample_rate=DEFAULT_SAMPLE_RATE,
        source_port=erspan_ports['source']['name'],
        direction=sampling_direction)
    assert_mirror_session_config_db_fields(
        duthost, session_name, {"sample_rate": DEFAULT_SAMPLE_RATE})


@pytest.mark.parametrize(
    "erspan_session, pktlen",
    [
        ({'truncate_size': 128}, 1500),
        ({'truncate_size': 256}, 1500),
        ({'truncate_size': 128}, 64),
        ({'truncate_size': 256}, 64),
        ({'truncate_size': 128}, 128),
        ({'truncate_size': 256}, 256),
    ],
    indirect=['erspan_session'],
)
def test_erspan_truncation_packet_size(
        skip_if_ingress_sampling_unsupported,
        skip_if_truncation_unsupported,
        ptfadapter,
        erspan_session,
        pktlen):
    '''
    Verify ERSPAN truncation across packet sizes. truncate_size with no sample_rate
    implies 1:1 sampling, so every probe is mirrored. Each mirrored frame length must
    be within MIRROR_LEN_TOLERANCE of ENCAP_OVERHEAD + min(pktlen, truncate_size),
    covering pktlen >, <, and == truncate_size.

    Steps: configure truncate_size only; send TRUNCATION_PROBE_COUNT pktlen-byte frames
    from the source port; assert every mirrored frame length matches the model.
    '''
    truncate_size = erspan_session['truncate_size']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'],
        pktlen=pktlen, count=TRUNCATION_PROBE_COUNT, timeout=5)
    pytest_assert(
        len(packets) == TRUNCATION_PROBE_COUNT,
        "Expected {} mirrored frames (truncate_size implies 1:1 sampling), got {}".format(
            TRUNCATION_PROBE_COUNT, len(packets)))

    for pkt_bytes in packets:
        _assert_mirror_len(len(pkt_bytes), pktlen, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256},
                          {'sample_rate': 512},
                          {'sample_rate': 1024}],
                         indirect=True)
def test_erspan_sampling_rx_direction(skip_if_ingress_sampling_unsupported, ptfadapter, erspan_session):
    '''
    Verify RX (ingress) sampling yields ~1 in N frames: mirrored count within
    [950, 1050] (NUM_SAMPLES +-5%).

    Steps: configure sample_rate=N; send NUM_SAMPLES x N frames from the source port;
    assert the mirrored count is within [950, 1050].
    '''
    sample_rate = erspan_session['sample_rate']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'])
    mirrored_count = len(packets)
    logger.info("RX sampling test: rate=1:%d, mirrored=%d, expected=[%d, %d]",
                sample_rate, mirrored_count, MIN_EXPECTED_SAMPLES, MAX_EXPECTED_SAMPLES)
    _assert_sampled_count(mirrored_count, sample_rate)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'truncate_size': 128}],
                         indirect=True)
def test_erspan_sampling_rx_with_truncation(
        skip_if_ingress_sampling_unsupported,
        skip_if_truncation_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify RX sampling and truncation together: mirrored count within [950, 1050]
    AND each mirrored frame truncated to ~ENCAP_OVERHEAD + truncate_size.

    Steps: configure sample_rate=256 + truncate_size=128; send NUM_SAMPLES x 256
    1500B frames from the source port; assert count and per-frame truncated length.
    '''
    sample_rate = erspan_session['sample_rate']
    truncate_size = erspan_session['truncate_size']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'], pktlen=1500)
    mirrored_count = len(packets)
    logger.info("RX sampling+truncation: rate=1:%d, mirrored=%d", sample_rate, mirrored_count)

    # Verify sampling rate
    _assert_sampled_count(mirrored_count, sample_rate)

    # Verify each mirrored frame is truncated to the configured size
    for pkt_bytes in packets:
        _assert_mirror_len(len(pkt_bytes), 1500, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'direction': 'tx'},
                          {'sample_rate': 512, 'direction': 'tx'},
                          {'sample_rate': 1024, 'direction': 'tx'}],
                         indirect=True)
def test_erspan_sampling_tx_direction(
        skip_if_egress_sampling_unsupported,
        skip_if_no_tx_ingress,
        ptfadapter,
        erspan_session):
    '''
    Verify TX (egress) sampling emits ERSPAN at the configured 1:N ratio (mirrored
    count within [950, 1050]).

    direction=tx binds the egress mirror to the source port, so only traffic *leaving*
    it is mirrored. We inject broadcast on a peer VLAN member; the DUT floods it out the
    source port (egress), triggering the mirror (same pattern as span test_mirroring_tx).

    Steps: configure sample_rate=N, direction=tx; inject NUM_SAMPLES x N broadcast frames
    on the peer (tx_ingress) port; assert the mirrored count is within [950, 1050].
    '''
    sample_rate = erspan_session['sample_rate']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['tx_ingress_index'])
    mirrored_count = len(packets)
    logger.info("TX sampling test: rate=1:%d, mirrored=%d, expected=[%d, %d]",
                sample_rate, mirrored_count, MIN_EXPECTED_SAMPLES, MAX_EXPECTED_SAMPLES)
    _assert_sampled_count(mirrored_count, sample_rate)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'truncate_size': 128, 'direction': 'tx'}],
                         indirect=True)
def test_erspan_sampling_tx_with_truncation(
        skip_if_egress_sampling_unsupported,
        skip_if_truncation_unsupported,
        skip_if_no_tx_ingress,
        ptfadapter,
        erspan_session):
    '''
    Verify TX (egress) sampling and truncation together: same flooding setup as
    test_erspan_sampling_tx_direction but with truncate_size and 1500B frames.
    Mirrored count within [950, 1050] AND each frame truncated to
    ~ENCAP_OVERHEAD + truncate_size.

    Steps: configure sample_rate=256, truncate_size=128, direction=tx; inject
    NUM_SAMPLES x 256 1500B broadcast frames on the peer port; assert count and length.
    '''
    sample_rate = erspan_session['sample_rate']
    truncate_size = erspan_session['truncate_size']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['tx_ingress_index'], pktlen=1500)
    mirrored_count = len(packets)
    logger.info("TX sampling+truncation: rate=1:%d, truncate=%d, mirrored=%d",
                sample_rate, truncate_size, mirrored_count)

    _assert_sampled_count(mirrored_count, sample_rate)

    for pkt_bytes in packets:
        _assert_mirror_len(len(pkt_bytes), 1500, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'direction': 'both'},
                          {'sample_rate': 512, 'direction': 'both'},
                          {'sample_rate': 1024, 'direction': 'both'}],
                         indirect=True)
def test_erspan_sampling_both_direction(
        skip_if_ingress_sampling_unsupported,
        skip_if_egress_sampling_unsupported,
        skip_if_no_tx_ingress,
        ptfadapter,
        erspan_session):
    '''
    Verify direction=both mirrors both ingress- and egress-triggered traffic at the
    configured 1:N ratio on each leg, proving both bindings are active.

    RX leg: inject on the source port       -> ingress mirror.
    TX leg: inject broadcast on a peer port -> floods out the source port -> egress mirror.
    Pass: each leg's mirrored count within [950, 1050] (NUM_SAMPLES +-5%).

    Steps: configure sample_rate=N, direction=both; run the RX leg then the TX leg;
    assert each leg's mirrored count is within [950, 1050].
    '''
    sample_rate = erspan_session['sample_rate']

    rx_packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'])
    logger.info("BOTH RX leg: rate=1:%d, mirrored=%d", sample_rate, len(rx_packets))
    _assert_sampled_count(len(rx_packets), sample_rate, label="BOTH RX leg")

    tx_packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['tx_ingress_index'])
    logger.info("BOTH TX leg: rate=1:%d, mirrored=%d", sample_rate, len(tx_packets))
    _assert_sampled_count(len(tx_packets), sample_rate, label="BOTH TX leg")


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256, 'truncate_size': 128, 'direction': 'both'}],
                         indirect=True)
def test_erspan_sampling_both_with_truncation(
        skip_if_ingress_sampling_unsupported,
        skip_if_egress_sampling_unsupported,
        skip_if_truncation_unsupported,
        skip_if_no_tx_ingress,
        ptfadapter,
        erspan_session):
    '''
    Verify direction=both sampling and truncation on both legs: same two-leg setup as
    test_erspan_sampling_both_direction but with truncate_size and 1500B frames.
    Pass: each leg's count within [950, 1050] AND every frame truncated to
    ~ENCAP_OVERHEAD + truncate_size.

    Steps: configure sample_rate=256, truncate_size=128, direction=both; run RX and TX
    legs with 1500B frames; verify each leg's count and per-frame truncated length.
    '''
    sample_rate = erspan_session['sample_rate']
    truncate_size = erspan_session['truncate_size']

    rx_packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'], pktlen=1500)
    logger.info("BOTH+trunc RX leg: rate=1:%d, truncate=%d, mirrored=%d",
                sample_rate, truncate_size, len(rx_packets))
    _assert_sampled_count(len(rx_packets), sample_rate, label="BOTH RX leg")
    for pkt_bytes in rx_packets:
        _assert_mirror_len(len(pkt_bytes), 1500, truncate_size)

    tx_packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['tx_ingress_index'], pktlen=1500)
    logger.info("BOTH+trunc TX leg: rate=1:%d, truncate=%d, mirrored=%d",
                sample_rate, truncate_size, len(tx_packets))
    _assert_sampled_count(len(tx_packets), sample_rate, label="BOTH TX leg")
    for pkt_bytes in tx_packets:
        _assert_mirror_len(len(pkt_bytes), 1500, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256}],
                         indirect=True)
def test_erspan_session_remove_stops_mirroring(
        duthosts,
        rand_one_dut_hostname,
        skip_if_ingress_sampling_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify removing the session stops mirroring: after removal, 1000 packets on the
    source port produce zero ERSPAN frames on the collector.

    Steps: create a sampled session; remove it; send 1000 frames from the source port;
    validate that zero ERSPAN frames are collected.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    src_port = erspan_session['source_index']
    gre_ports = [erspan_session['gre_egress_index']]
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)

    duthost.command('config mirror_session remove {}'.format(erspan_session['session_name']))

    inner_pkt = testutils.simple_tcp_packet(
        pktlen=100, eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff'
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, inner_pkt, count=1000)

    packets = collect_erspan_packets(ptfadapter, gre_ports, erspan_session['mirror_session_info'], timeout=3)
    pytest_assert(
        len(packets) == 0,
        "Should not receive ERSPAN packets after session removal, got {}".format(len(packets))
    )
