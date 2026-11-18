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
    config_db_key_exists,
    remove_mirror_session,
    sample_bindings,
    wait_for_sample_binding,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_memory_utilization,
]

DEFAULT_TRUNCATE_SIZE = 128
DEFAULT_SAMPLE_RATE = 50000
SAMPLING_TRUNCATION_PACKET_SIZE = 1500

# Batch sends and raise the ptf_nn_agent socket send timeout
SEND_BATCH_SIZE = 1000
SEND_SOCKET_TIMEOUT_MS = 30000
# DUT forwards TX probes once; the peer must not route them back.
PROBE_TTL = 2


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


def _relax_nn_send_timeout(ptfadapter, inject_index, timeout_ms=SEND_SOCKET_TIMEOUT_MS):
    '''
    Raise the nanomsg send timeout on the ptf dataplane inject socket so high-volume
    sends block on backpressure until the ptf_nn_agent drains its queue
    '''
    try:
        import nnpy
        inject_port = ptfadapter.dataplane.port_to_tuple(inject_index)
        sock = ptfadapter.dataplane.ports[inject_port].packet_inject.socket
        sock.setsockopt(nnpy.SOL_SOCKET, nnpy.SNDTIMEO, timeout_ms)
    except (ImportError, KeyError, AttributeError) as exc:
        logger.debug("Could not raise nn send timeout on port %s: %s", inject_index, exc)


def _send_sampled_traffic_and_collect(ptfadapter, erspan_session, inject_index,
                                      pktlen=100, count=None, timeout=20):
    '''
    Send probes and collect matching ERSPAN frames on the collector port.

    RX originals are discarded; TX originals leave the mirrored source port.
    '''
    gre_ports = erspan_session['gre_egress_indices']
    inject_port = ptfadapter.dataplane.port_to_tuple(inject_index)
    src_mac = ptfadapter.dataplane.get_mac(*inject_port)
    total_packets = count if count is not None else NUM_SAMPLES * erspan_session['sample_rate']
    probe = erspan_session['probes'][inject_index]
    pkt = testutils.simple_tcp_packet(
        pktlen=pktlen, eth_src=src_mac, eth_dst=probe['eth_dst'],
        ip_dst=probe['ip_dst'], ip_ttl=PROBE_TTL
    )

    ptfadapter.dataplane.flush()
    _relax_nn_send_timeout(ptfadapter, inject_index)
    remaining = total_packets
    while remaining > 0:
        batch = min(remaining, SEND_BATCH_SIZE)
        testutils.send(ptfadapter, inject_port, pkt, count=batch)
        remaining -= batch
    logger.info("Sent %d packets (pktlen=%d) from PTF port %d", total_packets, pktlen, inject_index)

    return collect_erspan_packets(
        ptfadapter, gre_ports, erspan_session['mirror_session_info'], timeout=timeout, expected_probe=pkt)


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
    pytest.param(
        {"sample_rate": DEFAULT_SAMPLE_RATE, "truncate_size": DEFAULT_TRUNCATE_SIZE},
        True,
        id="sample_rate_and_truncate_size",
    ),
]


def _expected_bindings(session, port, direction, sample_rate, truncate_size=None):
    fields = {'mirror_session': session, 'sample_rate': str(sample_rate), 'admin_state': 'up'}
    if truncate_size is not None:
        fields['truncate_size'] = str(truncate_size)
    directions = ('rx', 'tx') if direction == 'both' else (direction,)
    return {(port, d): fields for d in directions}


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
@pytest.mark.parametrize("create_kwargs,requires_truncation", CREATE_CONFIG_DB_CASES)
def test_create_erspan_session_config_fields(
        request,
        duthosts,
        rand_one_dut_hostname,
        erspan_config_source,
        mirror_session_cleanup,
        sampling_direction,
        create_kwargs,
        requires_truncation):
    '''
    Verify sampling/truncation is on the binding, not on the shared export.
    '''
    if requires_truncation:
        request.getfixturevalue("skip_if_truncation_unsupported")

    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_create_config")

    create_erspan_session_config(
        duthost, session_name,
        source_port=erspan_config_source,
        direction=sampling_direction,
        **create_kwargs)

    assert_mirror_session_config_db_fields(duthost, session_name, {
        'type': 'ERSPAN', 'src_port': None, 'direction': None, 'sample_rate': None, 'truncate_size': None})
    assert sample_bindings(duthost) == _expected_bindings(
        session_name, erspan_config_source, sampling_direction, **create_kwargs)


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
def test_remove_erspan_session_with_sampling(
        duthosts,
        rand_one_dut_hostname,
        erspan_config_source,
        mirror_session_cleanup,
        sampling_direction):
    '''
    Verify removing the binding leaves the export available for separate removal.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_remove_session")
    create_erspan_session_config(
        duthost, session_name, sample_rate=256,
        source_port=erspan_config_source,
        direction=sampling_direction)
    assert sample_bindings(duthost) == _expected_bindings(session_name, erspan_config_source, sampling_direction, 256)
    duthost.command('config mirror_session sample remove {} {} {}'.format(
        session_name, erspan_config_source, sampling_direction))
    assert not sample_bindings(duthost)
    assert config_db_key_exists(duthost, 'MIRROR_SESSION|' + session_name)
    duthost.command('config mirror_session remove {}'.format(session_name))
    pytest_assert(
        not config_db_key_exists(duthost, 'MIRROR_SESSION|' + session_name),
        "MIRROR_SESSION|{} should not exist after removal".format(session_name)
    )


@pytest.mark.parametrize("invalid_rate", [None, 0, 1], ids=['missing', 'zero', 'one'])
def test_invalid_sample_rate_rejected(duthosts, rand_one_dut_hostname, mirror_session_cleanup,
                                      erspan_config_source, invalid_rate):
    '''
    Truncation does not make the sampling rate optional; 0 and 1 are invalid, too.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_invalid_sr")
    result = create_erspan_session_config(
        duthost, session_name, erspan_config_source, 'rx', sample_rate=invalid_rate,
        truncate_size=DEFAULT_TRUNCATE_SIZE, module_ignore_errors=True)
    pytest_assert(
        result['rc'] != 0 and '--sample_rate' in result['stderr'],
        "Expected a sample_rate error for {}, got {}".format(invalid_rate, result['stderr'])
    )
    assert not sample_bindings(duthost)


@pytest.mark.parametrize("invalid_size", [0, 32, 63, 9217])
def test_invalid_truncate_size_rejected(duthosts, rand_one_dut_hostname, mirror_session_cleanup,
                                        erspan_config_source, invalid_size):
    '''
    Verify the CLI rejects an out-of-range truncate_size (non-zero exit code).

    Steps: attempt to add a binding with an invalid truncate_size; assert rc != 0.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_invalid_ts")
    result = create_erspan_session_config(
        duthost, session_name, erspan_config_source, 'rx', sample_rate=2,
        truncate_size=invalid_size, module_ignore_errors=True)
    pytest_assert(
        result['rc'] != 0 and '--truncate_size' in result['stderr'],
        "Expected a truncate_size error for {}, got {}".format(invalid_size, result['stderr'])
    )
    assert not sample_bindings(duthost)


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
def test_show_mirror_session_displays_new_columns(
        duthosts,
        rand_one_dut_hostname,
        erspan_config_source,
        mirror_session_cleanup,
        skip_if_truncation_unsupported,
        sampling_direction):
    '''
    Verify 'show mirror_session sample' lists the policy once per source and direction.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_show_cols")
    create_erspan_session_config(
        duthost, session_name, sample_rate=512, truncate_size=128,
        source_port=erspan_config_source,
        direction=sampling_direction)
    rows = duthost.show_and_parse('show mirror_session sample')
    actual = [(r['source port'], r['direction'], r['admin state'], r['sample rate'], r['truncate size'])
              for r in rows if r['mirror session'] == session_name]
    directions = ('rx', 'tx') if sampling_direction == 'both' else (sampling_direction,)
    assert sorted(actual) == [(erspan_config_source, direction, 'up', '512', '128') for direction in directions]


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
def test_erspan_sampling_config_high_rate(
        duthosts,
        rand_one_dut_hostname,
        erspan_config_source,
        mirror_session_cleanup,
        sampling_direction):
    '''
    Verify a sample_rate (1:50000) is accepted and stored in CONFIG_DB.

    Steps: add a binding with --sample_rate 50000 and the parametrized direction;
    assert CONFIG_DB sample_rate == 50000.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_name = mirror_session_cleanup("test_high_rate")
    create_erspan_session_config(
        duthost, session_name, sample_rate=DEFAULT_SAMPLE_RATE,
        source_port=erspan_config_source,
        direction=sampling_direction)
    assert sample_bindings(duthost) == _expected_bindings(
        session_name, erspan_config_source, sampling_direction, DEFAULT_SAMPLE_RATE)


@pytest.mark.parametrize(
    "erspan_session, pktlen",
    [
        ({'sample_rate': 2, 'truncate_size': 128}, 1500),
        ({'sample_rate': 2, 'truncate_size': 256}, 1500),
        ({'sample_rate': 2, 'truncate_size': 128}, 64),
        ({'sample_rate': 2, 'truncate_size': 256}, 64),
        ({'sample_rate': 2, 'truncate_size': 128}, 128),
        ({'sample_rate': 2, 'truncate_size': 256}, 256),
    ],
    ids=[
        'truncate128-pktlen1500',
        'truncate256-pktlen1500',
        'truncate128-pktlen64',
        'truncate256-pktlen64',
        'truncate128-pktlen128',
        'truncate256-pktlen256',
    ],
    indirect=['erspan_session'],
)
def test_erspan_truncation_packet_size(
        skip_if_vs_platform,
        skip_if_ingress_sampling_unsupported,
        skip_if_truncation_unsupported,
        ptfadapter,
        erspan_session,
        pktlen):
    '''
    Verify truncation with 1:2 sampling for frames below, at and above the limit.

    Check the sampled count and validate every mirrored frame's length
    against the encapsulation model and tolerance.
    '''
    truncate_size = erspan_session['truncate_size']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'],
        pktlen=pktlen)
    _assert_sampled_count(len(packets), erspan_session['sample_rate'])

    for pkt_bytes in packets:
        _assert_mirror_len(len(pkt_bytes), pktlen, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 100},
                          {'sample_rate': 256}],
                         ids=['rate100', 'rate256'],
                         indirect=True)
def test_erspan_sampling_rx_direction(
        skip_if_vs_platform,
        skip_if_ingress_sampling_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify RX (ingress) sampling yields ~1 in N frames: mirrored count within
    [9500, 10500] (NUM_SAMPLES +-5%).

    Steps: configure sample_rate=N; send NUM_SAMPLES x N frames from the source port;
    assert the mirrored count is within [9500, 10500].
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
                         ids=['rate256-truncate128'],
                         indirect=True)
def test_erspan_sampling_rx_with_truncation(
        skip_if_vs_platform,
        skip_if_ingress_sampling_unsupported,
        skip_if_truncation_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify RX sampling and truncation together: mirrored count within [9500, 10500]
    AND each mirrored frame truncated to ~ENCAP_OVERHEAD + truncate_size.

    Steps: configure sample_rate=256 + truncate_size=128; send NUM_SAMPLES x 256
    1500B frames from the source port; assert count and per-frame truncated length.
    '''
    sample_rate = erspan_session['sample_rate']
    truncate_size = erspan_session['truncate_size']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'], pktlen=SAMPLING_TRUNCATION_PACKET_SIZE)
    mirrored_count = len(packets)
    logger.info("RX sampling+truncation: rate=1:%d, mirrored=%d", sample_rate, mirrored_count)

    # Verify sampling rate
    _assert_sampled_count(mirrored_count, sample_rate)

    # Verify each mirrored frame is truncated to the configured size
    for pkt_bytes in packets:
        _assert_mirror_len(len(pkt_bytes), SAMPLING_TRUNCATION_PACKET_SIZE, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 100, 'direction': 'tx'},
                          {'sample_rate': 256, 'direction': 'tx'}],
                         ids=['rate100', 'rate256'],
                         indirect=True)
def test_erspan_sampling_tx_direction(
        skip_if_vs_platform,
        skip_if_egress_sampling_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify TX (egress) sampling emits ERSPAN at the configured 1:N ratio (mirrored
    count within [9500, 10500]).

    Inject on the peer; the probe route forwards frames out the mirrored source.

    Steps: configure sample_rate=N, direction=tx; inject NUM_SAMPLES x N unicast frames
    on the peer (tx_ingress) port; assert the mirrored count is within [9500, 10500].
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
                         ids=['rate256-truncate128'],
                         indirect=True)
def test_erspan_sampling_tx_with_truncation(
        skip_if_vs_platform,
        skip_if_egress_sampling_unsupported,
        skip_if_truncation_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify TX (egress) sampling with truncation: mirrored count within
    [9500, 10500] and each frame truncated to ~ENCAP_OVERHEAD + truncate_size.

    Steps: configure sample_rate=256, truncate_size=128, direction=tx; inject
    NUM_SAMPLES x 256 1500B unicast frames on the
    tx_ingress peer port so the DUT forwards them out the source port (egress);
    assert count and per-frame truncated length.
    '''
    sample_rate = erspan_session['sample_rate']
    truncate_size = erspan_session['truncate_size']
    packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['tx_ingress_index'], pktlen=SAMPLING_TRUNCATION_PACKET_SIZE)
    mirrored_count = len(packets)
    logger.info("TX sampling+truncation: rate=1:%d, truncate=%d, mirrored=%d",
                sample_rate, truncate_size, mirrored_count)

    _assert_sampled_count(mirrored_count, sample_rate)

    for pkt_bytes in packets:
        _assert_mirror_len(len(pkt_bytes), SAMPLING_TRUNCATION_PACKET_SIZE, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 100, 'direction': 'both'},
                          {'sample_rate': 256, 'direction': 'both'}],
                         ids=['rate100', 'rate256'],
                         indirect=True)
def test_erspan_sampling_both_direction(
        skip_if_vs_platform,
        skip_if_ingress_sampling_unsupported,
        skip_if_egress_sampling_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify direction=both mirrors both ingress- and egress-triggered traffic at the
    configured 1:N ratio on each leg, proving both bindings are active.

    RX leg: inject on the source port       -> ingress mirror.
    TX leg: inject unicast on the tx_ingress peer port
            -> DUT forwards out the source port -> egress mirror.
    Pass: each leg's mirrored count within [9500, 10500] (NUM_SAMPLES +-5%).

    Steps: configure sample_rate=N, direction=both; run the RX leg then the TX leg;
    assert each leg's mirrored count is within [9500, 10500].
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
                         ids=['rate256-truncate128'],
                         indirect=True)
def test_erspan_sampling_both_with_truncation(
        skip_if_vs_platform,
        skip_if_ingress_sampling_unsupported,
        skip_if_egress_sampling_unsupported,
        skip_if_truncation_unsupported,
        ptfadapter,
        erspan_session):
    '''
    Verify direction=both sampling and truncation on both legs: same two-leg setup as
    test_erspan_sampling_both_direction but with truncate_size and 1500B frames.
    Pass: each leg's count within [9500, 10500] AND every frame truncated to
    ~ENCAP_OVERHEAD + truncate_size.

    Steps: configure sample_rate=256, truncate_size=128, direction=both; run RX and TX
    legs with 1500B frames; verify each leg's count and per-frame truncated length.
    '''
    sample_rate = erspan_session['sample_rate']
    truncate_size = erspan_session['truncate_size']

    rx_packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['source_index'], pktlen=SAMPLING_TRUNCATION_PACKET_SIZE)
    logger.info("BOTH+trunc RX leg: rate=1:%d, truncate=%d, mirrored=%d",
                sample_rate, truncate_size, len(rx_packets))
    _assert_sampled_count(len(rx_packets), sample_rate, label="BOTH RX leg")
    for pkt_bytes in rx_packets:
        _assert_mirror_len(len(pkt_bytes), SAMPLING_TRUNCATION_PACKET_SIZE, truncate_size)

    tx_packets = _send_sampled_traffic_and_collect(
        ptfadapter, erspan_session, erspan_session['tx_ingress_index'], pktlen=SAMPLING_TRUNCATION_PACKET_SIZE)
    logger.info("BOTH+trunc TX leg: rate=1:%d, truncate=%d, mirrored=%d",
                sample_rate, truncate_size, len(tx_packets))
    _assert_sampled_count(len(tx_packets), sample_rate, label="BOTH TX leg")
    for pkt_bytes in tx_packets:
        _assert_mirror_len(len(pkt_bytes), SAMPLING_TRUNCATION_PACKET_SIZE, truncate_size)


@pytest.mark.parametrize('erspan_session',
                         [{'sample_rate': 256}],
                         ids=['rate256'],
                         indirect=True)
def test_erspan_session_remove_stops_mirroring(
        skip_if_vs_platform,
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
    gre_ports = erspan_session['gre_egress_indices']
    inject_port = ptfadapter.dataplane.port_to_tuple(src_port)
    src_mac = ptfadapter.dataplane.get_mac(*inject_port)

    remove_mirror_session(duthost, erspan_session['session_name'])
    wait_for_sample_binding(duthost, erspan_session['source_port'], 'rx', enabled=False)

    probe = erspan_session['probes'][src_port]
    inner_pkt = testutils.simple_tcp_packet(
        pktlen=100, eth_src=src_mac, eth_dst=probe['eth_dst'], ip_dst=probe['ip_dst'], ip_ttl=PROBE_TTL
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, inject_port, inner_pkt, count=1000)

    packets = collect_erspan_packets(ptfadapter, gre_ports, erspan_session['mirror_session_info'], timeout=3,
                                     expected_probe=inner_pkt)
    pytest_assert(
        len(packets) == 0,
        "Should not receive ERSPAN packets after session removal, got {}".format(len(packets))
    )
