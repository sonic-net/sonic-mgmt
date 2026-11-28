'''
Test HWSFLOW mirror sessions with session-level sampling and truncation.

An HWSFLOW mirror session sets the collector, the sample rate and the truncate size.
PORT_MIRROR_SAMPLE bindings attach source ports to it and set neither. The tests
configure through the CLI, send tagged probes from the PTF and decode the sFlow datagrams
the collector path receives.
'''

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from erspan_helpers import (
    ERSPAN_SRC_IP,
    ERSPAN_DST_IP,
    assert_mirror_session_config_db_fields,
    remove_mirror_session,
    sample_bindings,
)
from sflow_helpers import (
    HWSFLOW_SESSION_NAME,
    HWSFLOW_NUM_SAMPLES,
    HWSFLOW_DEFAULT_UDP_PORT,
    SFLOWTOOL,
    SflowCapture,
    create_hwsflow_session,
    add_hwsflow_binding,
    wait_for_hwsflow_binding,
    asic_db_object_count,
    make_probe,
    send_probes,
    ptf_tx_packets,
    wait_ptf_sent,
    probe_samples,
    header_bytes,
    assert_sample_count,
    assert_datagram_fields,
    assert_sample_rate,
    assert_input_ports,
    assert_header_length,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_memory_utilization,
]

# Low rates keep the probe count small: the PTF sends about a thousand packets per second.
SAMPLE_RATE = 16
SECOND_SAMPLE_RATE = 32
TRUNCATE_SIZE = 128
PROBE_LEN = 300
CUSTOM_UDP_SRC_PORT = 6400
CUSTOM_UDP_DST_PORT = 6344

# Probe destinations that setup_erspan_route (conftest.py) installs: RX originals are
# discarded, TX probes are routed out of the source port.
RX_PROBE_IP = '198.18.254.1'
TX_PROBE_IP = '198.18.254.2'


def _capable(erspan_capabilities, key):
    return erspan_capabilities.get(key, 'false').lower() == 'true'


def _lag_capable(erspan_capabilities, direction):
    '''Return True when a PortChannel binding in `direction` is programmed on the LAG object.'''
    return _capable(erspan_capabilities, {'rx': 'LAG_INGRESS_SAMPLE_MIRROR_CAPABLE',
                                          'tx': 'LAG_EGRESS_SAMPLE_MIRROR_CAPABLE'}[direction])


@pytest.fixture(scope='module')
def skip_if_hwsflow_unsupported(erspan_capabilities):
    '''Skip when the switch cannot create an HWSFLOW session that samples and truncates.'''
    for key in ('MIRROR_SESSION_HWSFLOW_CAPABLE', 'MIRROR_SESSION_SAMPLE_RATE_CAPABLE',
                'MIRROR_SESSION_TRUNCATION_CAPABLE'):
        if not _capable(erspan_capabilities, key):
            pytest.skip('Skip: platform does not support HWSFLOW mirror sessions ({} != true)'.format(key))


@pytest.fixture(scope='module')
def skip_if_no_sflowtool(ptfhost):
    '''Skip dataplane tests when the PTF cannot decode sFlow datagrams.'''
    if ptfhost.shell('test -x {}'.format(SFLOWTOOL), module_ignore_errors=True)['rc'] != 0:
        pytest.skip('Skip: {} is not available on the PTF'.format(SFLOWTOOL))


@pytest.fixture
def hwsflow(request, duthosts, rand_one_dut_hostname, skip_if_vs_platform, skip_if_hwsflow_unsupported,
            skip_if_no_sflowtool, erspan_ports, mirror_session_cleanup):
    '''
    Provide the collector path, two source ports and a factory for HWSFLOW sessions.

    create(sample_rate, ...) adds a session to the collector path and waits until it is
    active. Tests bind sources with add_hwsflow_binding(). Teardown removes the bindings
    and the sessions.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    mirror_session_cleanup(HWSFLOW_SESSION_NAME)
    request.getfixturevalue('setup_erspan_route')

    baseline = {object_type: asic_db_object_count(duthost, object_type)
                for object_type in ('MIRROR_SESSION', 'SAMPLEPACKET')}

    def create(sample_rate, session_name=HWSFLOW_SESSION_NAME, **options):
        if session_name != HWSFLOW_SESSION_NAME:
            mirror_session_cleanup(session_name)
        create_hwsflow_session(duthost, session_name, sample_rate, **options)
        state_key = 'MIRROR_SESSION_TABLE|{}'.format(session_name)

        def _session_active():
            return duthost.shell("sonic-db-cli STATE_DB HGET '{}' status".format(state_key),
                                 module_ignore_errors=True)['stdout'].strip() == 'active'

        ready = wait_until(30, 2, 0, _session_active)
        state_dump = duthost.shell("sonic-db-cli STATE_DB HGETALL '{}'".format(state_key),
                                   module_ignore_errors=True)['stdout']
        pytest_assert(ready, "Mirror session {} not active; STATE_DB: {}".format(session_name, state_dump))
        return session_name

    yield {
        'create': create,
        'collector_indices': erspan_ports['gre_egress']['indices'],
        'source': erspan_ports['source'],
        'second': erspan_ports['tx_ingress'],
        'asic_db_baseline': baseline,
    }


def _send_and_capture(ptfhost, ptfadapter, hwsflow, sends, udp_src_port=HWSFLOW_DEFAULT_UDP_PORT,
                      udp_dst_port=HWSFLOW_DEFAULT_UDP_PORT):
    '''
    Send each (inject_index, probe, count) while capturing on the collector path.

    Returns (capture, {inject_index: probe bytes}).
    '''
    sent = {}
    with SflowCapture(ptfhost, hwsflow['collector_indices'], udp_src_port, udp_dst_port) as capture:
        for inject_index, probe, count in sends:
            tx_start = ptf_tx_packets(ptfhost, inject_index)
            sent[inject_index] = send_probes(ptfadapter, inject_index, probe, count, pktlen=PROBE_LEN)
            wait_ptf_sent(ptfhost, inject_index, tx_start, count)
    return capture, sent


@pytest.mark.parametrize('sampling_direction', ['rx', 'tx'], indirect=True)
def test_hwsflow_port_source(
        duthosts,
        rand_one_dut_hostname,
        erspan_capabilities,
        ptfhost,
        ptfadapter,
        sampling_direction,
        hwsflow):
    '''
    Verify one port bound to a session with truncation and its own UDP ports: the binding
    stores no policy, the datagrams are version 5 from the session src_ip on the configured
    UDP ports, every sample reports the session's rate, headers are cut to
    min(frame, truncate_size), and the sample count matches the rate.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    source = hwsflow['source']
    if sampling_direction == 'tx' and len(source['members']) != 1:
        pytest.skip('TX HWSFLOW dataplane tests require a single-member routed mirror source')
    session_name = hwsflow['create'](SAMPLE_RATE, truncate_size=TRUNCATE_SIZE,
                                     udp_src_port=CUSTOM_UDP_SRC_PORT, udp_dst_port=CUSTOM_UDP_DST_PORT)
    bound = add_hwsflow_binding(duthost, session_name, source, sampling_direction,
                                _lag_capable(erspan_capabilities, sampling_direction))

    assert_mirror_session_config_db_fields(duthost, session_name, {
        'type': 'HWSFLOW',
        'src_ip': ERSPAN_SRC_IP,
        'dst_ip': ERSPAN_DST_IP,
        'sample_rate': str(SAMPLE_RATE),
        'truncate_size': str(TRUNCATE_SIZE),
        'udp_src_port': str(CUSTOM_UDP_SRC_PORT),
        'udp_dst_port': str(CUSTOM_UDP_DST_PORT),
        'gre_type': None,
        'queue': None,
        'direction': None,
    })
    binding = sample_bindings(duthost)[(bound, sampling_direction)]
    pytest_assert('sample_rate' not in binding and 'truncate_size' not in binding,
                  "HWSFLOW binding stores a sampling policy: {}".format(binding))

    if sampling_direction == 'rx':
        inject_index = source['index']
        probe = make_probe(source['router_mac'], RX_PROBE_IP)
    else:
        inject_index = hwsflow['second']['index']
        probe = make_probe(hwsflow['second']['router_mac'], TX_PROBE_IP)
    count = HWSFLOW_NUM_SAMPLES * SAMPLE_RATE
    capture, sent = _send_and_capture(ptfhost, ptfadapter, hwsflow, [(inject_index, probe, count)],
                                      udp_src_port=CUSTOM_UDP_SRC_PORT, udp_dst_port=CUSTOM_UDP_DST_PORT)

    samples = probe_samples(capture.datagrams, probe)
    logger.info("%d probe samples (rate 1:%d, sent %d)", len(samples), SAMPLE_RATE, count)
    pytest_assert(samples, "No samples of the probe on UDP ports {} -> {}".format(
        CUSTOM_UDP_SRC_PORT, CUSTOM_UDP_DST_PORT))
    assert_datagram_fields(samples, ERSPAN_SRC_IP)
    assert_sample_rate(samples, SAMPLE_RATE)
    assert_header_length(samples, PROBE_LEN, TRUNCATE_SIZE)
    if sampling_direction == 'rx':
        # The input interface and the leading bytes identify the source only for ingress samples.
        assert_input_ports(duthost, {source['name']: samples})
        for sample in samples:
            pytest_assert(header_bytes(sample) == sent[inject_index][:TRUNCATE_SIZE],
                          "Sampled header differs from the probe's first {} bytes".format(TRUNCATE_SIZE))
    assert_sample_count(len(samples), HWSFLOW_NUM_SAMPLES, label=sampling_direction)


def test_hwsflow_two_sessions_different_rates(
        duthosts,
        rand_one_dut_hostname,
        skip_if_ingress_sampling_unsupported,
        erspan_capabilities,
        ptfhost,
        ptfadapter,
        hwsflow):
    '''
    Verify two sessions at different rates with one port each: each port's samples report
    the rate of its own session, and each count matches that rate.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    bindings = [(hwsflow['source'], SAMPLE_RATE, HWSFLOW_SESSION_NAME),
                (hwsflow['second'], SECOND_SAMPLE_RATE, HWSFLOW_SESSION_NAME + '_2')]
    probes = {}
    sends = []
    for port, rate, session_name in bindings:
        hwsflow['create'](rate, session_name=session_name)
        add_hwsflow_binding(duthost, session_name, port, 'rx', _lag_capable(erspan_capabilities, 'rx'))
        probes[port['name']] = make_probe(port['router_mac'], RX_PROBE_IP)
        sends.append((port['index'], probes[port['name']], HWSFLOW_NUM_SAMPLES * rate))
    capture, _ = _send_and_capture(ptfhost, ptfadapter, hwsflow, sends)

    samples = {port['name']: probe_samples(capture.datagrams, probes[port['name']]) for port, _, _ in bindings}
    for port, rate, _ in bindings:
        logger.info("%s: %d probe samples (rate 1:%d)", port['name'], len(samples[port['name']]), rate)
        pytest_assert(samples[port['name']], "No samples from {}".format(port['name']))
        assert_datagram_fields(samples[port['name']], ERSPAN_SRC_IP)
        assert_sample_rate(samples[port['name']], rate)
        assert_sample_count(len(samples[port['name']]), HWSFLOW_NUM_SAMPLES, label=port['name'])
    assert_input_ports(duthost, samples)


def test_hwsflow_portchannel_source(
        duthosts,
        rand_one_dut_hostname,
        skip_if_ingress_sampling_unsupported,
        erspan_capabilities,
        erspan_lag_source,
        ptfhost,
        ptfadapter,
        hwsflow):
    '''
    Verify a PortChannel binding: packets received on each member are sampled at the
    session's rate, and each member reports its own ifIndex as the input interface.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    lag = erspan_lag_source
    session_name = hwsflow['create'](SAMPLE_RATE)
    add_hwsflow_binding(duthost, session_name, lag, 'rx', _lag_capable(erspan_capabilities, 'rx'))

    probes = {}
    sends = []
    for member, index in zip(lag['members'], lag['indices']):
        probes[member] = make_probe(lag['router_mac'], RX_PROBE_IP)
        sends.append((index, probes[member], HWSFLOW_NUM_SAMPLES * SAMPLE_RATE))
    capture, _ = _send_and_capture(ptfhost, ptfadapter, hwsflow, sends)

    samples = {member: probe_samples(capture.datagrams, probes[member]) for member in lag['members']}
    for member in lag['members']:
        logger.info("%s member %s: %d probe samples", lag['l3_interface'], member, len(samples[member]))
        pytest_assert(samples[member], "No samples from {} member {}".format(lag['l3_interface'], member))
        assert_sample_rate(samples[member], SAMPLE_RATE)
        assert_sample_count(len(samples[member]), HWSFLOW_NUM_SAMPLES, label=member)
    assert_input_ports(duthost, samples)


def _assert_one_port_stopped(capture, probes, stopped, kept):
    stale = probe_samples(capture.datagrams, probes[stopped['name']])
    pytest_assert(not stale, "{} samples from {}, which is not sampled".format(len(stale), stopped['name']))
    samples = probe_samples(capture.datagrams, probes[kept['name']])
    assert_sample_rate(samples, SAMPLE_RATE)
    assert_sample_count(len(samples), HWSFLOW_NUM_SAMPLES, label=kept['name'])


def test_hwsflow_binding_admin_state(
        duthosts,
        rand_one_dut_hostname,
        skip_if_ingress_sampling_unsupported,
        erspan_capabilities,
        ptfhost,
        ptfadapter,
        hwsflow):
    '''
    Verify that a disabled binding stops its samples while the other binding of the session
    keeps sampling, and that the binding samples at the session's rate again when enabled.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    toggled, kept = hwsflow['source'], hwsflow['second']
    lag_capable = _lag_capable(erspan_capabilities, 'rx')
    session_name = hwsflow['create'](SAMPLE_RATE)
    probes = {}
    sends = []
    for port in (toggled, kept):
        add_hwsflow_binding(duthost, session_name, port, 'rx', lag_capable)
        probes[port['name']] = make_probe(port['router_mac'], RX_PROBE_IP)
        sends.append((port['index'], probes[port['name']], HWSFLOW_NUM_SAMPLES * SAMPLE_RATE))

    duthost.command('config mirror_session sample disable {} {} rx'.format(session_name, toggled['l3_interface']))
    wait_for_hwsflow_binding(duthost, toggled, 'rx', lag_capable, enabled=False)
    capture, _ = _send_and_capture(ptfhost, ptfadapter, hwsflow, sends)
    _assert_one_port_stopped(capture, probes, toggled, kept)

    duthost.command('config mirror_session sample enable {} {} rx'.format(session_name, toggled['l3_interface']))
    wait_for_hwsflow_binding(duthost, toggled, 'rx', lag_capable)
    capture, _ = _send_and_capture(ptfhost, ptfadapter, hwsflow, sends)
    for port in (toggled, kept):
        samples = probe_samples(capture.datagrams, probes[port['name']])
        assert_sample_rate(samples, SAMPLE_RATE)
        assert_sample_count(len(samples), HWSFLOW_NUM_SAMPLES, label=port['name'])


def test_hwsflow_binding_remove(
        duthosts,
        rand_one_dut_hostname,
        skip_if_ingress_sampling_unsupported,
        erspan_capabilities,
        ptfhost,
        ptfadapter,
        hwsflow):
    '''
    Verify that removing one binding stops its samples while the other binding of the
    session keeps sampling, and that removing everything returns ASIC_DB to its baseline.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    removed, kept = hwsflow['source'], hwsflow['second']
    session_name = hwsflow['create'](SAMPLE_RATE)
    probes = {}
    sends = []
    for port in (removed, kept):
        add_hwsflow_binding(duthost, session_name, port, 'rx', _lag_capable(erspan_capabilities, 'rx'))
        probes[port['name']] = make_probe(port['router_mac'], RX_PROBE_IP)
        sends.append((port['index'], probes[port['name']], HWSFLOW_NUM_SAMPLES * SAMPLE_RATE))

    duthost.command('config mirror_session sample remove {} {} rx'.format(session_name, removed['l3_interface']))
    wait_for_hwsflow_binding(duthost, removed, 'rx', _lag_capable(erspan_capabilities, 'rx'), enabled=False)
    capture, _ = _send_and_capture(ptfhost, ptfadapter, hwsflow, sends)
    _assert_one_port_stopped(capture, probes, removed, kept)

    remove_mirror_session(duthost, session_name)
    baseline = hwsflow['asic_db_baseline']

    def _at_baseline():
        return all(asic_db_object_count(duthost, object_type) == count for object_type, count in baseline.items())

    pytest_assert(wait_until(30, 2, 0, _at_baseline),
                  "ASIC_DB did not return to its baseline {} after removing the session".format(baseline))
