'''
Helper functions for HWSFLOW mirror session tests.

An HWSFLOW mirror session exports the samples of its PORT_MIRROR_SAMPLE source bindings as
sFlow datagrams to dst_ip. The session sets the sample rate and the truncate size. The
tests capture the datagrams on the PTF ports the collector route points at and decode them
with sflowtool.
'''

import ast
import json
import logging
import random
import time

import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli, SonicDbCli
from tests.common.utilities import wait_until
from erspan_helpers import ERSPAN_SRC_IP, ERSPAN_DST_IP, wait_for_sample_binding

logger = logging.getLogger(__name__)

HWSFLOW_SESSION_NAME = "hwsflow_sample_trunc"
HWSFLOW_DSCP = "8"
HWSFLOW_TTL = "64"
HWSFLOW_DEFAULT_UDP_PORT = 6343

SFLOW_DRAIN_SECONDS = 5

HWSFLOW_NUM_SAMPLES = 1200
HWSFLOW_COUNT_TOLERANCE = 0.20

SFLOWTOOL = "/usr/local/bin/sflowtool"

# Batch sends and raise the ptf_nn_agent socket send timeout
SEND_BATCH_SIZE = 1000
SEND_SOCKET_TIMEOUT_MS = 30000
# The DUT forwards TX probes once; the peer must not route them back.
PROBE_TTL = 2


def create_hwsflow_session(duthost, session_name, sample_rate, truncate_size=None,
                           udp_src_port=None, udp_dst_port=None):
    '''Create an HWSFLOW session with 'config mirror_session hwsflow add'.'''
    cmd = 'config mirror_session hwsflow add {} {} {} {} {} --sample_rate {}'.format(
        session_name, ERSPAN_SRC_IP, ERSPAN_DST_IP, HWSFLOW_DSCP, HWSFLOW_TTL, sample_rate)
    for option, value in (('truncate_size', truncate_size), ('udp_src_port', udp_src_port),
                          ('udp_dst_port', udp_dst_port)):
        if value is not None:
            cmd += ' --{} {}'.format(option, value)
    return duthost.command(cmd)


def add_hwsflow_binding(duthost, session_name, port, direction, lag_capable):
    '''
    Bind the routed interface of `port` to the session and wait until it is programmed.

    The binding sets no rate or truncate size. A port that is a PortChannel member is sampled
    through its PortChannel. Returns the bound interface name.
    '''
    interface = port['l3_interface']
    duthost.command('config mirror_session sample add {} {} {}'.format(session_name, interface, direction))
    wait_for_hwsflow_binding(duthost, port, direction, lag_capable)
    return interface


def wait_for_hwsflow_binding(duthost, port, direction, lag_capable, enabled=True):
    if port['l3_interface'].startswith('PortChannel'):
        wait_for_lag_sample_binding(duthost, port['l3_interface'], port['members'], direction, lag_capable, enabled)
    else:
        wait_for_sample_binding(duthost, port['l3_interface'], direction, enabled)


def wait_for_lag_sample_binding(duthost, portchannel, members, direction, lag_capable, enabled=True):
    '''
    Wait for a PortChannel binding to be programmed, or removed when `enabled` is False.

    When the switch reports the LAG sampling capability for this direction the binding is
    on the LAG object; otherwise it is on each member port.
    '''
    if not lag_capable:
        for member in members:
            wait_for_sample_binding(duthost, member, direction, enabled)
        return
    asic = AsicDbCli(duthost)
    oid = SonicDbCli(duthost, 'COUNTERS_DB').hget_key_value('COUNTERS_LAG_NAME_MAP', portchannel)
    stage = {'rx': 'INGRESS', 'tx': 'EGRESS'}[direction]

    def ready():
        fields = asic.hget_all('ASIC_STATE:SAI_OBJECT_TYPE_LAG:{}'.format(oid))
        sample = fields.get('SAI_LAG_ATTR_{}_SAMPLEPACKET_ENABLE'.format(stage), 'oid:0x0')
        mirror = fields.get('SAI_LAG_ATTR_{}_SAMPLE_MIRROR_SESSION_LIST'.format(stage), '0:null')
        return (sample != 'oid:0x0' and mirror.startswith('1:oid:')) == enabled

    pytest_assert(wait_until(30, 1, 0, ready), 'Sample binding {} {} did not converge on the LAG object '
                  '(enabled={})'.format(portchannel, direction, enabled))


def asic_db_object_count(duthost, object_type):
    '''Return the number of ASIC_DB objects of a SAI object type, for example MIRROR_SESSION.'''
    keys = AsicDbCli(duthost).get_keys('ASIC_STATE:SAI_OBJECT_TYPE_{}:*'.format(object_type),
                                       raise_error_when_not_found=False)
    return len([key for key in keys if key])


def make_probe(eth_dst, ip_dst):
    '''
    Return a probe with a random tag: ip_src and tcp_sport identify this test's samples
    in a capture that also holds background traffic and other bindings' samples.
    '''
    return {
        'eth_dst': eth_dst,
        'ip_src': "10.123.{}.{}".format(random.randint(0, 255), random.randint(1, 254)),
        'ip_dst': ip_dst,
        'tcp_sport': random.randint(10000, 60000),
    }


def _relax_nn_send_timeout(ptfadapter, inject_port, timeout_ms=SEND_SOCKET_TIMEOUT_MS):
    '''
    Raise the nanomsg send timeout on the ptf dataplane inject socket so high-volume
    sends block on backpressure until the ptf_nn_agent drains its queue
    '''
    try:
        import nnpy
        sock = ptfadapter.dataplane.ports[inject_port].packet_inject.socket
        sock.setsockopt(nnpy.SOL_SOCKET, nnpy.SNDTIMEO, timeout_ms)
    except (ImportError, KeyError, AttributeError) as exc:
        logger.debug("Could not raise nn send timeout on port %s: %s", inject_port, exc)


def send_probes(ptfadapter, inject_index, probe, count, pktlen=100):
    '''
    Send `count` copies of a TCP probe from PTF port `inject_index`.

    Returns the probe bytes, so callers can compare sampled headers with them.
    '''
    inject_port = ptfadapter.dataplane.port_to_tuple(inject_index)
    pkt = testutils.simple_tcp_packet(
        pktlen=pktlen,
        eth_src=ptfadapter.dataplane.get_mac(*inject_port),
        eth_dst=probe['eth_dst'],
        ip_src=probe['ip_src'],
        ip_dst=probe['ip_dst'],
        ip_ttl=PROBE_TTL,
        tcp_sport=probe['tcp_sport'])
    ptfadapter.dataplane.flush()
    _relax_nn_send_timeout(ptfadapter, inject_port)
    remaining = count
    while remaining > 0:
        batch = min(remaining, SEND_BATCH_SIZE)
        testutils.send(ptfadapter, inject_port, pkt, count=batch)
        remaining -= batch
    logger.info("Sent %d probes (pktlen=%d, src=%s, sport=%d) from PTF port %d",
                count, pktlen, probe['ip_src'], probe['tcp_sport'], inject_index)
    return bytes(pkt)


def ptf_tx_packets(ptfhost, ptf_index):
    '''Return the TX packet counter of PTF port `ptf_index`.'''
    return int(ptfhost.shell("cat /sys/class/net/eth{}/statistics/tx_packets".format(ptf_index))['stdout'])


def wait_ptf_sent(ptfhost, ptf_index, tx_start, count):
    '''
    Wait until PTF port `ptf_index` has sent `count` packets since its TX counter read `tx_start`.

    ptfadapter returns once packets are queued to ptf_nn_agent, which drains at a few hundred
    pps, so a capture stopped right after the send misses most probes.
    '''
    timeout = 60 + count // 100
    pytest_assert(wait_until(timeout, 2, 0, lambda: ptf_tx_packets(ptfhost, ptf_index) - tx_start >= count),
                  "PTF port {} did not send {} probes within {}s".format(ptf_index, count, timeout))


def _parse_sflowtool_line(line):
    # sflowtool -j emits one JSON object per datagram. Older builds emit Python-style
    # literals, which is why tests/sflow parses with ast.literal_eval.
    try:
        return json.loads(line)
    except ValueError:
        return ast.literal_eval(line)


class SflowCapture(object):
    '''
    Capture sFlow datagrams on PTF ports while the block runs, then decode them.

    with SflowCapture(ptfhost, ptf_indices, udp_src_port, udp_dst_port) as cap:
        send_probes(...)
    cap.datagrams     # decoded sflowtool JSON, one dict per datagram

    The capture filter is the session's UDP source and destination port, so a decoded
    datagram proves both. The collector route can point at a PortChannel, and the LAG hash picks the
    member, so each member port gets its own tcpdump. tcpdump -U writes each packet as it
    arrives; without it the last few datagrams sit in the buffer when tcpdump stops.
    '''

    def __init__(self, ptfhost, ptf_indices, udp_src_port=HWSFLOW_DEFAULT_UDP_PORT,
                 udp_dst_port=HWSFLOW_DEFAULT_UDP_PORT, drain=SFLOW_DRAIN_SECONDS):
        self.ptfhost = ptfhost
        self.ptf_indices = list(ptf_indices)
        self.udp_src_port = udp_src_port
        self.udp_dst_port = udp_dst_port
        self.drain = drain
        self.pcaps = {index: "/tmp/sflow_mirror_eth{}_{}.pcap".format(index, udp_dst_port)
                      for index in self.ptf_indices}
        self.datagrams = []
        self._pids = []

    def __enter__(self):
        for index, pcap in self.pcaps.items():
            self.ptfhost.shell("rm -f {}".format(pcap))
            self._pids.append(self.ptfhost.shell(
                "nohup tcpdump -U -i eth{} -w {} 'udp src port {} and udp dst port {}' "
                ">/dev/null 2>&1 & echo $!".format(
                    index, pcap, self.udp_src_port, self.udp_dst_port))['stdout'].strip())
        # Let tcpdump open the interfaces before traffic starts
        time.sleep(2)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        time.sleep(self.drain)
        self.ptfhost.shell("kill -INT {} ; sleep 1".format(' '.join(self._pids)), module_ignore_errors=True)
        if exc_type is not None:
            return False
        for pcap in self.pcaps.values():
            output = self.ptfhost.shell("{} -j -r {}".format(SFLOWTOOL, pcap))['stdout']
            self.datagrams += [_parse_sflowtool_line(line) for line in output.splitlines()
                               if line.startswith('{')]
        logger.info("Captured %d sFlow datagrams on PTF ports %s (udp %d -> %d)",
                    len(self.datagrams), self.ptf_indices, self.udp_src_port, self.udp_dst_port)
        return False


def probe_samples(datagrams, probe):
    '''
    Return the flow samples whose sampled header has this probe's tag.

    Each result is the sflowtool flow sample with its HEADER element under 'header' and
    the datagram's agent and version added.
    '''
    matched = []
    for datagram in datagrams:
        for sample in datagram.get('samples', []):
            if sample.get('sampleType') != 'FLOWSAMPLE':
                continue
            for element in sample.get('elements', []):
                if element.get('flowSampleType') != 'HEADER':
                    continue
                if (element.get('srcIP') == probe['ip_src'] and
                        element.get('TCPSrcPort') == str(probe['tcp_sport'])):
                    matched.append(dict(sample, header=element, agent=datagram.get('agent'),
                                        datagram_version=datagram.get('datagramVersion')))
    return matched


def header_bytes(sample):
    '''Return the sampled header of a flow sample as bytes.'''
    hex_str = sample['header'].get('headerBytes', '')
    return bytes(bytearray(int(b, 16) for b in hex_str.split('-') if b))


def assert_sample_count(count, expected, tolerance=HWSFLOW_COUNT_TOLERANCE, label=None):
    '''Assert `count` is within expected +/- tolerance.'''
    low = int(expected * (1 - tolerance))
    high = int(expected * (1 + tolerance))
    msg = "Sample count {} outside expected range [{}, {}]".format(count, low, high)
    if label:
        msg = "{}: {}".format(label, msg)
    pytest_assert(low <= count <= high, msg)


def assert_datagram_fields(samples, agent):
    '''Assert every sample came in a version 5 datagram from `agent`.'''
    for sample in samples:
        pytest_assert(str(sample['datagram_version']) == '5',
                      "Datagram version {} != 5".format(sample['datagram_version']))
        pytest_assert(sample['agent'] == agent,
                      "Agent {} != session src_ip {}".format(sample['agent'], agent))


def assert_sample_rate(samples, sample_rate):
    '''Assert every sample reports the session's sampling rate.'''
    for sample in samples:
        pytest_assert(int(sample['meanSkipCount']) == int(sample_rate),
                      "Sample rate {} != session rate {}".format(sample['meanSkipCount'], sample_rate))


def get_ifindex(duthost, port):
    '''Return the ifIndex SONiC gives a port in SNMP, which hsflowd also reports.'''
    cmd = "python3 -c \"from sonic_py_common import port_util; print(port_util.get_index_from_str('{}'))\""
    return int(duthost.shell(cmd.format(port))['stdout'])


def assert_input_ports(duthost, samples_by_port):
    '''
    Assert the ingress samples of each port report that port's ifIndex as the input interface.

    A packet received on a PortChannel member reports the member port.
    '''
    for port, samples in samples_by_port.items():
        expected = get_ifindex(duthost, port)
        inputs = {int(sample['inputPort']) for sample in samples}
        pytest_assert(inputs == {expected},
                      "{}: samples report input interfaces {}, expected ifIndex {}".format(
                          port, sorted(inputs), expected))


def assert_header_length(samples, pktlen, truncate_size):
    '''
    Assert every sampled header is min(frame, truncate_size) bytes long.

    A frame shorter than the limit is sampled whole; the header may also include its 4-byte FCS.
    '''
    for sample in samples:
        length = len(header_bytes(sample))
        if pktlen >= truncate_size:
            pytest_assert(length == truncate_size,
                          "Header length {} != truncate_size {} (frame {})".format(length, truncate_size, pktlen))
        else:
            limit = min(pktlen + 4, truncate_size)
            pytest_assert(pktlen <= length <= limit,
                          "Header length {} does not hold the {}B frame within {}".format(length, pktlen, limit))
