"""
SRv6 data plane I/O helper.

This module provides `SRv6IO`, a lightweight sender/sniffer used to measure the
data plane disruption experienced by SRv6 traffic while a disruptive operation
(e.g. a warm reboot) is performed on the DUT.

The design follows `tests/common/dualtor/dual_tor_io.py`:

* a sniffer runs on the PTF host under supervisor control and dumps a pcap
  (the sniffer script `tests/scripts/dual_tor_sniffer.py` is topology agnostic
  and is reused as is),
* a sender thread runs on the test host and injects sequence numbered packets
  through the PTF data plane,
* once the traffic has been captured, the pcap is analyzed and every gap in the
  received sequence numbers is reported as a disruption.

The disruption is measured using the timestamps of the *sent* copies captured on
the wire (and not the time at which the sender intended to send them), so that
jitter of the python sender cannot be mistaken for a data plane outage. This is
the same approach as the one used by `ptftests/py3/advanced-reboot.py`.
"""

import datetime
import logging
import os
import threading
import time

import jinja2
import scapy.all as scapyall
import ptf.testutils as testutils

from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from tests.common.utilities import InterruptableThread, wait_until

logger = logging.getLogger(__name__)

TEMPLATES_DIR = "templates/"
SUPERVISOR_CONFIG_DIR = "/etc/supervisor/conf.d/"
SRV6_SNIFFER_CONF_TEMPL = "srv6_sniffer.conf.j2"
SRV6_SNIFFER_CONF = "srv6_sniffer.conf"
SRV6_SNIFFER_PROGRAM = "srv6_sniffer"

PTF_SNIFFER_PATH = "/root/srv6_sniffer.py"
CAPTURE_PCAP = "/tmp/srv6_capture.pcap"
CAPTURE_LOG = "/tmp/srv6_capture.log"

SRV6_FLOW = "srv6"

FLOW_MAGIC = {
    SRV6_FLOW: "SRV6HB",
}

# Number of digits used to encode the sequence number in the packet payload
SEQ_DIGITS = 8

# Hop limit of the injected packets. The copy forwarded by the DUT is expected to
# carry SEND_HLIM - 1, any lower value means the packet went through the DUT more
# than once.
SEND_HLIM = 64

UDP_DPORT = 4791


class SRv6IO(object):
    """Send a continuous SRv6 flow through the DUT and measure its disruption."""

    def __init__(self, duthost, ptfhost, ptfadapter, io_ready_event,
                 ptf_src_port, router_mac, sid_dst, egress_dst,
                 with_srh=False, send_interval=0.01,
                 max_duration=1200, sniff_time_incr=60, src_ipv6="1000::1"):
        """
        Args:
            duthost: DUT host object.
            ptfhost: PTF host object, used to run the sniffer.
            ptfadapter: PTF adapter, used to inject the packets.
            io_ready_event: threading.Event set once sender and sniffer are up.
            ptf_src_port: PTF port index used to inject the traffic.
            router_mac: MAC address of the DUT, used as the outer destination MAC.
            sid_dst: destination IPv6 address of the injected SRv6 packets. It
                must match the configured uN SID.
            egress_dst: destination IPv6 address expected after the uN behavior
                has been applied by the DUT.
            with_srh: inject the SRv6 packets with a segment routing header.
            send_interval: interval in seconds between two sending rounds. One
                packet is sent on every round.
            max_duration: upper bound, in seconds, of the sending phase.
            sniff_time_incr: extra time given to the sniffer on top of
                `max_duration`.
            src_ipv6: source IPv6 address of the injected packets.
        """
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.ptfadapter = ptfadapter
        self.io_ready_event = io_ready_event
        self.ptf_src_port = ptf_src_port
        self.router_mac = router_mac
        self.sid_dst = sid_dst
        self.egress_dst = egress_dst
        self.with_srh = with_srh
        self.send_interval = send_interval
        self.max_duration = max_duration
        self.sniff_timeout = max_duration + sniff_time_incr
        self.src_ipv6 = src_ipv6

        self.ptf_sniffer = PTF_SNIFFER_PATH
        self.capture_pcap = CAPTURE_PCAP
        self.capture_log = CAPTURE_LOG
        self.sniff_filter = None
        self.sniffer_start = None

        self.stop_early = False
        self.sender_start = None
        self.sender_stop = None
        self.action_start = None
        self.action_stop = None
        self.action_start_seq = None
        self.action_stop_seq = None
        self.packets_sent = {SRV6_FLOW: 0}
        self.all_packets = []
        self.test_results = dict()

        self.flows = [SRV6_FLOW]

        self.max_packets = int(self.max_duration / self.send_interval)

        self.ptfadapter.dataplane.flush()

    #
    # Packet generation
    #
    def _payload(self, flow, seq):
        return "{}{:0{width}d}".format(FLOW_MAGIC[flow], seq, width=SEQ_DIGITS)

    def _build_srv6_packet(self, src_mac, seq):
        """Build an SRv6 packet destined to the uN SID under test."""
        payload = self._payload(SRV6_FLOW, seq)
        if self.with_srh:
            return testutils.simple_ipv6_sr_packet(
                eth_dst=self.router_mac,
                eth_src=src_mac,
                ipv6_src=self.src_ipv6,
                ipv6_dst=self.sid_dst,
                ipv6_hlim=SEND_HLIM,
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6() / UDP(dport=UDP_DPORT) / Raw(load=payload)
            )
        return Ether(dst=self.router_mac, src=src_mac) \
            / IPv6(src=self.src_ipv6, dst=self.sid_dst, hlim=SEND_HLIM) \
            / IPv6() / UDP(dport=UDP_DPORT) / Raw(load=payload)

    #
    # Sniffer management
    #
    def setup_ptf_sniffer(self):
        """Setup ptf sniffer supervisor config."""
        ptf_sniffer_args = '-f "%s" -p %s -l %s -t %s' % (
            self.sniff_filter,
            self.capture_pcap,
            self.capture_log,
            self.sniff_timeout
        )
        templ = jinja2.Template(open(os.path.join(TEMPLATES_DIR, SRV6_SNIFFER_CONF_TEMPL)).read())
        self.ptfhost.copy(
            content=templ.render(ptf_sniffer=self.ptf_sniffer, ptf_sniffer_args=ptf_sniffer_args),
            dest=os.path.join(SUPERVISOR_CONFIG_DIR, SRV6_SNIFFER_CONF)
        )
        self.ptfhost.copy(src='scripts/dual_tor_sniffer.py', dest=self.ptf_sniffer)
        self.ptfhost.shell("supervisorctl update")

    def start_ptf_sniffer(self):
        self.ptfhost.shell("supervisorctl start {}".format(SRV6_SNIFFER_PROGRAM))

    def stop_ptf_sniffer(self):
        self.ptfhost.shell("supervisorctl stop {}".format(SRV6_SNIFFER_PROGRAM),
                           module_ignore_errors=True)

    def force_stop_ptf_sniffer(self):
        logger.info("Force stop the ptf sniffer process by sending SIGTERM")
        self.ptfhost.command("pkill -SIGTERM -f %s" % self.ptf_sniffer, module_ignore_errors=True)

    def _get_ptf_sniffer_status(self):
        stdout_text = self.ptfhost.command(
            "supervisorctl status {}".format(SRV6_SNIFFER_PROGRAM), module_ignore_errors=True
        )["stdout"]
        if "no such process" in stdout_text:
            return None
        return stdout_text.split()[1]

    def _is_ptf_sniffer_running(self):
        status = self._get_ptf_sniffer_status()
        return (status is not None) and ("RUNNING" in status)

    def _is_ptf_sniffer_stopped(self):
        status = self._get_ptf_sniffer_status()
        return (status is None) or ("EXITED" in status or "STOPPED" in status)

    def _build_sniff_filter(self):
        """Capture both the injected and the forwarded copies of the flow."""
        addresses = [self.sid_dst, self.egress_dst]
        sniff_filter = "ip6 and ({})".format(
            " or ".join("dst host {}".format(addr) for addr in addresses))

        # The egress destination is routed to a neighbor which may not have a
        # route for it and send it straight back, so a single injected packet can
        # be forwarded by the DUT once per remaining hop. Only the first pass is
        # of interest: the later ones are not duplications made by the DUT and
        # they multiply the load put on the sniffer, which then starts dropping
        # the copies the measurement is based on. ip6[7] is the hop limit.
        sniff_filter = "({}) and (ip6[7] >= {})".format(sniff_filter, SEND_HLIM - 1)

        # The PTF backplane interface is the next hop of the routes announced to
        # the VMs, so packets sent by the DUT to the VMs are captured both on the
        # interface tapped to the VM and on the backplane interface. Filter the
        # backplane copies out to avoid reporting them as duplications.
        output = self.ptfhost.shell('cat /sys/class/net/backplane/address',
                                    module_ignore_errors=True)
        if not output.get('failed', False):
            sniff_filter = '({}) and (not ether dst {})'.format(sniff_filter, output['stdout'])
        return sniff_filter

    def start_sniffer(self):
        self.sniffer_start = datetime.datetime.now()
        self.sniff_filter = self._build_sniff_filter()
        logger.info("Sniffer started at {}, filter: {}".format(self.sniffer_start, self.sniff_filter))

        self.ptfhost.file(path=self.capture_pcap, state="absent")
        if os.path.exists(self.capture_pcap):
            os.unlink(self.capture_pcap)

        self.setup_ptf_sniffer()
        self.start_ptf_sniffer()

        # Let the scapy sniffer initialize completely
        if not wait_until(20, 5, 10, self._is_ptf_sniffer_running):
            self.stop_sniffer()
            raise RuntimeError("Could not start ptf sniffer.")

    def stop_sniffer(self):
        if self._is_ptf_sniffer_running():
            self.stop_ptf_sniffer()

        # The pcap write might take some time, add some waiting here
        if not wait_until(30, 5, 0, self._is_ptf_sniffer_stopped):
            raise RuntimeError("Could not stop ptf sniffer.")
        logger.info("Sniffer finished running after {}".format(
            datetime.datetime.now() - self.sniffer_start))

    def fetch_captured_packets(self):
        logger.info("Fetching pcap file from ptf")
        self.ptfhost.fetch(src=self.capture_pcap, dest='/tmp/', flat=True, fail_on_missing=False)
        self.all_packets = scapyall.rdpcap(self.capture_pcap)
        logger.info("Number of all packets captured: {}".format(len(self.all_packets)))

    #
    # Sender
    #
    def send_packets(self):
        """Inject one SRv6 packet every `send_interval` until asked to stop."""
        src_mac = self.ptfadapter.dataplane.get_mac(0, self.ptf_src_port)
        if isinstance(src_mac, bytes):
            src_mac = src_mac.decode()

        self.sender_start = datetime.datetime.now()
        logger.info("Sender started at {}".format(self.sender_start))

        # Signal the runner that sender and sniffer are up
        self.io_ready_event.set()

        seq = 0
        while seq < self.max_packets and not self.stop_early:
            testutils.send_packet(self.ptfadapter, self.ptf_src_port,
                                  self._build_srv6_packet(src_mac, seq))
            self.packets_sent[SRV6_FLOW] += 1
            seq += 1
            time.sleep(self.send_interval)

        # Give the last packets a chance to be forwarded and captured
        time.sleep(10)
        self.sender_stop = datetime.datetime.now()
        logger.info("Sender finished running after {}, packets sent: {}".format(
            self.sender_stop - self.sender_start, self.packets_sent))

        if not self._is_ptf_sniffer_running():
            raise RuntimeError("ptf sniffer is not running long enough to cover packets sending.")

    def start_io_test(self):
        """
        Entry point of the I/O thread.

        The capture is deliberately not fetched here: reading a pcap of several
        hundred thousand packets takes minutes and would have to be accounted in
        the timeout of the thread join, which is only meant to bound the sender
        and the sniffer. The runner fetches it once the thread has terminated.
        """
        try:
            self.start_sniffer()
            self.send_packets()
            self.stop_sniffer()
        except Exception:
            self.force_stop_ptf_sniffer()
            raise

    def mark_action_start(self):
        self.action_start = datetime.datetime.now()
        self.action_start_seq = self.packets_sent[SRV6_FLOW]

    def mark_action_stop(self):
        self.action_stop = datetime.datetime.now()
        self.action_stop_seq = self.packets_sent[SRV6_FLOW]

    #
    # Flow examination
    #
    def _decode_payload(self, packet):
        """Return (flow, seq) of a captured packet, or (None, None)."""
        raw = bytes(packet)
        for flow, magic in FLOW_MAGIC.items():
            index = raw.find(magic.encode())
            if index == -1:
                continue
            digits = raw[index + len(magic):index + len(magic) + SEQ_DIGITS]
            try:
                return flow, int(digits)
            except ValueError:
                return None, None
        return None, None

    def examine_flow(self):
        """Analyze the captured packets and build the per flow test results."""
        sent = {flow: {} for flow in self.flows}
        received = {flow: {} for flow in self.flows}
        duplicates = {flow: 0 for flow in self.flows}
        mis_forwarded = {flow: 0 for flow in self.flows}
        unexpected_hlim = {flow: 0 for flow in self.flows}

        for packet in self.all_packets:
            if not packet.haslayer(Ether) or not packet.haslayer(IPv6):
                continue
            flow, seq = self._decode_payload(packet)
            if flow is None or flow not in self.flows:
                continue

            timestamp = float(packet.time)
            if packet[Ether].src.lower() != self.router_mac.lower():
                # Copy injected by the PTF, captured on the injection interface
                sent[flow].setdefault(seq, timestamp)
                continue

            # Copy forwarded by the DUT
            if packet[IPv6].dst != self.egress_dst:
                # The packet was forwarded but the uN behavior was not applied,
                # it must not be accounted as successfully forwarded.
                logger.warning("Packet {} of flow {} forwarded with unexpected destination {}".format(
                    seq, flow, packet[IPv6].dst))
                mis_forwarded[flow] += 1
                continue
            if seq in received[flow]:
                duplicates[flow] += 1
                continue
            if packet[IPv6].hlim >= SEND_HLIM:
                # The forwarded copy is expected to have its hop limit decremented
                unexpected_hlim[flow] += 1
            received[flow][seq] = timestamp

        for flow in self.flows:
            self.test_results[flow] = self._build_flow_result(
                flow, sent[flow], received[flow], duplicates[flow],
                mis_forwarded[flow], unexpected_hlim[flow])

        return self.test_results

    def _covers_action(self, sent):
        """
        Tell whether the traffic actually spans the whole action.

        If the sender ran out of packets before the action completed, no traffic
        was flowing while the DUT was rebooting and the absence of disruption
        would be meaningless.

        The comparison is made on sequence numbers rather than on timestamps: the
        capture is timestamped by the PTF host while the action is timed by the
        test host, and the two clocks are not synchronized.
        """
        if self.action_start_seq is None or self.action_stop_seq is None:
            return None
        if not sent:
            return False
        return min(sent) < self.action_start_seq and max(sent) >= self.action_stop_seq

    def _build_flow_result(self, flow, sent, received, duplicates, mis_forwarded, unexpected_hlim):
        disruptions = self._compute_disruptions(sent, received)
        total_disruption = sum(item['duration'] for item in disruptions)
        longest_disruption = max([item['duration'] for item in disruptions]) if disruptions else 0

        result = {
            'flow': flow,
            'sent_packets': len(sent),
            'received_packets': len(received),
            'lost_packets': sum(item['lost_packets'] for item in disruptions),
            'duplicated_packets': duplicates,
            'mis_forwarded_packets': mis_forwarded,
            'unexpected_hlim_packets': unexpected_hlim,
            'covers_action': self._covers_action(sent),
            'disruptions': disruptions,
            'disruption_count': len(disruptions),
            'longest_disruption': longest_disruption,
            'total_disruption': total_disruption,
        }
        return result

    def _compute_disruptions(self, sent, received):
        """
        Walk the received sequence numbers and report every gap that contains at
        least one packet which was actually sent.

        The length of a disruption is the time elapsed between the sending of the
        first lost packet and the sending of the first packet received after the
        gap, which is how `advanced-reboot.py` measures it.
        """
        disruptions = []
        if not received:
            if sent:
                first, last = min(sent), max(sent)
                disruptions.append(self._disruption(first, last, sent[first], sent[last], len(sent)))
            return disruptions

        received_seqs = sorted(received)

        # Packets sent before the first received one
        leading_lost = [seq for seq in sent if seq < received_seqs[0]]
        if leading_lost:
            first, last = min(leading_lost), max(leading_lost)
            disruptions.append(self._disruption(
                first, received_seqs[0], sent[first], sent[received_seqs[0]], len(leading_lost)))

        previous = None
        for seq in received_seqs:
            if previous is not None and seq - previous > 1:
                lost = [lost_seq for lost_seq in range(previous + 1, seq) if lost_seq in sent]
                if lost:
                    end_time = sent.get(seq, received[seq])
                    disruptions.append(self._disruption(
                        previous, seq, sent[lost[0]], end_time, len(lost)))
                else:
                    # None of the missing packets was captured on the sending
                    # side either: the sender or the sniffer missed them, this
                    # is not a data plane disruption.
                    logger.warning("Sequence numbers {}-{} were neither sent nor received, "
                                   "ignoring them".format(previous + 1, seq - 1))
            previous = seq

        # Packets sent after the last received one, i.e. an outage that never recovered
        trailing_lost = [seq for seq in sent if seq > received_seqs[-1]]
        if trailing_lost:
            first, last = min(trailing_lost), max(trailing_lost)
            disruptions.append(self._disruption(
                received_seqs[-1], last, sent[first], sent[last], len(trailing_lost)))

        return disruptions

    def _disruption(self, start_id, end_id, start_time, end_time, lost_packets):
        disruption = {
            'start_id': start_id,
            'end_id': end_id,
            'start_time': start_time,
            'end_time': end_time,
            'duration': max(end_time - start_time, 0),
            'lost_packets': lost_packets,
        }
        if self.action_start:
            action_start = self.action_start.timestamp()
            disruption['start_offset_from_action'] = start_time - action_start
            disruption['end_offset_from_action'] = end_time - action_start
        return disruption

    def get_test_results(self):
        return self.test_results


def run_srv6_io_test(duthost, ptfhost, ptfadapter, action, ptf_src_port, router_mac,
                     sid_dst, egress_dst, with_srh=False,
                     send_interval=0.01, max_duration=1200, settle_time=60,
                     warm_up_time=15):
    """
    Run a continuous SRv6 flow through the DUT while `action` is executed.

    The traffic keeps running for `settle_time` seconds after `action` returned:
    the SRv6 SID entries are reconciled by bgpcfgd/fpmsyncd/orchagent *after* the
    warm boot finalizer completes, so a disruption caused by a late
    reprogramming would otherwise not be covered by the traffic.

    Returns:
        SRv6IO: the I/O object, with the test results already computed.
    """
    io_ready = threading.Event()
    srv6_io = SRv6IO(duthost, ptfhost, ptfadapter, io_ready, ptf_src_port, router_mac,
                     sid_dst, egress_dst, with_srh=with_srh,
                     send_interval=send_interval, max_duration=max_duration)

    io_thread = InterruptableThread(target=srv6_io.start_io_test)
    io_thread.set_error_handler(lambda *args, **kwargs: io_ready.set())
    io_thread.start()
    io_ready.wait()

    if not io_thread.is_alive():
        # The I/O thread died before sending anything, join it to get the reason
        io_thread.join(timeout=10)
        raise RuntimeError("The SRv6 I/O thread stopped before the traffic was started")

    try:
        # Send some traffic before the action so that a disruption which started
        # before the action can be told apart from one caused by the action
        time.sleep(warm_up_time)

        logger.info("Sender and sniffer are ready, executing the action")
        srv6_io.mark_action_start()
        action()
        srv6_io.mark_action_stop()

        logger.info("Action completed, keeping the traffic running for {}s".format(settle_time))
        time.sleep(settle_time)
    except Exception:
        srv6_io.stop_early = True
        # Do not let a failure of the I/O thread mask the failure of the action
        io_thread.join(timeout=120, suppress_exception=True)
        raise

    srv6_io.stop_early = True
    io_thread.join(timeout=300)
    if io_thread.is_alive():
        raise RuntimeError("SRv6 I/O thread did not terminate")

    srv6_io.fetch_captured_packets()
    srv6_io.examine_flow()
    return srv6_io


def format_flow_result(result):
    """Build a human readable summary of a flow result."""
    lines = [
        "flow                    : {}".format(result['flow']),
        "sent packets            : {}".format(result['sent_packets']),
        "received packets        : {}".format(result['received_packets']),
        "lost packets            : {}".format(result['lost_packets']),
        "duplicated packets      : {}".format(result['duplicated_packets']),
        "mis forwarded packets   : {}".format(result['mis_forwarded_packets']),
        "unexpected hop limit    : {}".format(result['unexpected_hlim_packets']),
        "traffic covers action   : {}".format(result['covers_action']),
        "disruption count        : {}".format(result['disruption_count']),
        "longest disruption (s)  : {:.4f}".format(result['longest_disruption']),
        "total disruption (s)    : {:.4f}".format(result['total_disruption']),
    ]
    for disruption in result['disruptions']:
        offset = "{:.4f}s".format(disruption['start_offset_from_action']) \
            if 'start_offset_from_action' in disruption else "an unknown time"
        lines.append(
            "  disruption: packets {}-{} ({} lost), duration {:.4f}s, "
            "starting {} after the action".format(
                disruption['start_id'], disruption['end_id'], disruption['lost_packets'],
                disruption['duration'], offset))
    return "\n".join(lines)
