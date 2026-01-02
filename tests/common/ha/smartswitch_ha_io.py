import re
import datetime
import time
import logging
import jinja2
import json
import os
import scapy.all as scapyall
from operator import itemgetter
from itertools import groupby
from collections import defaultdict
from natsort import natsorted

from tests.common.utilities import wait_until, convert_scapy_packet_to_bytes

TCP_DST_PORT = 5000
TEMPLATES_DIR = "templates/"
SUPERVISOR_CONFIG_DIR = "/etc/supervisor/conf.d/"
SSW_HA_SNIFFER_CONF_TEMPL = "smartswitch_ha_sniffer.conf.j2"
SSW_HA_SNIFFER_CONF = "ha_sniffer.conf"

NUM_SENT_PACKETS = 1000
SENDER_NAMESPACE = "ns1"
SNIFFER_NAMESPACE = "ns2"

logger = logging.getLogger(__name__)


class SmartSwitchHaTrafficTest:
    """Class to conduct IO over ports in `active-standby` mode."""

    def __init__(self, targethost, ptfhost, tbinfo,
                 io_ready, send_interval=0.01,
                 client_namespace=SENDER_NAMESPACE,
                 server_namespace=SNIFFER_NAMESPACE):
        self.duthost = targethost
        self.ptfhost = ptfhost
        self.tbinfo = tbinfo
        self.io_ready_event = io_ready

        self.test_results = dict()
        self.stop_early = False
        self.ptf_sniffer = "/root/ha_sniffer.py"

        self.client_namespace = client_namespace
        self.server_namespace = server_namespace

        self.time_to_listen = 300.0
        self.sniff_time_incr = 0

        if send_interval < 0.0035:
            if send_interval is not None:
                logger.warn("Minimum packet send-interval is .0035s. \
                    Ignoring user-provided interval {}".format(send_interval))
            self.send_interval = 0.0035
        else:
            self.send_interval = send_interval
        logger.info("Using send interval {}".format(self.send_interval))

        self.all_packets = []

    def setup_ptf_sniffer(self):
        """Setup ptf sniffer supervisor config."""
        ptf_sniffer_args = '-f "%s" -p %s -l %s -t %s ' % (
            self.sniff_filter,
            self.capture_pcap,
            self.capture_log,
            self.sniff_timeout,
        )

        logger.debug("PTF Sniffer args: {}".format(ptf_sniffer_args))
        logger.debug("PTF Sniffer script: {}".format(self.ptf_sniffer))
        logger.debug("PTF Sniffer namespace: {}".format(self.server_namespace))

        templ = jinja2.Template(open(os.path.join(TEMPLATES_DIR, SSW_HA_SNIFFER_CONF_TEMPL)).read())

        self.ptfhost.copy(
            content=templ.render(ptf_sniffer=self.ptf_sniffer,
                                 ptf_sniffer_args=ptf_sniffer_args,
                                 netns=self.server_namespace),
            dest=os.path.join(SUPERVISOR_CONFIG_DIR, SSW_HA_SNIFFER_CONF)
        )
        self.ptfhost.copy(src='scripts/ha_sniffer.py', dest=self.ptf_sniffer)
        self.ptfhost.shell("supervisorctl update")

    def start_ptf_sniffer(self):
        """Start the ptf sniffer."""
        self.ptfhost.shell("supervisorctl start ha_sniffer")

    def stop_ptf_sniffer(self):
        """Stop the ptf sniffer."""
        self.ptfhost.shell("supervisorctl stop ha_sniffer", module_ignore_errors=True)

    def force_stop_ptf_sniffer(self):
        """Force stop the ptf sniffer by sending SIGTERM."""
        logger.info("Force stop the ptf sniffer process by sending SIGTERM")
        self.ptfhost.command("pkill -SIGTERM -f %s" % self.ptf_sniffer, module_ignore_errors=True)

    def start_io_test(self):
        """
        @summary: The entry point to start the dataplane I/O test.
        """
        self.send_and_sniff()

    def send_and_sniff(self):
        """Start the I/O sender/sniffer."""
        try:
            self.start_sniffer()
            self.send_packets()
            self.stop_sniffer()
        except Exception:
            self.force_stop_ptf_sniffer()
            raise

        self.fetch_captured_packets()

    def _get_ptf_sniffer_status(self):
        """Get the ptf sniffer status."""
        # the output should be like
        # $ supervisorctl status ha_sniffer
        # ha_sniffer                 EXITED    Oct 29 01:11 PM
        stdout_text = self.ptfhost.command(
            "supervisorctl status ha_sniffer", module_ignore_errors=True
        )["stdout"]
        if "no such process" in stdout_text:
            return None
        else:
            return stdout_text.split()[1]

    def _is_ptf_sniffer_running(self):
        """Check if the ptf sniffer is running."""
        status = self._get_ptf_sniffer_status()
        return ((status is not None) and ("RUNNING" in status))

    def _is_ptf_sniffer_stopped(self):
        status = self._get_ptf_sniffer_status()
        return ((status is None) or ("EXITED" in status or "STOPPED" in status))

    def start_sniffer(self):
        """Start ptf sniffer."""
        self.sniff_timeout = self.time_to_listen + self.sniff_time_incr
        self.sniffer_start = datetime.datetime.now()
        logger.info("Sniffer started at {}".format(str(self.sniffer_start)))
        # self.sniff_filter = "tcp and tcp dst port {} and tcp src port {} and not icmp".\
        #    format(TCP_DST_PORT, self.tcp_sport)
        self.sniff_filter = "tcp and tcp dst port {} and not icmp".\
            format(TCP_DST_PORT)

        # We run a PTF script on PTF to sniff traffic. The PTF script calls
        # scapy.sniff which by default capture the backplane interface for
        # announcing routes from PTF to VMs. On VMs, the PTF backplane is the
        # next hop for the annoucned routes. So, packets sent by DUT to VMs
        # are forwarded to the PTF backplane interface as well. Then on PTF,
        # the packets sent by DUT to VMs can be captured on both the PTF interfaces
        # tapped to VMs and on the backplane interface. This will result in
        # packet duplication and fail the test. Below change is to add capture
        # filter to filter out all the packets destined to the PTF backplane interface.
        output = self.ptfhost.shell('cat /sys/class/net/backplane/address',
                                    module_ignore_errors=True)
        if not output['failed']:
            # self.sniff_filter = '({}) and (not ether dst {})'.format(self.sniff_filter, ptf_bp_mac)
            self.sniff_filter = '({})'.format(self.sniff_filter)

        self.capture_pcap = '/tmp/capture.pcap'
        self.capture_log = '/tmp/capture.log'

        # Do some cleanup first
        self.ptfhost.file(path=self.capture_pcap, state="absent")
        if os.path.exists(self.capture_pcap):
            os.unlink(self.capture_pcap)

        self.setup_ptf_sniffer()
        self.start_ptf_sniffer()

        # Let the scapy sniff initialize completely.
        if not wait_until(20, 5, 10, self._is_ptf_sniffer_running):
            self.stop_sniffer()
            raise RuntimeError("Could not start ptf sniffer.")

    def stop_sniffer(self):
        """Stop the ptf sniffer."""
        if self._is_ptf_sniffer_running():
            self.stop_ptf_sniffer()

        # The pcap write might take some time, add some waiting here.
        if not wait_until(30, 5, 0, self._is_ptf_sniffer_stopped):
            raise RuntimeError("Could not stop ptf sniffer.")
        logger.info("Sniffer finished running after {}".
                    format(str(datetime.datetime.now() - self.sniffer_start)))

    def fetch_captured_packets(self):
        """Fetch the captured packet file generated by the ptf sniffer."""
        logger.info('Fetching pcap file from ptf')
        self.ptfhost.fetch(src=self.capture_pcap, dest='/tmp/', flat=True, fail_on_missing=False)
        self.all_packets = scapyall.rdpcap(self.capture_pcap)
        logger.info("Number of all packets captured: {}".format(len(self.all_packets)))

    def send_packets(self):
        """Send packets generated."""
        logger.info("Sender waiting to send {} packets".format(NUM_SENT_PACKETS))

        sender_start = datetime.datetime.now()
        logger.info("Sender started at {}".format(str(sender_start)))

        # Signal data_plane_utils that sender and sniffer threads have begun
        self.io_ready_event.set()

        self.start_tcp_server(namespace=self.server_namespace)
        # TODO: interval, packet numbers etc. should be passed as parameters
        self.start_tcp_client(namespace=self.client_namespace)

        # wait 10s so all packets could be forwarded
        time.sleep(10)
        logger.info(
            "Sender finished running after %s, %s packets sent",
            datetime.datetime.now() - sender_start,
            NUM_SENT_PACKETS
        )

        self.stop_tcp_server(namespace=self.server_namespace)

        if not self._is_ptf_sniffer_running():
            raise RuntimeError("ptf sniffer is not running enough time to cover packets sending.")

    def get_test_results(self):
        return self.test_results

    def examine_flow(self):
        """
        @summary: This method examines packets collected by sniffer thread
            The method compares TCP payloads of the packets one by one (assuming all
            payloads are consecutive integers), and the losses if found - are treated
            as disruptions in Dataplane forwarding. All disruptions are saved to
            self.lost_packets dictionary, in format:
            disrupt_start_id = (missing_packets_count, disrupt_time,
            disrupt_start_timestamp, disrupt_stop_timestamp)
        """
        examine_start = datetime.datetime.now()
        logger.info("Packet flow examine started {}".format(str(examine_start)))

        if not self.all_packets:
            logger.error("self.all_packets not defined.")
            return None

        # Filter out packets:
        filtered_packets = [pkt for pkt in self.all_packets if
                            scapyall.TCP in pkt and
                            scapyall.ICMP not in pkt and
                            pkt[scapyall.TCP].dport == TCP_DST_PORT]
        logger.info("Number of filtered packets captured: {}".format(len(filtered_packets)))
        if not filtered_packets or len(filtered_packets) == 0:
            logger.error("Sniffer failed to capture any traffic")

        dst_to_packet_map = defaultdict(list)

        # Split packets into separate lists based on dst IP address
        for packet in filtered_packets:
            dst_addr = packet[scapyall.IP].dst
            dst_to_packet_map[dst_addr].append(packet)

        def get_packet_sort_key(packet):
            return (self.check_packet_id(packet), packet.time)

        # For each server's packet list, sort by payload then timestamp
        # (in case of duplicates)
        for dst in list(dst_to_packet_map.keys()):
            dst_to_packet_map[dst].sort(key=get_packet_sort_key)

        logger.info("Measuring traffic disruptions...")
        for dst_ip, packet_list in list(dst_to_packet_map.items()):
            filename = '/tmp/capture_filtered_{}.pcap'.format(dst_ip)
            scapyall.wrpcap(filename, packet_list)
            logger.info("Filtered pcap dumped to {}".format(filename))

        self.test_results = {}

        for dst_ip in natsorted(list(dst_to_packet_map.keys())):
            result = self.examine_each_packet(dst_ip, dst_to_packet_map[dst_ip])
            logger.info("Server {} results:\n{}"
                        .format(dst_ip, json.dumps(result, indent=4)))
            self.test_results[dst_ip] = result

    def examine_each_packet(self, dst_ip, packets):
        received_packet_list = list()
        duplicate_packet_list = list()
        disruption_ranges = list()
        disruption_before_traffic = False
        disruption_after_traffic = False
        duplicate_ranges = []

        for packet in packets:

            curr_time = packet.time

            curr_payload = self.check_packet_id(packet)
            if curr_payload < 0:
                # Invalid packet, skip it
                continue

            # Look back at the previous received packet to check for gaps/duplicates
            # Only if we've already received some packets
            if len(received_packet_list) > 0:
                prev_payload, prev_time = received_packet_list[-1]

                if prev_payload == curr_payload:
                    # Duplicate packet detected, increment the counter
                    duplicate_packet_list.append((curr_payload, curr_time))
                if prev_payload + 1 < curr_payload:
                    # Non-sequential packets indicate a disruption
                    disruption_dict = {
                        'start_time': prev_time,
                        'end_time': curr_time,
                        'start_id': prev_payload,
                        'end_id': curr_payload
                    }
                    disruption_ranges.append(disruption_dict)

            # Save packets as (payload_id, timestamp) tuples
            # for easier timing calculations later
            received_packet_list.append((curr_payload, curr_time))

        if len(received_packet_list) == 0:
            logger.error("Sniffer failed to filter any traffic from DUT")
        else:
            # Find ranges of consecutive packets that have been duplicated
            # All packets within the same consecutive range will have the same
            # difference between the packet index and the sequence number
            for _, grouper in groupby(enumerate(duplicate_packet_list), lambda t: t[0] - t[1][0]):
                group = list(map(itemgetter(1), grouper))
                duplicate_start, duplicate_end = group[0], group[-1]
                duplicate_dict = {
                    'start_time': duplicate_start[1],
                    'end_time': duplicate_end[1],
                    'start_id': duplicate_start[0],
                    'end_id': duplicate_end[0]
                }
                duplicate_ranges.append(duplicate_dict)

            # If the first packet we received is not #0, some disruption started
            # before traffic started. Store the id of the first received packet
            if received_packet_list[0][0] != 0:
                disruption_before_traffic = received_packet_list[0][0]
            # If the last packet we received does not match the number of packets
            # sent, some disruption continued after the traffic finished.
            # Store the id of the last received packet
            if received_packet_list[-1][0] != NUM_SENT_PACKETS - 1:
                disruption_after_traffic = received_packet_list[-1][0]

        result = {
            'sent_packets': NUM_SENT_PACKETS,
            'received_packets': len(received_packet_list),
            'disruption_before_traffic': disruption_before_traffic,
            'disruption_after_traffic': disruption_after_traffic,
            'duplications': duplicate_ranges,
            'disruptions': disruption_ranges
        }

        if len(received_packet_list) < NUM_SENT_PACKETS:
            logger.error('Not all sent packets were captured. '
                         'Something went wrong!')
            logger.error('Dumping dst ip {} results and continuing:\n{}'
                         .format(dst_ip, json.dumps(result, indent=4)))

        return result

    def check_packet_id(self, packet):

        try:
            payload_bytes = convert_scapy_packet_to_bytes(packet[scapyall.TCP].payload)
            payload_str = payload_bytes.decode()
        except Exception:
            return -1

        match = re.search(r"Packet id: (\d+)\.", payload_str)
        if match:
            id = int(match.group(1))
        else:
            logger.warning("Invalid packet payload format: {}".format(payload_str))
            return -1

        return id

    def start_tcp_server(self, namespace=None):
        cmd = "python3 /root/tcp_server.py &"
        if namespace:
            cmd = f"ip netns exec {namespace} {cmd}"
        self.ptfhost.shell(cmd)

        if not self._is_tcp_server_running(namespace):
            raise RuntimeError("TCP server did not start successfully in namespace {}".format(namespace))

    def stop_tcp_server(self, namespace=None):
        cmd = "pkill -f /root/tcp_server.py"
        if namespace:
            cmd = f"ip netns exec {namespace} {cmd}"
        self.ptfhost.shell(cmd)

        if self._is_tcp_server_running(namespace):
            raise RuntimeError("TCP server did not stop successfully in namespace {}".format(namespace))

    def _is_tcp_server_running(self, namespace=None):
        cmd = "pgrep -f /root/tcp_server.py"
        if namespace:
            cmd = f"ip netns exec {namespace} {cmd}"
        result = self.ptfhost.shell(cmd, module_ignore_errors=True)
        return result["rc"] == 0

    def _is_tcp_client_running(self, namespace=None):
        cmd = "pgrep -f /root/tcp_client.py"
        if namespace:
            cmd = f"ip netns exec {namespace} {cmd}"
        result = self.ptfhost.shell(cmd, module_ignore_errors=True)
        return result["rc"] == 0

    def start_tcp_client(self, namespace=None):
        cmd = "python3 /root/tcp_client.py "
        if namespace:
            cmd = f"ip netns exec {namespace} {cmd}"
        self.ptfhost.shell(cmd)
