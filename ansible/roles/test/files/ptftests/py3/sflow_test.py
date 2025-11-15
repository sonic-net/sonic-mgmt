"""
        ptf --test-dir ptftests sflow_test \
            --platform-dir ptftests \
            --platform remote \
            -t "enabled_sflow_interfaces=[u'Ethernet116', u'Ethernet124', u'Ethernet112', u'Ethernet120'];\
                active_collectors=[];dst_port=3;testbed_type='t0';router_mac=u'52:54:00:f7:0c:d0';\
                sflow_ports_file='/tmp/sflow_ports.json';agent_id=u'10.250.0.101'" \
            --relax \
            --debug info \
            --log-file /tmp/TestSflowCollector.test_two_collectors.log \
            --socket-recv-size 16384

        /usr/bin/python /usr/bin/ptf --test-dir ptftests sflow_test \
            --platform-dir ptftests \
            --platform remote \
            -t "enabled_sflow_interfaces=[u'Ethernet116', u'Ethernet124', u'Ethernet112', u'Ethernet120'];\
                active_collectors=['collector1'];dst_port=3;testbed_type='t0';router_mac='52:54:00:f7:0c:d0';\
                sflow_ports_file='/tmp/sflow_ports.json';agent_id=u'10.250.0.101'" \
            --relax \
            --debug info \
            --log-file /tmp/TestSflow.log \
            --socket-recv-size 16384
"""

import ptf
import os
import json
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
import threading
import time
from collections import Counter
import logging
import ast
import subprocess

# use enough samples to smooth out any minor fluctuation
EXPECTED_FLOW_SAMPLES_PER_INTF = 100


class SflowTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()
    # --------------------------------------------------------------------------

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.dst_port = self.test_params['dst_port']

        if 'enabled_sflow_interfaces' in self.test_params:
            self.enabled_intf = self.test_params['enabled_sflow_interfaces']
        self.agent_id = self.test_params['agent_id']
        self.active_col = ast.literal_eval(self.test_params['active_collectors'])
        self.sflow_interfaces = []
        self.sflow_ports_file = self.test_params['sflow_ports_file']
        if 'polling_int' in self.test_params:
            self.poll_tests = True
            self.polling_int = self.test_params['polling_int']
        else:
            self.poll_tests = False
        with open(self.sflow_ports_file) as fp:
            self.interfaces = json.load(fp)
            for port, index in self.interfaces.items():
                self.sflow_interfaces.append(index["ptf_indices"])
        logging.info("Sflow interfaces under Test : %s" % self.interfaces)
        self.collectors = ['collector0', 'collector1']
        for param, value in self.test_params.items():
            logging.info("%s : %s" % (param, value))
        samples_per_collector = 0
        if 'enabled_sflow_interfaces' in self.test_params:
            samples_per_collector = EXPECTED_FLOW_SAMPLES_PER_INTF * len(self.enabled_intf)
        else:
            samples_per_collector = EXPECTED_FLOW_SAMPLES_PER_INTF * len(self.interfaces)
        self.total_expected_flow_samples = samples_per_collector * len(self.active_col)

    def tearDown(self):
        self.cmd(["supervisorctl", "stop", "arp_responder"])
        self.cmd(["killall", "sflowtool"])
    # --------------------------------------------------------------------------

    def generate_ArpResponderConfig(self):
        config = {}
        config['eth%d' % self.dst_port] = ['192.168.0.4']
        with open('/tmp/sflow_arpresponder.conf', 'w') as fp:
            json.dump(config, fp)
        self.cmd(["supervisorctl", "restart", "arp_responder"])

    # --------------------------------------------------------------------------

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    # --------------------------------------------------------------------------

    def read_data(self, collector, ready_event, stop_event, sflow_port=['6343']):
        """
        Starts sflowtool with the corresponding port and saves the data to file for processing
        """
        outfile = '/tmp/%s' % collector
        with open(outfile, 'w') as f:
            process = subprocess.Popen(['/usr/local/bin/sflowtool', '-j', '-p'] + sflow_port,
                                       stdout=f,
                                       stderr=subprocess.STDOUT,
                                       shell=False
                                       )

            flow_count = 0
            counter_count = 0
            port_sample = {}
            port_sample[collector] = {}
            port_sample[collector]['FlowSample'] = {}
            port_sample[collector]['CounterSample'] = {}
            logging.info("Collector %s starts collecting ......" % collector)
            ready_event.set()
            timeout = 240
            logging.info("Waiting for stop_event to be set under {} seconds; stop_event is {}".format(
                timeout, stop_event.isSet()))
            # Wait for stop_event to be set from Main Thread or to pass out by timeout
            event_is_set = stop_event.wait(timeout=timeout)
            logging.info("{}; stop_event set: {}".format(
                threading.current_thread().getName(), event_is_set))

        process.terminate()
        process.wait()
        f.close()
        with open(outfile, 'r') as sflow_data:
            for line in sflow_data:
                j = json.dumps(ast.literal_eval(line))
                datagram = json.loads(j)
                agent = datagram["agent"]
                samples = datagram["samples"]
                for sample in samples:
                    sampleType = sample["sampleType"]
                    if sampleType == "FLOWSAMPLE":
                        flow_count += 1
                        port_sample[collector]['FlowSample'][flow_count] = sample
                    elif sampleType == "COUNTERSSAMPLE":
                        counter_count += 1
                        port_sample[collector]['CounterSample'][counter_count] = sample
                        port_sample[collector]['CounterSample'][counter_count]['agent_id'] = agent
        sflow_data.close()
        port_sample[collector]['counter_count'] = counter_count
        port_sample[collector]['flow_count'] = flow_count
        port_sample[collector]['total_count'] = counter_count + flow_count
        logging.info("%s Sampled Packets : Total flow samples -> %s Total counter samples -> %s" %
                     (collector, flow_count, counter_count))
        return (port_sample)

    def count_packets_received(self, collector_name):
        """
        Count packets received by checking the collector's output file

        Args:
            collector_name: 'collector0' or 'collector1'

        Returns:
            tuple: flow_count, counter_count
        """
        outfile = f'/tmp/{collector_name}'
        flow_count = 0
        counter_count = 0
        try:
            if os.path.exists(outfile):
                with open(outfile, 'r') as f:
                    lines = f.readlines()
                for line in lines:
                    try:
                        j = json.dumps(ast.literal_eval(line.strip()))
                        datagram = json.loads(j)
                        samples = datagram.get("samples", [])
                        for sample in samples:
                            sample_type = sample.get("sampleType", "")
                            if sample_type == "FLOWSAMPLE":
                                flow_count += 1
                            elif sample_type == "COUNTERSSAMPLE":
                                counter_count += 1
                    except (ValueError, SyntaxError, json.JSONDecodeError):
                        # Skip malformed lines
                        continue
        except (OSError, IOError):
            # File doesn't exist or can't be read
            pass
        total_count = flow_count + counter_count
        return flow_count, counter_count, total_count
    # --------------------------------------------------------------------------

    def collector_0(self, ready_event, stop_event):
        self.collector0_samples = self.read_data('collector0', ready_event, stop_event)
    # --------------------------------------------------------------------------

    def collector_1(self, ready_event, stop_event):
        self.collector1_samples = self.read_data('collector1', ready_event, stop_event, ['6344'])
    # --------------------------------------------------------------------------

    def packet_analyzer(self, port_sample, collector, poll_test):
        logging.info("Analysing collector  %s" % collector)
        data = {}
        data['total_samples'] = 0
        data['total_flow_count'] = port_sample[collector]['flow_count']
        data['total_counter_count'] = port_sample[collector]['counter_count']
        data['total_samples'] = port_sample[collector]['flow_count'] + \
            port_sample[collector]['counter_count']
        logging.info(data)
        if data['total_flow_count']:
            data['flow_port_count'] = Counter(
                k['inputPort'] for k in port_sample[collector]['FlowSample'].values())

        if collector not in self.active_col:
            logging.info("....%s : Sample Packets are not expected , received %s flow packets  and %s counter packets"
                         % (collector, data['total_flow_count'], data['total_counter_count']))
            self.assertTrue(data['total_samples'] == 0,
                            "Packets are not expected from %s , but received %s flow packets  and %s counter packets"
                            % (collector, data['total_flow_count'], data['total_counter_count']))
        else:
            if poll_test:
                if self.polling_int == 0:
                    logging.info(
                        "....Polling is disabled , Number of counter samples collected %s"
                        % data['total_counter_count'])
                    self.assertTrue(data['total_counter_count'] == 0,
                                    "Received %s counter packets when polling is disabled in %s"
                                    % (data['total_counter_count'], collector))
                else:
                    logging.info("..Analyzing polling test counter packets")
                    self.assertTrue(data['total_samples'] != 0,
                                    "....Packets are not received in active collector  ,%s" % collector)
                    self.analyze_counter_sample(
                        data, collector, self.polling_int, port_sample)
            else:
                logging.info(
                    "Analyzing flow samples in collector %s" % collector)
                self.assertTrue(data['total_samples'] != 0,
                                "....Packets are not received in active collector  ,%s" % collector)
                self.analyze_flow_sample(data, collector)
        return data

    # --------------------------------------------------------------------------

    def analyze_counter_sample(self, data, collector, polling_int, port_sample):
        counter_sample = {}
        for intf in self.interfaces.keys():
            counter_sample[intf] = 0
        self.assertTrue(data['total_counter_count'] > 0,
                        "No counter packets are received in collector %s" % collector)
        for i in range(1, data['total_counter_count']+1):
            rcvd_agent_id = port_sample[collector]['CounterSample'][i]['agent_id']
            self.assertTrue(
                rcvd_agent_id == self.agent_id,
                "Agent id in Sampled packet is not expected . Expected :  %s , received : %s"
                % (self.agent_id, rcvd_agent_id))
            elements = port_sample[collector]['CounterSample'][i]['elements']
            for element in elements:
                try:
                    if 'ifName' in element and element['ifName'] in self.interfaces.keys():
                        intf = element['ifName']
                        counter_sample[intf] += 1
                except KeyError:
                    pass
        logging.info("....%s : Counter samples collected for Individual  ports  = %s" % (
            collector, counter_sample))
        for port in counter_sample:
            # checking  for max  2 samples instead of 1 considering initial time delay before tests
            # as the counter sampling is random and non-deterministic over period of polling time
            self.assertTrue(
                1 <= counter_sample[port] <= 2,
                " %s counter sample packets are collected in %s seconds of polling interval in port %s "
                "instead of 1 or 2" % (counter_sample[port], polling_int, port))

    # ---------------------------------------------------------------------------

    def analyze_flow_sample(self, data, collector):
        logging.info("packets collected from interfaces ifindex : %s" %
                     data['flow_port_count'])
        logging.info("Expected number of packets from each port : %s to %s" % (
            EXPECTED_FLOW_SAMPLES_PER_INTF * 0.6, EXPECTED_FLOW_SAMPLES_PER_INTF * 1.4))
        for port in self.interfaces:
            # NOTE: hsflowd is sending index instead of ifindex.
            index = self.interfaces[port]['port_index']
            logging.info("....%s : Flow packets collected from port %s = %s" % (
                collector, port, data['flow_port_count'][index]))
            if port in self.enabled_intf:
                # Checking samples with tolerance of 40 % as the sampling is random and not deterministic.
                # Over many samples it should converge to a mean of 1:N
                # Number of packets sent = EXPECTED_FLOW_SAMPLES_PER_INTF * sampling rate of interface
                min_samples = EXPECTED_FLOW_SAMPLES_PER_INTF * 0.6
                max_samples = EXPECTED_FLOW_SAMPLES_PER_INTF * 1.4
                self.assertTrue(
                    min_samples <= data['flow_port_count'][index] <= max_samples,
                    "Expected Number of samples are not collected from Interface %s in collector %s , Received %s"
                    " which is outside the acceptable range of %s to %s"
                    % (port, collector, data['flow_port_count'][index], min_samples, max_samples))
            else:
                self.assertTrue(data['flow_port_count'][index] == 0,
                                "Packets are collected from Non Sflow interface %s in collector %s" % (port, collector))

    # ---------------------------------------------------------------------------

    def sendTraffic(self):
        src_ip_addr_templ = '192.168.{}.1'
        ip_dst_addr = '192.168.0.4'
        pktlen = 100
        # send EXPECTED_FLOW_SAMPLES_PER_INTF * sampling_rate packets in each interface for better analysis
        for _ in range(0, EXPECTED_FLOW_SAMPLES_PER_INTF, 1):
            index = 0
            for intf in self.interfaces:
                ip_src_addr = src_ip_addr_templ.format(str(8 * index))
                src_port = self.interfaces[intf]['ptf_indices']
                src_mac = self.dataplane.get_mac(0, src_port)
                tcp_pkt = testutils.simple_tcp_packet(pktlen=pktlen,
                                                      eth_dst=self.router_mac,
                                                      eth_src=src_mac,
                                                      ip_src=ip_src_addr,
                                                      ip_dst=ip_dst_addr,
                                                      ip_ttl=64)
                no_of_packets = self.interfaces[intf]['sample_rate']
                testutils.send(self, src_port, tcp_pkt, count=no_of_packets)
                index += 1
            pktlen += 10  # send traffic with different packet sizes

    # --------------------------------------------------------------------------

    def runTest(self):
        self.generate_ArpResponderConfig()
        collector0_ready = threading.Event()
        collector1_ready = threading.Event()
        stop_collector = threading.Event()
        thr1 = threading.Thread(target=self.collector_0,
                                name='Collector0_thread', args=(collector0_ready, stop_collector,))
        thr2 = threading.Thread(target=self.collector_1,
                                name='Collector1_thread', args=(collector1_ready, stop_collector,))
        thr1.start()
        thr2.start()

        # Wait for both collectors to be ready
        if not collector0_ready.wait(timeout=30):
            raise Exception("Collector 0 failed to initialize")
        if not collector1_ready.wait(timeout=30):
            raise Exception("Collector 1 failed to initialize")

        if self.poll_tests:
            if self.polling_int == 0:
                time.sleep(20)
            else:
                # wait for polling time for collector to collect packets
                logging.info(
                    "Waiting for % seconds of polling interval" % self.polling_int)
                time.sleep(self.polling_int)
        else:
            self.sendTraffic()

            # Wait for packets to arrive. If we don't see any packets for 30 seconds, fail the test.
            # Otherwise, as long as packets are arriving, keep waiting.
            last_update_time = time.time()
            last_packet_count = 0
            while time.time() < last_update_time + 30:
                time.sleep(5)
                current_packet_count = 0
                for collector in self.active_col:
                    flow_count, _, _ = self.count_packets_received(collector)
                    current_packet_count += flow_count
                if current_packet_count > last_packet_count:
                    last_packet_count = current_packet_count
                    # If we're receiving packets but haven't seen all the ones we expect, just wait longer.
                    # If we've seen as many as we expect, let the timeout expire to see if we get any extra.
                    if last_packet_count < self.total_expected_flow_samples:
                        last_update_time = time.time()
                    logging.info("%s/%s packets received, waiting for more..." % (
                        last_packet_count, self.total_expected_flow_samples))
                elif last_packet_count > 0:
                    # We're not receiving any new packets, time to count the samples
                    logging.info("No new packets received, stopping...")
                    break

        stop_collector.set()
        thr1.join()
        thr2.join()
        logging.debug(self.collector0_samples)
        logging.debug(self.collector1_samples)
        self.packet_analyzer(self.collector0_samples,
                             'collector0', self.poll_tests)
        self.packet_analyzer(self.collector1_samples,
                             'collector1', self.poll_tests)
