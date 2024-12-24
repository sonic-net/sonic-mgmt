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
import json
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
import threading
import time
from collections import Counter
import logging
import ast
import subprocess


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
        self.active_col = self.test_params['active_collectors']
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

    def read_data(self, collector, event, sflow_port=['6343']):
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
            timeout = 240
            logging.info("Waiting for event to be set under {} seconds; Event is {}".format(
                timeout, event.isSet()))
            # Wait for event to be set from Main Thread or to pass out by timeout
            event_is_set = event.wait(timeout=timeout)
            logging.info("{}; Event set: {}".format(
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
    # --------------------------------------------------------------------------

    def collector_0(self, event):
        self.collector0_samples = self.read_data('collector0', event)
    # --------------------------------------------------------------------------

    def collector_1(self, event):
        self.collector1_samples = self.read_data('collector1', event, ['6344'])

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
            100 * 0.6, 100 * 1.4))
        for port in self.interfaces:
            # NOTE: hsflowd is sending index instead of ifindex.
            index = self.interfaces[port]['port_index']
            logging.info("....%s : Flow packets collected from port %s = %s" % (
                collector, port, data['flow_port_count'][index]))
            if port in self.enabled_intf:
                # Checking samples with tolerance of 40 % as the sampling is random and not deterministic.
                # Over many samples it should converge to a mean of 1:N
                # Number of packets sent = 100 * sampling rate of interface
                self.assertTrue(
                    100 * 0.6 <= data['flow_port_count'][index] <= 100 * 1.4,
                    "Expected Number of samples are not collected from Interface %s in collector %s , Received %s"
                    % (port, collector, data['flow_port_count'][index]))
            else:
                self.assertTrue(data['flow_port_count'][index] == 0,
                                "Packets are collected from Non Sflow interface %s in collector %s" % (port, collector))

    # ---------------------------------------------------------------------------

    def sendTraffic(self):
        src_ip_addr_templ = '192.168.{}.1'
        ip_dst_addr = '192.168.0.4'
        src_mac = self.dataplane.get_mac(0, 0)
        pktlen = 100
        # send 100 * sampling_rate packets in each interface for better analysis
        for _ in range(0, 100, 1):
            index = 0
            for intf in self.interfaces:
                ip_src_addr = src_ip_addr_templ.format(str(8 * index))
                src_port = self.interfaces[intf]['ptf_indices']
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
        time.sleep(1)
        stop_collector = threading.Event()
        thr1 = threading.Thread(target=self.collector_0,
                                name='Collector0_thread', args=(stop_collector,))
        thr2 = threading.Thread(target=self.collector_1,
                                name='Collector1_thread', args=(stop_collector,))
        thr1.start()
        time.sleep(2)
        thr2.start()
        # wait for the collectors to initialise
        time.sleep(5)
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
            time.sleep(10)  # For Test Stability
        stop_collector.set()
        thr1.join()
        thr2.join()
        logging.debug(self.collector0_samples)
        logging.debug(self.collector1_samples)
        self.packet_analyzer(self.collector0_samples,
                             'collector0', self.poll_tests)
        self.packet_analyzer(self.collector1_samples,
                             'collector1', self.poll_tests)
