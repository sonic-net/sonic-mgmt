#
#ptf --test-dir fast-reboot fast-reboot.FastReloadTest --platform remote --platform-dir fast-reboot --qlen 1000 -t "verbose=True;dut_username='acsadmin';dut_hostname='10.251.0.243';fast_reboot_limit=30;portchannel_ports_file='/tmp/portchannel_interfaces.json';vlan_ports_file='/tmp/vlan_interfaces.json';port_indices_file='/tmp/port_indices.json';dut_mac='4c:76:25:f4:b7:00';vlan_ip_range='172.0.0.0/26';default_ip_range='192.168.0.0/16'"
#
#
# This test measures length of DUT dataplace disruption in fast-reboot procedure.
#
# This test supposes that fast-reboot initiates by running /usr/bin/fast-reboot command.
# The test sequence are following:
# 1. Check that DUT is stable. That means that pings work in both directions: from T1 to servers and from servers to T1.
# 2. If DUT is stable the test starts continiously pinging DUT in both directions.
# 3. The test runs '/usr/bin/fast-reboot' on DUT remotely. The ssh key supposed to be uploaded by ansible before the test
# 3. As soon as it sees that ping starts failuring in one of directions the test registers a start of dataplace disruption
# 4. As soon as the test sess that pings start working for DUT in both directions it registers a stop of dataplane disruption
# 5. If the length of the disruption is less 30 seconds - the test passes


import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils
from ptf.testutils import *
from ptf.dataplane import match_exp_pkt
import datetime
import time
import subprocess
from ptf.mask import Mask
import socket
import ptf.packet as scapy
import threading
import os
import signal
import random
import struct
import socket
from pprint import pprint
import sys
import json

class FastReloadTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.log_fp = open('/tmp/fast-reboot.log', 'w')
        self.test_params = testutils.test_params_get()
        self.check_param('verbose', False,   required = False)
        self.check_param('dut_username', '', required = True)
        self.check_param('dut_hostname', '', required = True)
        self.check_param('fast_reboot_limit', 30, required = False)
        self.check_param('portchannel_ports_file', '', required = True)
        self.check_param('vlan_ports_file', '', required = True)
        self.check_param('port_indices_file', '', required = True)
        self.check_param('dut_mac', '', required = True)
        self.check_param('default_ip_range', '', required = True)

        # Default settings
        self.nr_pkts = 100
        self.nr_tests = 3
        self.reboot_delay = 10
        self.timeout_thr = None

        self.read_port_indices()
        portchannel_ports = self.read_portchannel_ports()
        vlan_ip_range = self.read_vlan_ip_range()
        vlan_ports = self.read_vlan_ports()

        self.limit = datetime.timedelta(seconds=self.test_params['fast_reboot_limit'])
        self.dut_ssh = self.test_params['dut_username'] + '@' + self.test_params['dut_hostname']
        self.dut_mac = self.test_params['dut_mac']
        #
        self.from_t1_src_addr = self.random_ip(self.test_params['default_ip_range'])
        self.from_t1_src_port = self.random_port(portchannel_ports)
        self.from_t1_dst_addr = self.random_ip(vlan_ip_range)
        self.from_t1_dst_ports = [self.random_port(vlan_ports)]
        self.from_t1_if_name = "eth%d" % self.from_t1_dst_ports[0]
        self.from_t1_if_addr = "%s/%s" % (self.from_t1_dst_addr, vlan_ip_range.split('/')[1])
        #
        self.from_server_src_addr = self.random_ip(vlan_ip_range)
        self.from_server_src_port = self.random_port(vlan_ports)
        self.from_server_dst_addr = self.random_ip(self.test_params['default_ip_range'])
        self.from_server_dst_ports = portchannel_ports

        self.log("Test params:")
        self.log("DUT ssh: %s" % self.dut_ssh)
        self.log("DUT fast-reboot limit: %s" % self.limit)
        self.log("DUT mac address: %s" % self.dut_mac)
        self.log("From T1 src addr: %s" % self.from_t1_src_addr)
        self.log("From T1 src port: %s" % self.from_t1_src_port)
        self.log("From T1 dst addr: %s" % self.from_t1_dst_addr)
        self.log("From T1 dst ports: %s" % self.from_t1_dst_ports)
        self.log("From server src addr: %s" % self.from_server_src_addr)
        self.log("From server src port: %s" % self.from_server_src_port)
        self.log("From server dst addr: %s" % self.from_server_dst_addr)
        self.log("From server dst ports: %s" % self.from_server_dst_ports)

        return

    def read_json(self, name):
        with open(self.test_params[name]) as fp:
          content = json.load(fp)

        return content

    def read_port_indices(self):
        self.port_indices = self.read_json('port_indices_file')

    def read_portchannel_ports(self):
        content = self.read_json('portchannel_ports_file')
        pc_ifaces = []
        for pc in content:
            pc_ifaces.extend([self.port_indices[member] for member in pc['members']])

        return pc_ifaces

    def read_vlan_ip_range(self):
        content = self.read_json('vlan_ports_file')
        if len(content) > 1:
            self.log('DUT has more than 1 VLANS')
        return content[0]['subnet']

    def read_vlan_ports(self):
        content = self.read_json('vlan_ports_file')

        return [self.port_indices[ifname] for ifname in content[0]['members'].split(" ")]

    def check_param(self, param, default, required = False):
        if param not in self.test_params:
            if required:
                raise Exception("Test parameter '%s' is required" % param)
            self.test_params[param] = default

    def random_ip(self, ip):
        src_addr, mask = ip.split('/')
        n_hosts = 2**(32 - int(mask))
        random_host = random.randint(2, n_hosts - 2)
        src_addr_n = struct.unpack(">I", socket.inet_aton(src_addr))[0]
        net_addr_n = src_addr_n & (2**32 - n_hosts)
        random_addr_n = net_addr_n + random_host
        random_ip = socket.inet_ntoa(struct.pack(">I", random_addr_n))

        return random_ip

    def random_port(self, ports):
        return random.choice(ports)

    def log(self, message, verbose=False):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if verbose and self.test_params['verbose'] or not verbose:
            print "%s : %s" % (current_time, message)
        self.log_fp.write("%s : %s\n" % (current_time, message))

    def timeout(self, seconds, message):
        def timeout_exception(self, message):
            self.log('Timeout is reached: %s' % message)
            os.kill(os.getpid(), signal.SIGINT)

        if self.timeout_thr is None:
            self.timeout_thr = threading.Timer(seconds, timeout_exception, args=(self, message))
            self.timeout_thr.start()
        else:
            raise Exception("Timeout already set")

    def cancel_timeout(self):
        if self.timeout_thr is not None:
            self.timeout_thr.cancel()
            self.timeout_thr = None

    def setUp(self):
        print

        self.cmd(['ifconfig', self.from_t1_if_name, self.from_t1_if_addr])
        # FIXME: Check return value for self.cmd
        self.dataplane = ptf.dataplane_instance
        for p in self.dataplane.ports.values():
            port = p.get_packet_source()
            port.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1000000)

        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        self.cmd(['ifconfig', self.from_t1_if_name, '0'])
        # FIXME: Check return value for self.cmd
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        self.log_fp.close()

    def runTest(self):
        no_routing_start = None
        no_routing_stop = None
        thr = threading.Thread(target=self.background)
        thr.setDaemon(True)

        self.log("Check that device is alive and pinging")
        self.assertTrue(self.check_alive(), 'DUT is not stable')

        self.log("Schedule to reboot the remote switch in %s sec" % self.reboot_delay)
        thr.start()

        self.log("Wait when ASIC stops")
        self.timeout(120, "DUT hasn't stopped for 120 seconds")
        no_routing_start = self.check_stop()
        self.cancel_timeout()

        self.log("ASIC was stopped, Waiting when it's up. Stop time: %s" % str(no_routing_start))
        self.timeout(120, "DUT hasn't started to work for 120 seconds")
        no_routing_stop = self.check_start()
        self.cancel_timeout() 
        self.log("ASIC works again. Start time: %s" % str(no_routing_stop))

        self.log("Downtime was %s" % str(no_routing_stop - no_routing_start))

        self.assertTrue(no_routing_stop - no_routing_start < self.limit, "Downtime must be less then %s seconds" % self.test_params['fast_reboot_limit'])

    def background(self):
        time.sleep(self.reboot_delay)

        self.log("Rebooting remote side")
        stdout, stderr, return_code = self.cmd(["ssh", self.dut_ssh, "sudo fast-reboot"])
        if stdout != []:
            self.log("stdout from fast-reboot: %s" % str(stdout))
        if stderr != []:
            self.log("stderr from fast-reboot: %s" % str(stderr))
        self.log("return code from fast-reboot: %s" % str(return_code))

        return

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def check_stop(self):
        return self.iteration(True)

    def check_start(self):
        return self.iteration(False)

    def iteration(self, is_stop):
        recorded_time = None
        counter = self.nr_tests
        while True:
            success = self.ping_iteration()
            if success and is_stop or not success and not is_stop:
                self.log("Success", True)
                recorded_time = None
            else:
                self.log("Not Success", True)
                if recorded_time is None:
                    recorded_time = datetime.datetime.now()
                if counter == 0:
                    break
                else:
                    counter -= 1

        return recorded_time

    def ping_iteration(self):
        return self.pingFromServers() > 0 and self.pingFromUpperTier() > 0

    def check_alive(self):
        counter = self.nr_tests
        while True:
            success = self.ping_alive()
            if not success:
                return False
            if counter == 0:
                break
            else:
                counter -= 1
            time.sleep(1)

        return True

    def ping_alive(self):
        nr_from_s = self.pingFromServers()
        nr_from_l = self.pingFromUpperTier()
        is_success_from_s = nr_from_s > self.nr_pkts * 0.7
        is_success_from_l = nr_from_l > self.nr_pkts * 0.7

        return is_success_from_s and is_success_from_l

    def pingFromServers(self):
        return self.ping0(self.dut_mac,
                          self.from_server_src_addr,
                          self.from_server_dst_addr,
                          self.from_server_src_port,
                          self.from_server_dst_ports,
                          "servers->t1")

    def pingFromUpperTier(self):
        return self.ping0(self.dut_mac,
                          self.from_t1_src_addr,
                          self.from_t1_dst_addr,
                          self.from_t1_src_port,
                          self.from_t1_dst_ports,
                          "t1->servers")

    def ping0(self, eth_dst, ip_src, ip_dst, from_port, to_ports, msg):
        packet = simple_tcp_packet(
                      eth_dst=eth_dst,
                      ip_src=ip_src,
                      ip_dst=ip_dst,
                      tcp_dport=5000
                 )
        exp_packet = simple_tcp_packet(
                      ip_src=ip_src,
                      ip_dst=ip_dst,
                      ip_ttl=63,
                      tcp_dport=5000,
                     )

        exp_packet = Mask(exp_packet)
        exp_packet.set_do_not_care_scapy(scapy.Ether,"src")
        exp_packet.set_do_not_care_scapy(scapy.Ether,"dst")

        for i in xrange(self.nr_pkts):
            testutils.send_packet(self, from_port, str(packet))

        total_rcv_pkt_cnt = testutils.count_matched_packets_all_ports(self, exp_packet, to_ports)

        self.log("Send %5d Received %5d %s" % (self.nr_pkts, total_rcv_pkt_cnt, msg), True)

        return total_rcv_pkt_cnt

