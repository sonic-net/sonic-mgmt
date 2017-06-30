#
#ptf --test-dir ptftests fast-reboot.FastReloadTest --platform remote --platform-dir ptftests --qlen 1000 -t "verbose=True;dut_username='acsadmin';dut_hostname='10.3.147.243';fast_reboot_limit=30;portchannel_ports_file='/tmp/portchannel_interfaces.json';vlan_ports_file='/tmp/vlan_interfaces.json';ports_file='/tmp/ports.json';dut_mac='4c:76:25:f4:b7:00';vlan_ip_range='172.0.0.0/26';default_ip_range='192.168.0.0/16';vlan_ip_range='172.0.0.0/26';arista_vms=['10.64.246.200', '10.64.246.201', '10.64.246.202', '10.64.246.203']"
#
#
# This test checks that DUT is able to make FastReboot procedure
#
# This test supposes that fast-reboot initiates by running /usr/bin/fast-reboot command.
#
# The test is using "pings". This is packets which are sent through dataplane in two directions
# 1. From one of vlan interfaces to T1 device. The source ip, source interface, and destination IP are chosen randomly from valid choices. Number of packet is 100.
# 2. From all of portchannel ports to all of vlan ports. The source ip, source interface, and destination IP are chosed sequentially from valid choices.
#    Currently we have 500 distrinct destination vlan addresses. Our target to have 1000 of them.
#
# The test sequence is following:
# 1. Check that DUT is stable. That means that "pings" work in both directions: from T1 to servers and from servers to T1.
# 2. If DUT is stable the test starts continiously pinging DUT in both directions.
# 3. The test runs '/usr/bin/fast-reboot' on DUT remotely. The ssh key supposed to be uploaded by ansible before the test
# 3. As soon as it sees that ping starts failuring in one of directions the test registers a start of dataplace disruption
# 4. As soon as the test sess that pings start working for DUT in both directions it registers a stop of dataplane disruption
# 5. If the length of the disruption is less 30 seconds (if not redefined by parameter) - the test passes
# 6. If there're any drops, when control plane is down - the test fails
# 7. When test start fast-reboot procedure it connects to all VM (which emulates T1) and starts fetching status of BGP and LACP
#    if LACP is inactive on VMs and interfaces goes down test failes
#    if BGP graceful restart timeout is not equal 120 seconds the test fails
#    if BGP graceful restart is not enabled on DUT the test fails
#    If BGP graceful restart timeout is less than 15 seconds the test fails
#    if BGP routes disappeared the test is failed

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
from fcntl import ioctl
import sys
import json
import re
from collections import defaultdict
import json
import paramiko
import Queue


class Arista(object):
    def __init__(self, ip, queue, login='admin', password='123456'):
        self.ip = ip
        self.queue = queue
        self.login = login
        self.password = password
        self.conn = None
        self.hostname = None
        self.fails = set()

    def __del__(self):
        self.disconnect()

    def connect(self):
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.conn.connect(self.ip, username=self.login, password=self.password, allow_agent=False, look_for_keys=False)
        self.shell = self.conn.invoke_shell()

        first_prompt = self.do_cmd(None, prompt = '>')
        self.hostname = self.extract_hostname(first_prompt)

        self.do_cmd('enable')
        self.do_cmd('terminal length 0')

        return self.shell

    def extract_hostname(self, first_prompt):
        lines = first_prompt.split('\n')
        prompt = lines[-1]
        return prompt.strip().replace('>', '#')

    def do_cmd(self, cmd, prompt = None):
        if prompt == None:
            prompt = self.hostname

        if cmd is not None:
            self.shell.send(cmd + '\n')

        input_buffer = ''
        while prompt not in input_buffer:
            input_buffer += self.shell.recv(16384)

        return input_buffer

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

        return

    def run(self, lo_prefix='10.1.0.32/32', vlan_prefix='172.0.0.0/22'):
        data = {}
        bgp_once = False
        self.connect()
        while True:
            cmd = self.queue.get()
            if cmd == 'quit':
                break
            cur_time = time.time()
            info = {}
            lacp_output = self.do_cmd('show lacp neighbor')
            info['lacp'] = self.parse_lacp(lacp_output)
            bgp_neig_output = self.do_cmd('show ip bgp neighbors')
            info['bgp_neig'] = self.parse_bgp_neig(bgp_neig_output)
            if not bgp_once:
                self.ipv4_gr_enabled, self.ipv6_gr_enabled, self.gr_timeout = self.parse_bgp_neig_once(bgp_neig_output)
                bgp_once = True
            bgp_route_output = self.do_cmd('show ip route bgp')
            info['bgp_route'] = self.parse_bgp_route(bgp_route_output, lo_prefix, vlan_prefix)
            data[cur_time] = info

        self.disconnect()

        return self.test_all_client_cases(data)

    def parse_lacp(self, output):
        return output.find('Bundled') != -1

    def parse_bgp_neig_once(self, output):
        is_gr_ipv4_enabled = False
        is_gr_ipv6_enabled = False
        restart_time = None
        for line in output.split('\n'):
            if '     Restart-time is' in line:
                restart_time = int(line.replace('       Restart-time is ', ''))
                continue

            if 'is enabled, Forwarding State is' in line:
                if 'IPv6' in line:
                    is_gr_ipv6_enabled = True
                elif 'IPv4' in line:
                    is_gr_ipv4_enabled = True

        return is_gr_ipv4_enabled, is_gr_ipv6_enabled, restart_time

    def parse_bgp_neig(self, output):
        gr_active = None
        gr_timer = None
        for line in output.split('\n'):
            if 'Restart timer is' in line:
                gr_active = 'is active' in line
                gr_timer = str(line[-9:-1])

        return gr_active, gr_timer

    def parse_bgp_route(self, output, lo_prefix, vlan_prefix):
        lo_route = None
        lo_valid = None
        lo_nexthop = None
        vlan_route = None
        vlan_valid = None
        vlan_nexthop = None
        for line in output.split('\n'):
            line = str(line.strip())
            if line.startswith('B'):
                interface = line.split(', ')[-1]
                if lo_prefix in line:
                    lo_route = True
                    lo_valid = 'Port-Channel' in interface
                    lo_nexthop = interface
                elif vlan_prefix in line:
                    vlan_route = True
                    vlan_valid = 'Port-Channel' in interface
                    vlan_nexthop = interface

        return [('lo', lo_route, lo_valid, lo_prefix, lo_nexthop), ('vlan', vlan_route, vlan_valid, vlan_prefix, vlan_nexthop)]

    def test_all_client_cases(self, output):
        # [0] True 'ipv4_gr_enabled', [1] doesn't matter 'ipv6_enabled', [2] should be >= 120
        if not self.ipv4_gr_enabled:
            self.fails.add("bgp ipv4 graceful restart is not enabled")
        if not self.ipv6_gr_enabled:
            pass # ToDo:
        if self.gr_timeout < 120: # bgp graceful restart timeout less then 120 seconds
            self.fails.add("bgp graceful restart timeout is less then 120 seconds")

        for when, other in sorted(output.items()):
            lacp_bundled = other['lacp']
            # Should be true always
            if not lacp_bundled:
                self.fails.add("PortChannel bundle was down")

            gr_active, timer = other['bgp_neig']
            # wnen it's False, it's ok, wnen it's True, check that inactivity timer not less then 15 seconds
            if gr_active and datetime.datetime.strptime(timer, '%H:%M:%S') < datetime.datetime(1900, 1, 1, second = 15):
                self.fails.add("graceful restart timer is almost finished. Less then 15 seconds left")
            bgp_route_results = other['bgp_route']
            # check that route is present [0] = True, is valid [1] = True. if it's not show
            for iface, r_exists, r_valid, r_prefix, r_nexthop in bgp_route_results:
                if not r_exists:
                    self.fails.add("route for %s prefix %s does not exist" % (iface, r_prefix))
                elif not r_valid:
                    self.fails.add("route for %s prefix %s points to wrong interface %s" % (iface, r_prefix, r_nexthop))

        return self.fails


class FastReloadTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.fails = {}
        self.log_fp = open('/tmp/fast-reboot.log', 'w')
        self.test_params = testutils.test_params_get()
        self.check_param('verbose', False,   required = False)
        self.check_param('dut_username', '', required = True)
        self.check_param('dut_hostname', '', required = True)
        self.check_param('fast_reboot_limit', 30, required = False)
        self.check_param('graceful_limit', 120, required = False)
        self.check_param('portchannel_ports_file', '', required = True)
        self.check_param('vlan_ports_file', '', required = True)
        self.check_param('ports_file', '', required = True)
        self.check_param('dut_mac', '', required = True)
        self.check_param('default_ip_range', '', required = True)
        self.check_param('vlan_ip_range', '', required = True)
        self.check_param('lo_prefix', '10.1.0.32/32', required = False)
        self.check_param('arista_vms', [], required = True)

        # Default settings
        self.nr_pc_pkts = 100
        self.nr_tests = 3
        self.reboot_delay = 10
        self.task_timeout = 300   # Wait up to 5 minutes for tasks to complete
        self.max_nr_vl_pkts = 500 # FIXME: should be 1000. But bcm asic is not stable
        self.timeout_thr = None

        return

    def read_json(self, name):
        with open(self.test_params[name]) as fp:
          content = json.load(fp)

        return content

    def read_port_indices(self):
        self.port_indices = self.read_json('ports_file')

        return

    def read_portchannel_ports(self):
        content = self.read_json('portchannel_ports_file')
        pc_ifaces = []
        for pc in content.values():
            pc_ifaces.extend([self.port_indices[member] for member in pc['members']])

        return pc_ifaces

    def read_vlan_ports(self):
        content = self.read_json('vlan_ports_file')
        if len(content) > 1:
            raise "Too many vlans"
        return [self.port_indices[ifname] for ifname in content.values()[0]['members']]

    def check_param(self, param, default, required = False):
        if param not in self.test_params:
            if required:
                raise Exception("Test parameter '%s' is required" % param)
            self.test_params[param] = default

    def random_ip(self, ip):
        net_addr, mask = ip.split('/')
        n_hosts = 2**(32 - int(mask))
        random_host = random.randint(2, n_hosts - 2)
        return self.host_ip(ip, random_host)

    def host_ip(self, net_ip, host_number):
        src_addr, mask = net_ip.split('/')
        n_hosts = 2**(32 - int(mask))
        if host_number > (n_hosts - 2):
            raise Exception("host number %d is greater than number of hosts %d in the network %s" % (host_number, n_hosts - 2, net_ip))
        src_addr_n = struct.unpack(">I", socket.inet_aton(src_addr))[0]
        net_addr_n = src_addr_n & (2**32 - n_hosts)
        host_addr_n = net_addr_n + host_number
        host_ip = socket.inet_ntoa(struct.pack(">I", host_addr_n))

        return host_ip

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
            self.tearDown()
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
        self.read_port_indices()
        self.portchannel_ports = self.read_portchannel_ports()
        vlan_ip_range = self.test_params['vlan_ip_range']
        self.vlan_ports = self.read_vlan_ports()

        self.limit = datetime.timedelta(seconds=self.test_params['fast_reboot_limit'])
        self.dut_ssh = self.test_params['dut_username'] + '@' + self.test_params['dut_hostname']
        self.dut_mac = self.test_params['dut_mac']
        #
        self.nr_vl_pkts = self.generate_from_t1()

        self.log("Test params:")
        self.log("DUT ssh: %s" % self.dut_ssh)
        self.log("DUT fast-reboot limit: %s" % self.limit)
        self.log("DUT mac address: %s" % self.dut_mac)

        self.log("From server src addr: %s" % self.from_server_src_addr)
        self.log("From server src port: %s" % self.from_server_src_port)
        self.log("From server dst addr: %s" % self.from_server_dst_addr)
        self.log("From server dst ports: %s" % self.from_server_dst_ports)
        self.log("From upper layer number of packets: %d" % self.nr_vl_pkts)

        self.dataplane = ptf.dataplane_instance
        for p in self.dataplane.ports.values():
            port = p.get_packet_source()
            port.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1000000)

        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

        self.log("Enabling arp_responder")
        self.cmd(["supervisorctl", "start", "arp_responder"])

        return

    def tearDown(self):
        self.log("Disabling arp_responder")
        self.cmd(["supervisorctl", "stop", "arp_responder"])
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        self.log_fp.close()

    def get_if(self, iff, cmd):
        s = socket.socket()
        ifreq = ioctl(s, cmd, struct.pack("16s16x",iff))
        s.close()

        return ifreq

    def get_mac(self, iff):
        SIOCGIFHWADDR = 0x8927          # Get hardware address
        return ':'.join(['%02x' % ord(char) for char in self.get_if(iff, SIOCGIFHWADDR)[18:24]])

    def generate_from_t1(self):
        self.from_t1 = []

        vlan_ip_range = self.test_params['vlan_ip_range']

        _, mask = vlan_ip_range.split('/')
        n_hosts = min(2**(32 - int(mask)) - 3, self.max_nr_vl_pkts)

        dump = defaultdict(dict)
        counter = 0
        for i in xrange(2, n_hosts + 2):
            from_t1_src_addr = self.random_ip(self.test_params['default_ip_range'])
            from_t1_src_port = self.random_port(self.portchannel_ports)
            from_t1_dst_addr = self.host_ip(vlan_ip_range, i)
            from_t1_dst_port = self.vlan_ports[i % len(self.vlan_ports)]
            from_t1_if_name = "eth%d" % from_t1_dst_port
            from_t1_if_addr = "%s/%s" % (from_t1_dst_addr, vlan_ip_range.split('/')[1])
            vlan_mac_hex = '72060001%04x' % counter
            lag_mac_hex = '5c010203%04x' % counter
            mac_addr = ':'.join(lag_mac_hex[i:i+2] for i in range(0, len(lag_mac_hex), 2))
            packet = simple_tcp_packet(
                      eth_src=mac_addr,
                      eth_dst=self.dut_mac,
                      ip_src=from_t1_src_addr,
                      ip_dst=from_t1_dst_addr,
                      ip_ttl=255,
                      tcp_dport=5000
            )
            self.from_t1.append((from_t1_src_port, str(packet)))
            dump[from_t1_if_name][from_t1_dst_addr] = vlan_mac_hex
            counter += 1

        exp_packet = simple_tcp_packet(
                      ip_src="0.0.0.0",
                      ip_dst="0.0.0.0",
                      tcp_dport=5000,
        )

        self.from_t1_exp_packet = Mask(exp_packet)
        self.from_t1_exp_packet.set_do_not_care_scapy(scapy.Ether, "src")
        self.from_t1_exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
        self.from_t1_exp_packet.set_do_not_care_scapy(scapy.IP, "src")
        self.from_t1_exp_packet.set_do_not_care_scapy(scapy.IP, "dst")
        self.from_t1_exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
        self.from_t1_exp_packet.set_do_not_care_scapy(scapy.TCP, "chksum")
        self.from_t1_exp_packet.set_do_not_care_scapy(scapy.IP, "ttl")

        # save data for arp_replay process
        with open("/tmp/from_t1.json", "w") as fp:
            json.dump(dump, fp)

        random_vlan_iface = random.choice(dump.keys())
        self.from_server_src_port = int(random_vlan_iface.replace('eth',''))
        self.from_server_src_addr = random.choice(dump[random_vlan_iface].keys())
        self.from_server_dst_addr = self.random_ip(self.test_params['default_ip_range'])
        self.from_server_dst_ports = self.portchannel_ports

        return n_hosts

    def runTest(self):
        self.reboot_start = None
        no_routing_start = None
        no_routing_stop = None

        arista_vms = self.test_params['arista_vms'][1:-1].split(",")
        ssh_targets = [vm[1:-1] for vm in arista_vms]

        self.ssh_jobs = []
        for addr in ssh_targets:
            q = Queue.Queue()
            thr = threading.Thread(target=self.ssh_job, kwargs={'ip': addr, 'queue': q})
            thr.setDaemon(True)
            self.ssh_jobs.append((thr, q))
            thr.start()

        thr = threading.Thread(target=self.background)
        thr.setDaemon(True)
        self.log("Check that device is alive and pinging")
        self.assertTrue(self.check_alive(), 'DUT is not stable')

        self.log("Schedule to reboot the remote switch in %s sec" % self.reboot_delay)
        thr.start()

        self.log("Wait until ASIC stops")
        self.timeout(self.task_timeout, "DUT hasn't stopped in %d seconds" % self.task_timeout)
        no_routing_start, upper_replies = self.check_stop()
        self.cancel_timeout()

        self.log("ASIC was stopped, Waiting until it's up. Stop time: %s" % str(no_routing_start))
        self.timeout(self.task_timeout, "DUT hasn't started to work for %d seconds" % self.task_timeout)
        no_routing_stop, _ = self.check_start()
        self.cancel_timeout()

        for thr, q in self.ssh_jobs:
            q.put('quit')
            thr.join()

        no_cp_replies = self.extract_no_cpu_replies(upper_replies)

        self.log("ASIC works again. Start time: %s" % str(no_routing_stop))

        self.log("Downtime was %s" % str(no_routing_stop - no_routing_start))
        self.log("Reboot time was %s" % str(no_routing_stop - self.reboot_start))
        self.log("Number replies when control plane was down: %d Expected: %d" % (no_cp_replies, self.nr_vl_pkts))

        self.fails['dut'] = set()
        if no_routing_stop - no_routing_start > self.limit:
            self.fails['dut'].add("Downtime must be less then %s seconds" % self.test_params['fast_reboot_limit'])
        if no_routing_stop - self.reboot_start > datetime.timedelta(seconds=self.test_params['graceful_limit']):
            self.fails['dut'].add("Fast-reboot cycle must be less then graceful limit %s seconds" % self.test_params['graceful_limit'])
        if no_cp_replies < 0.95 * self.nr_vl_pkts:
            self.fails['dut'].add("Dataplane didn't route to all servers, when control-plane was down: %d vs %d" % (no_cp_replies, self.nr_vl_pkts))

        is_good = True
        for name, fails in self.fails.items():
            if len(fails) > 0:
                is_good = False
            for fail in fails:
                self.log("FAILED:%s:%s" % (name, fail))

        self.assertTrue(is_good, "Something went wrong. Please check output above")

    def extract_no_cpu_replies(self, arr):
      """
      This function tries to extract number of replies from dataplane, when control plane is non working
      """
      # remove all tail zero values
      non_zero = filter(lambda x : x > 0, arr)

      # check that last value is different from previos
      if len(non_zero) > 1 and non_zero[-1] < non_zero[-2]:
          return non_zero[-2]
      else:
          return non_zero[-1]

    def background(self):
        time.sleep(self.reboot_delay)

        self.log("Rebooting remote side")
        self.reboot_start = datetime.datetime.now()
        stdout, stderr, return_code = self.cmd(["ssh", "-oStrictHostKeyChecking=no", self.dut_ssh, "sudo fast-reboot"])
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

    def ssh_job(self, ip, queue):
        ssh = Arista(ip, queue)
        self.fails[ip] = ssh.run(self.test_params['lo_prefix'], self.test_params['vlan_ip_range'])

    def check_stop(self):
        return self.iteration(True)

    def check_start(self):
        return self.iteration(False)

    def iteration(self, is_stop):
        recorded_time = None
        counter = self.nr_tests
        nr_from_upper_array = []
        while True:
            success, nr_from_upper = self.ping_iteration()
            nr_from_upper_array.append(nr_from_upper)
            for _, q in self.ssh_jobs:
                q.put('go')
            if success and is_stop or not success and not is_stop:
                self.log("Base state", True)
                recorded_time = None
            else:
                self.log("Changed state", True)
                if recorded_time is None:
                    recorded_time = datetime.datetime.now()
                if counter == 0:
                    break
                else:
                    counter -= 1

        return recorded_time, nr_from_upper_array

    def ping_iteration(self):
        nr_from_servers = self.pingFromServers()
        if nr_from_servers > 0:
            nr_from_upper = self.pingFromUpperTier()
        else:
            nr_from_upper = 0
        return nr_from_servers > 0 and nr_from_upper > 0, nr_from_upper

    def check_alive(self):
        # This function checks that DUT routes packets in both directions.
        #
        # Sometimes first attempt failes because ARP response to DUT is not so fast.
        # But after this the functions expects to see "replies" on at least 50% of requests.
        # If the function sees that there is some issue with dataplane after we see successful replies
        # it consider that DUT is not healthy too
        was_alive = 0
        for counter in range(self.nr_tests * 2):
            success = self.ping_alive()
            if success:
              was_alive += 1
            else:
              if was_alive > 0:
                return False    # Stopped working after it working for sometime?

        return was_alive > self.nr_tests

    def ping_alive(self):
        nr_from_s = self.pingFromServers()
        nr_from_l = self.pingFromUpperTier()
        is_success_from_s = nr_from_s > self.nr_pc_pkts * 0.7
        is_success_from_l = nr_from_l > self.nr_vl_pkts * 0.7

        return is_success_from_s and is_success_from_l

    def pingFromServers(self):
        packet = simple_tcp_packet(
                      eth_dst=self.dut_mac,
                      ip_src=self.from_server_src_addr,
                      ip_dst=self.from_server_dst_addr,
                      tcp_dport=5000
                 )
        exp_packet = simple_tcp_packet(
                      ip_src=self.from_server_src_addr,
                      ip_dst=self.from_server_dst_addr,
                      ip_ttl=63,
                      tcp_dport=5000,
                     )

        exp_packet = Mask(exp_packet)
        exp_packet.set_do_not_care_scapy(scapy.Ether,"src")
        exp_packet.set_do_not_care_scapy(scapy.Ether,"dst")

        raw_packet = str(packet)

        for i in xrange(self.nr_pc_pkts):
            testutils.send_packet(self, self.from_server_src_port, raw_packet)

        total_rcv_pkt_cnt = testutils.count_matched_packets_all_ports(self, exp_packet, self.from_server_dst_ports, timeout=0.5)

        self.log("Send %5d Received %5d servers->t1" % (self.nr_pc_pkts, total_rcv_pkt_cnt), True)

        return total_rcv_pkt_cnt

    def pingFromUpperTier(self):
        for entry in self.from_t1:
            testutils.send_packet(self, *entry)

        total_rcv_pkt_cnt = testutils.count_matched_packets_all_ports(self, self.from_t1_exp_packet, self.vlan_ports, timeout=0.5)

        self.log("Send %5d Received %5d t1->servers" % (self.nr_vl_pkts, total_rcv_pkt_cnt), True)

        return total_rcv_pkt_cnt
