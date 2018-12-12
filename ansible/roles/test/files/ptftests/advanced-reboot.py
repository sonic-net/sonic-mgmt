#
#ptf --test-dir ptftests fast-reboot --qlen=1000 --platform remote -t 'verbose=True;dut_username="admin";dut_hostname="10.0.0.243";reboot_limit_in_seconds=30;portchannel_ports_file="/tmp/portchannel_interfaces.json";vlan_ports_file="/tmp/vlan_interfaces.json";ports_file="/tmp/ports.json";dut_mac="4c:76:25:f5:48:80";default_ip_range="192.168.0.0/16";vlan_ip_range="172.0.0.0/22";arista_vms="[\"10.0.0.200\",\"10.0.0.201\",\"10.0.0.202\",\"10.0.0.203\"]"' --platform-dir ptftests --disable-vxlan --disable-geneve --disable-erspan --disable-mpls --disable-nvgre
#
#
# This test checks that DUT is able to make FastReboot procedure
#
# This test supposes that fast-reboot/warm-reboot initiates by running /usr/bin/{fast,warm}-reboot command.
#
# The test uses "pings". The "pings" are packets which are sent through dataplane in two directions
# 1. From one of vlan interfaces to T1 device. The source ip, source interface, and destination IP are chosen randomly from valid choices. Number of packet is 100.
# 2. From all of portchannel ports to all of vlan ports. The source ip, source interface, and destination IP are chosed sequentially from valid choices.
#    Currently we have 500 distrinct destination vlan addresses. Our target to have 1000 of them.
#
# The test sequence is following:
# 1. Check that DUT is stable. That means that "pings" work in both directions: from T1 to servers and from servers to T1.
# 2. If DUT is stable the test starts continiously pinging DUT in both directions.
# 3. The test runs '/usr/bin/{fast,warm}-reboot' on DUT remotely. The ssh key supposed to be uploaded by ansible before the test
# 4. As soon as it sees that ping starts failuring in one of directions the test registers a start of dataplace disruption
# 5. As soon as the test sees that pings start working for DUT in both directions it registers a stop of dataplane disruption
# 6. If the length of the disruption is less than 30 seconds (if not redefined by parameter) - the test passes
# 7. If there're any drops, when control plane is down - the test fails
# 8. When test start reboot procedure it connects to all VM (which emulates T1) and starts fetching status of BGP and LACP
#    LACP is supposed to be down for one time only, if not - the test fails
#    if default value of BGP graceful restart timeout is less than 120 seconds the test fails
#    if BGP graceful restart is not enabled on DUT the test fails
#    If BGP graceful restart timeout value is almost exceeded (less than 15 seconds) the test fails
#    if BGP routes disappeares more then once, the test failed
#
# The test expects you're running the test with link state propagation helper.
# That helper propagate a link state from fanout switch port to corresponding VM port
#

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
import thread
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
import pickle
from operator import itemgetter


class Arista(object):
    DEBUG = False
    def __init__(self, ip, queue, test_params, login='admin', password='123456'):
        self.ip = ip
        self.queue = queue
        self.login = login
        self.password = password
        self.conn = None
        self.hostname = None
        self.v4_routes = [test_params['vlan_ip_range'], test_params['lo_prefix']]
        self.v6_routes = [test_params['lo_v6_prefix']]
        self.fails = set()
        self.info = set()
        self.min_bgp_gr_timeout = int(test_params['min_bgp_gr_timeout'])

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

    def run(self):
        data = {}
        debug_data = {}
        run_once = False
        log_first_line = None
        quit_enabled = False
        routing_works = True
        self.connect()
        while not (quit_enabled and v4_routing_ok and v6_routing_ok):
            cmd = self.queue.get()
            if cmd == 'quit':
                quit_enabled = True
                continue
            cur_time = time.time()
            info = {}
            debug_info = {}
            lacp_output = self.do_cmd('show lacp neighbor')
            info['lacp'] = self.parse_lacp(lacp_output)
            bgp_neig_output = self.do_cmd('show ip bgp neighbors')
            info['bgp_neig'] = self.parse_bgp_neighbor(bgp_neig_output)

            bgp_route_v4_output = self.do_cmd('show ip route bgp | json')
            v4_routing_ok = self.parse_bgp_route(bgp_route_v4_output, self.v4_routes)
            info['bgp_route_v4'] = v4_routing_ok

            bgp_route_v6_output = self.do_cmd("show ipv6 route bgp | json")
            v6_routing_ok = self.parse_bgp_route(bgp_route_v6_output, self.v6_routes)
            info["bgp_route_v6"] = v6_routing_ok

            if not run_once:
                self.ipv4_gr_enabled, self.ipv6_gr_enabled, self.gr_timeout = self.parse_bgp_neighbor_once(bgp_neig_output)
                if self.gr_timeout is not None:
                    log_first_line = "session_begins_%f" % cur_time
                    self.do_cmd("send log message %s" % log_first_line)
                    run_once = True

            data[cur_time] = info
            if self.DEBUG:
                debug_data[cur_time] = {
                    'show lacp neighbor' : lacp_output,
                    'show ip bgp neighbors' : bgp_neig_output,
                    'show ip route bgp' : bgp_route_v4_output,
                    'show ipv6 route bgp' : bgp_route_v6_output,
                }

        attempts = 60
        for _ in range(attempts):
            log_output = self.do_cmd("show log | begin %s" % log_first_line)
            log_lines = log_output.split("\r\n")[1:-1]
            log_data = self.parse_logs(log_lines)
            if len(log_data) != 0:
                break
            time.sleep(1) # wait until logs are populated

        if len(log_data) == 0:
            log_data['error'] = 'Incomplete output'

        self.disconnect()

        # save data for troubleshooting
        with open("/tmp/%s.data.pickle" % self.ip, "w") as fp:
            pickle.dump(data, fp)

        # save debug data for troubleshooting
        if self.DEBUG:
            with open("/tmp/%s.raw.pickle" % self.ip, "w") as fp:
                pickle.dump(debug_data, fp)
            with open("/tmp/%s.logging" % self.ip, "w") as fp:
                fp.write("\n".join(log_lines))

        self.check_gr_peer_status(data)
        cli_data = {}
        cli_data['lacp']   = self.check_series_status(data, "lacp",         "LACP session")
        cli_data['bgp_v4'] = self.check_series_status(data, "bgp_route_v4", "BGP v4 routes")
        cli_data['bgp_v6'] = self.check_series_status(data, "bgp_route_v6", "BGP v6 routes")
        cli_data['po']     = self.check_change_time(samples, "po_changetime", "PortChannel interface")

        return self.fails, self.info, cli_data, log_data

    def extract_from_logs(self, regexp, data):
        raw_data = []
        result = defaultdict(list)
        initial_time = -1
        re_compiled = re.compile(regexp)
        for line in data:
            m = re_compiled.match(line)
            if not m:
                continue
            raw_data.append((datetime.datetime.strptime(m.group(1), "%b %d %X"), m.group(2), m.group(3)))

        if len(raw_data) > 0:
            initial_time = raw_data[0][0]
            for when, what, status in raw_data:
                offset = (when - initial_time if when > initial_time else initial_time - when).seconds
                result[what].append((offset, status))

        return result, initial_time

    def parse_logs(self, data):
        result = {}
        bgp_r = r'^(\S+\s+\d+\s+\S+) \S+ Rib: %BGP-5-ADJCHANGE: peer (\S+) .+ (\S+)$'
        result_bgp, initial_time_bgp = self.extract_from_logs(bgp_r, data)
        if_r = r'^(\S+\s+\d+\s+\S+) \S+ Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface (\S+), changed state to (\S+)$'
        result_if, initial_time_if = self.extract_from_logs(if_r, data)

        if initial_time_bgp == -1 or initial_time_if == -1:
            return result

        for events in result_bgp.values():
            if events[-1][1] != 'Established':
                return result

        # first state is Idle, last state is Established
        for events in result_bgp.values():
            if len(events) > 1:
                assert(events[0][1] != 'Established')

            assert(events[-1][1] == 'Established')

        # first state is down, last state is up
        for events in result_if.values():
            assert(events[0][1] == 'down')
            assert(events[-1][1] == 'up')

        po_name = [ifname for ifname in result_if.keys() if 'Port-Channel' in ifname][0]
        neigh_ipv4 = [neig_ip for neig_ip in result_bgp.keys() if '.' in neig_ip][0]

        result['PortChannel was down (seconds)'] = result_if[po_name][-1][0] - result_if[po_name][0][0]
        for if_name in sorted(result_if.keys()):
            result['Interface %s was down (times)' % if_name] = map(itemgetter(1), result_if[if_name]).count("down")

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was down (seconds)" if ':' in neig_ip else "BGP IPv4 was down (seconds)"
            result[key] = result_bgp[neig_ip][-1][0] - result_bgp[neig_ip][0][0]

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was down (times)" if ':' in neig_ip else "BGP IPv4 was down (times)"
            result[key] = map(itemgetter(1), result_bgp[neig_ip]).count("Idle")

        bgp_po_offset = (initial_time_if - initial_time_bgp if initial_time_if > initial_time_bgp else initial_time_bgp - initial_time_if).seconds
        result['PortChannel went down after bgp session was down (seconds)'] = bgp_po_offset + result_if[po_name][0][0]

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was gotten up after Po was up (seconds)" if ':' in neig_ip else "BGP IPv4 was gotten up after Po was up (seconds)"
            result[key] = result_bgp[neig_ip][-1][0] - bgp_po_offset - result_if[po_name][-1][0]

        return result

    def parse_lacp(self, output):
        return output.find('Bundled') != -1

    def parse_bgp_neighbor_once(self, output):
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

    def parse_bgp_neighbor(self, output):
        gr_active = None
        gr_timer = None
        for line in output.split('\n'):
            if 'Restart timer is' in line:
                gr_active = 'is active' in line
                gr_timer = str(line[-9:-1])

        return gr_active, gr_timer

    def parse_bgp_route(self, output, expects):
        prefixes = set()
        data = "\n".join(output.split("\r\n")[1:-1])
        obj = json.loads(data)

        if "vrfs" in obj and "default" in obj["vrfs"]:
            obj = obj["vrfs"]["default"]
        for prefix, attrs in obj["routes"].items():
            if "routeAction" not in attrs or attrs["routeAction"] != "forward":
                continue
            if all("Port-Channel" in via["interface"] for via in attrs["vias"]):
                prefixes.add(prefix)

        return set(expects) == prefixes

    def check_gr_peer_status(self, output):
        # [0] True 'ipv4_gr_enabled', [1] doesn't matter 'ipv6_enabled', [2] should be >= 120
        if not self.ipv4_gr_enabled:
            self.fails.add("bgp ipv4 graceful restart is not enabled")
        if not self.ipv6_gr_enabled:
            pass # ToDo:
        if self.gr_timeout < 120: # bgp graceful restart timeout less then 120 seconds
            self.fails.add("bgp graceful restart timeout is less then 120 seconds")

        for when, other in sorted(output.items(), key = lambda x : x[0]):
            gr_active, timer = other['bgp_neig']
            # wnen it's False, it's ok, wnen it's True, check that inactivity timer not less then self.min_bgp_gr_timeout seconds
            if gr_active and datetime.datetime.strptime(timer, '%H:%M:%S') < datetime.datetime(1900, 1, 1, second = self.min_bgp_gr_timeout):
                self.fails.add("graceful restart timer is almost finished. Less then %d seconds left" % self.min_bgp_gr_timeout)

    def check_series_status(self, output, entity, what):
        # find how long anything was down
        # Input parameter is a dictionary when:status
        # constraints:
        # entity must be down just once
        # entity must be up when the test starts
        # entity must be up when the test stops

        sorted_keys = sorted(output.keys())
        if not output[sorted_keys[0]][entity]:
            self.fails.add("%s must be up when the test starts" % what)
            return 0, 0
        if not output[sorted_keys[-1]][entity]:
            self.fails.add("%s must be up when the test stops" % what)
            return 0, 0

        start = sorted_keys[0]
        cur_state = True
        res = defaultdict(list)
        for when in sorted_keys[1:]:
            if cur_state != output[when][entity]:
                res[cur_state].append(when - start)
                start = when
                cur_state = output[when][entity]
        res[cur_state].append(when - start)

        is_down_count = len(res[False])

        if is_down_count > 1:
            self.info.add("%s must be down just for once" % what)

        return is_down_count, sum(res[False]) # summary_downtime

    def check_change_time(self, output, entity, what):
        # find last changing time updated, if no update, the entity is never changed
        # Input parameter is a dictionary when:last_changing_time
        # constraints:
        # the dictionary `output` cannot be empty
        sorted_keys = sorted(output.keys())
        if not output:
            self.fails.add("%s cannot be empty" % what)
            return 0, 0

        start = sorted_keys[0]
        prev_time = output[start]
        change_count = 0
        for when in sorted_keys[1:]:
            if prev_time != output[when][entity]:
                prev_time = output[when][entity]
                change_count += 1

        if change_count > 0:
            self.info.add("%s state changed %d times" % (what, change_count))

        # Note: the first item is a placeholder
        return 0, change_count

class ReloadTest(BaseTest):
    TIMEOUT = 0.5
    def __init__(self):
        BaseTest.__init__(self)
        self.fails = {}
        self.info = {}
        self.cli_info = {}
        self.logs_info = {}
        self.log_fp = open('/tmp/reboot.log', 'w')
        self.test_params = testutils.test_params_get()
        self.check_param('verbose', False,   required = False)
        self.check_param('dut_username', '', required = True)
        self.check_param('dut_hostname', '', required = True)
        self.check_param('reboot_limit_in_seconds', 30, required = False)
        self.check_param('reboot_type', 'fast-reboot', required = False)
        self.check_param('graceful_limit', 120, required = False)
        self.check_param('portchannel_ports_file', '', required = True)
        self.check_param('vlan_ports_file', '', required = True)
        self.check_param('ports_file', '', required = True)
        self.check_param('dut_mac', '', required = True)
        self.check_param('dut_vlan_ip', '', required = True)
        self.check_param('default_ip_range', '', required = True)
        self.check_param('vlan_ip_range', '', required = True)
        self.check_param('lo_prefix', '10.1.0.32/32', required = False)
        self.check_param('lo_v6_prefix', 'fc00:1::/64', required = False)
        self.check_param('arista_vms', [], required = True)
        self.check_param('min_bgp_gr_timeout', 15, required = False)

        # Default settings
        self.ping_dut_pkts = 10
        self.nr_pc_pkts = 100
        self.nr_tests = 3
        self.reboot_delay = 10
        self.task_timeout = 300   # Wait up to 5 minutes for tasks to complete
        self.max_nr_vl_pkts = 500 # FIXME: should be 1000.
                                  # But ptf is not fast enough + swss is slow for FDB and ARP entries insertions
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

        self.limit = datetime.timedelta(seconds=self.test_params['reboot_limit_in_seconds'])
        self.reboot_type = self.test_params['reboot_type']
        if self.reboot_type not in ['fast-reboot', 'warm-reboot']:
            raise ValueError('Not supported reboot_type %s' % self.reboot_type)
        self.dut_ssh = self.test_params['dut_username'] + '@' + self.test_params['dut_hostname']
        self.dut_mac = self.test_params['dut_mac']
        #
        self.generate_from_t1()
        self.generate_from_vlan()
        self.generate_ping_dut_vlan_intf()

        self.log("Test params:")
        self.log("DUT ssh: %s" % self.dut_ssh)
        self.log("DUT reboot limit in seconds: %s" % self.limit)
        self.log("DUT mac address: %s" % self.dut_mac)

        self.log("From server src addr: %s" % self.from_server_src_addr)
        self.log("From server src port: %s" % self.from_server_src_port)
        self.log("From server dst addr: %s" % self.from_server_dst_addr)
        self.log("From server dst ports: %s" % self.from_server_dst_ports)
        self.log("From upper layer number of packets: %d" % self.nr_vl_pkts)
        self.log("VMs: %s" % str(self.test_params['arista_vms']))

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

        self.nr_vl_pkts = n_hosts

        return

    def generate_from_vlan(self):
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

        self.from_vlan_exp_packet = Mask(exp_packet)
        self.from_vlan_exp_packet.set_do_not_care_scapy(scapy.Ether,"src")
        self.from_vlan_exp_packet.set_do_not_care_scapy(scapy.Ether,"dst")

        self.from_vlan_packet = str(packet)

        return

    def generate_ping_dut_vlan_intf(self):
        packet = simple_icmp_packet(eth_dst=self.dut_mac,
                                    ip_src=self.from_server_src_addr,
                                    ip_dst=self.test_params['dut_vlan_ip'])

        exp_packet = simple_icmp_packet(eth_src=self.dut_mac,
                                        ip_src=self.test_params['dut_vlan_ip'],
                                        ip_dst=self.from_server_src_addr,
                                        icmp_type='echo-reply')


        self.ping_dut_exp_packet  = Mask(exp_packet)
        self.ping_dut_exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
        self.ping_dut_exp_packet.set_do_not_care_scapy(scapy.IP, "id")
        self.ping_dut_exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")

        self.ping_dut_packet = str(packet)

    def runTest(self):
        self.reboot_start = None
        no_routing_start = None
        no_routing_stop = None

        arista_vms = self.test_params['arista_vms'][1:-1].split(",")
        ssh_targets = []
        for vm in arista_vms:
            if (vm.startswith("'") or vm.startswith('"')) and (vm.endswith("'") or vm.endswith('"')):
                ssh_targets.append(vm[1:-1])
            else:
                ssh_targets.append(vm)

        self.log("Converted addresses VMs: %s" % str(ssh_targets))

        self.ssh_jobs = []
        for addr in ssh_targets:
            q = Queue.Queue()
            thr = threading.Thread(target=self.peer_state_check, kwargs={'ip': addr, 'queue': q})
            thr.setDaemon(True)
            self.ssh_jobs.append((thr, q))
            thr.start()

        thr = threading.Thread(target=self.background)
        thr.setDaemon(True)
        self.log("Check that device is alive and pinging")
        self.assertTrue(self.check_alive(), 'DUT is not stable')

        try:
            self.log("Schedule to reboot the remote switch in %s sec" % self.reboot_delay)
            thr.start()

            self.log("Wait until VLAN and CPU port down")
            self.timeout(self.task_timeout, "DUT hasn't shutdown in %d seconds" % self.task_timeout)
            self.wait_until_vlan_cpu_port_down()
            self.cancel_timeout()

            self.reboot_start = datetime.datetime.now()
            self.log("Dut reboots: reboot start %s" % str(self.reboot_start))

            self.log("Check that device is still forwarding Data plane traffic")
            self.assertTrue(self.check_alive(), 'DUT is not stable')

            self.log("Wait until VLAN and CPU port up")
            self.timeout(self.task_timeout, "DUT hasn't bootup in %d seconds" % self.task_timeout)
            self.wait_until_vlan_cpu_port_up()
            self.cancel_timeout()

            self.log("Wait until ASIC stops")
            self.timeout(self.task_timeout, "DUT hasn't stopped in %d seconds" % self.task_timeout)
            no_routing_start, upper_replies = self.check_forwarding_stop()
            self.cancel_timeout()

            self.log("ASIC was stopped, Waiting until it's up. Stop time: %s" % str(no_routing_start))
            self.timeout(self.task_timeout, "DUT hasn't started to work for %d seconds" % self.task_timeout)
            no_routing_stop, _ = self.check_forwarding_resume()
            self.cancel_timeout()

            # wait until all bgp session are established
            self.log("Wait until bgp routing is up on all devices")
            for _, q in self.ssh_jobs:
                q.put('quit')

            self.timeout(self.task_timeout, "SSH threads haven't finished for %d seconds" % self.task_timeout)
            while any(thr.is_alive() for thr, _ in self.ssh_jobs):
                for _, q in self.ssh_jobs:
                    q.put('go')
                time.sleep(self.TIMEOUT)

            for thr, _ in self.ssh_jobs:
                thr.join()
            self.cancel_timeout()

            self.log("ASIC works again. Start time: %s" % str(no_routing_stop))
            self.log("")

            no_cp_replies = self.extract_no_cpu_replies(upper_replies)

            self.fails['dut'] = set()
            if no_routing_stop - no_routing_start > self.limit:
                self.fails['dut'].add("Downtime must be less then %s seconds. It was %s" \
                        % (self.test_params['reboot_limit_in_seconds'], str(no_routing_stop - no_routing_start)))
            if no_routing_stop - self.reboot_start > datetime.timedelta(seconds=self.test_params['graceful_limit']):
                self.fails['dut'].add("Fast-reboot cycle must be less than graceful limit %s seconds" % self.test_params['graceful_limit'])
            if no_cp_replies < 0.95 * self.nr_vl_pkts:
                self.fails['dut'].add("Dataplane didn't route to all servers, when control-plane was down: %d vs %d" % (no_cp_replies, self.nr_vl_pkts))

        finally:
            # Generating report
            self.log("="*50)
            self.log("Report:")
            self.log("="*50)

            self.log("LACP/BGP were down for (extracted from cli):")
            self.log("-"*50)
            for ip in sorted(self.cli_info.keys()):
                self.log("    %s - lacp: %7.3f (%d) po_events: (%d) bgp v4: %7.3f (%d) bgp v6: %7.3f (%d)" \
                         % (ip, self.cli_info[ip]['lacp'][1],   self.cli_info[ip]['lacp'][0], \
                                self.cli_info[ip]['po'][1], \
                                self.cli_info[ip]['bgp_v4'][1], self.cli_info[ip]['bgp_v4'][0],\
                                self.cli_info[ip]['bgp_v6'][1], self.cli_info[ip]['bgp_v6'][0]))

            self.log("-"*50)
            self.log("Extracted from VM logs:")
            self.log("-"*50)
            for ip in sorted(self.logs_info.keys()):
                self.log("Extracted log info from %s" % ip)
                for msg in sorted(self.logs_info[ip].keys()):
                    if msg != 'error':
                        self.log("    %s : %d" % (msg, self.logs_info[ip][msg]))
                    else:
                        self.log("    %s" % self.logs_info[ip][msg])
                self.log("-"*50)

            self.log("Summary:")
            self.log("-"*50)
            self.log("Downtime was %s" % str(no_routing_stop - no_routing_start))
            self.log("Reboot time was %s" % str(no_routing_stop - self.reboot_start))


            self.log("How many packets were received back when control plane was down: %d Expected: %d" % (no_cp_replies, self.nr_vl_pkts))

            has_info = any(len(info) > 0 for info in self.info.values())
            if has_info:
                self.log("-"*50)
                self.log("Additional info:")
                self.log("-"*50)
                for name, info in self.info.items():
                    for entry in info:
                        self.log("INFO:%s:%s" % (name, entry))
                self.log("-"*50)

            is_good = all(len(fails) == 0 for fails in self.fails.values())

            errors = ""
            if not is_good:
                self.log("-"*50)
                self.log("Fails:")
                self.log("-"*50)

                errors = "\n\nSomething went wrong. Please check output below:\n\n"
                for name, fails in self.fails.items():
                    for fail in fails:
                        self.log("FAILED:%s:%s" % (name, fail))
                        errors += "FAILED:%s:%s\n" % (name, fail)

            self.log("="*50)

            self.assertTrue(is_good, errors)

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
        stdout, stderr, return_code = self.cmd(["ssh", "-oStrictHostKeyChecking=no", self.dut_ssh, "sudo " + self.reboot_type])
        if stdout != []:
            self.log("stdout from %s: %s" % (self.reboot_type, str(stdout)))
        if stderr != []:
            self.log("stderr from %s: %s" % (self.reboot_type, str(stderr)))
        self.log("return code from %s: %s" % (self.reboot_type, str(return_code)))

        # Note: a timeout reboot in ssh session will return a 255 code
        if return_code not in [0, 255]:
            thread.interrupt_main()

        return

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def peer_state_check(self, ip, queue):
        ssh = Arista(ip, queue, self.test_params)
        self.fails[ip], self.info[ip], self.cli_info[ip], self.logs_info[ip] = ssh.run()

    def wait_until_vlan_cpu_port_down(self):
        while True:
            total_rcv_pkt_cnt = self.pingDut()
            if total_rcv_pkt_cnt < self.ping_dut_pkts:
                break

    def wait_until_vlan_cpu_port_up(self):
        while True:
            total_rcv_pkt_cnt = self.pingDut()
            if total_rcv_pkt_cnt >= self.ping_dut_pkts / 2:
                break

    def check_forwarding_stop(self):
        return self.iteration(True)

    def check_forwarding_resume(self):
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
        replies_from_servers = self.pingFromServers()
        if replies_from_servers > 0:
            replies_from_upper = self.pingFromUpperTier()
        else:
            replies_from_upper = 0
        return replies_from_servers > 0 and replies_from_upper > 0, replies_from_upper

    def check_alive(self):
        # This function checks that DUT routes the packets in the both directions.
        #
        # Sometimes first attempt failes because ARP responses to DUT are not so fast.
        # But after this the function expects to see steady "replies".
        # If the function sees that there is an issue with the dataplane after we saw
        # successful replies it considers that the DUT is not healthy
        #
        # Sometimes I see that DUT returns more replies then requests.
        # I think this is because of not populated FDB table
        # The function waits while it's done

        was_alive = False
        for counter in range(self.nr_tests * 2):
            success, _ = self.ping_alive()
            if success:
              was_alive = True
            else:
              if was_alive:
                return False    # Stopped working after it working for sometime?

        # wait, until FDB entries are populated
        for _ in range(self.nr_tests * 10): # wait for some time
            if not self.ping_alive()[1]:    # until we see that there're no extra replies
                return True

        return False                        # we still see extra replies

    def ping_alive(self):
        nr_from_s = self.pingFromServers()
        nr_from_l = self.pingFromUpperTier()

        is_alive      = nr_from_s > self.nr_pc_pkts * 0.7 and nr_from_l > self.nr_vl_pkts * 0.7
        is_asic_weird = nr_from_s > self.nr_pc_pkts        or nr_from_l > self.nr_vl_pkts
        # we receive more, then sent. not populated FDB table

        return is_alive, is_asic_weird

    def pingFromServers(self):
        for i in xrange(self.nr_pc_pkts):
            testutils.send_packet(self, self.from_server_src_port, self.from_vlan_packet)

        total_rcv_pkt_cnt = testutils.count_matched_packets_all_ports(self, self.from_vlan_exp_packet, self.from_server_dst_ports, timeout=self.TIMEOUT)

        self.log("Send %5d Received %5d servers->t1" % (self.nr_pc_pkts, total_rcv_pkt_cnt), True)

        return total_rcv_pkt_cnt

    def pingFromUpperTier(self):
        for entry in self.from_t1:
            testutils.send_packet(self, *entry)

        total_rcv_pkt_cnt = testutils.count_matched_packets_all_ports(self, self.from_t1_exp_packet, self.vlan_ports, timeout=self.TIMEOUT)

        self.log("Send %5d Received %5d t1->servers" % (self.nr_vl_pkts, total_rcv_pkt_cnt), True)

        return total_rcv_pkt_cnt

    def pingDut(self):
        for i in xrange(self.ping_dut_pkts):
            testutils.send_packet(self, self.random_port(self.vlan_ports), self.ping_dut_packet)

        total_rcv_pkt_cnt = testutils.count_matched_packets_all_ports(self, self.ping_dut_exp_packet, self.vlan_ports, timeout=self.TIMEOUT)

        self.log("Send %5d Received %5d ping DUT" % (self.ping_dut_pkts, total_rcv_pkt_cnt), True)

        return total_rcv_pkt_cnt
