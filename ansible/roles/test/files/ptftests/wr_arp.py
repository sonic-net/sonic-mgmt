# This is Control Plane Assistent test for Warm-Reboot.
# The test first start Ferret server, implemented in Python. Then initiate Warm-Rebbot procedure.
# While the host in Warm-Reboot test continiously sending ARP request to the Vlan member ports and
# expect to receive ARP replies. The test will fail as soon as there is no replies for more than 25 seconds
# for one of the Vlan member ports
# To Run the test from the command line:
# ptf --test-dir 1 1.ArpTest  --platform-dir ptftests --platform remote -t "config_file='/tmp/vxlan_decap.json';ferret_ip='10.64.246.21';dut_ssh='10.3.147.243';how_long=370"
#
import time
import json
import subprocess
import datetime
import traceback
import sys
import socket
import threading
from collections import defaultdict
from pprint import pprint
from Queue import Queue

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.dataplane as dataplane
import ptf.testutils as testutils
from device_connection import DeviceConnection


class ArpTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

        log_file_name = '/tmp/wr_arp_test.log'
        self.log_fp = open(log_file_name, 'a')
        self.log_fp.write("\nNew test:\n")

        self.q_to_dut = Queue()
        self.q_from_dut = Queue()

        return

    def __del__(self):
        self.log_fp.close()

        return

    def log(self, message):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print "%s : %s" % (current_time, message)
        self.log_fp.write("%s : %s\n" % (current_time, message))
        self.log_fp.flush()

        return

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def dut_exec_cmd(self, cmd):
        self.log("Executing cmd='{}'".format(cmd))
        stdout, stderr, return_code = self.dut_connection.execCommand(cmd, timeout=30)
        self.log("return_code={}, stdout={}, stderr={}".format(return_code, stdout, stderr))

        if return_code == 0:
            return True, str(stdout)
        elif return_code == 255:
            return True, str(stdout)
        else:
            return False, "return code: %d. stdout = '%s' stderr = '%s'" % (return_code, str(stdout), str(stderr))

    def dut_thr(self, q_from, q_to):
        while True:
            cmd = q_from.get()
            if cmd == 'WR':
                self.log("Rebooting remote side")
                res, res_text = self.dut_exec_cmd("sudo warm-reboot -c {}".format(self.ferret_ip))
                if res:
                    q_to.put('ok: %s' % res_text)
                else:
                    q_to.put('error: %s' % res_text)
            elif cmd == 'uptime':
                self.log("Check uptime remote side")
                res, res_text = self.dut_exec_cmd("uptime -s")
                if res:
                    q_to.put('ok: %s' % res_text)
                else:
                    q_to.put('error: %s' % res_text)
            elif cmd == 'quit':
                q_to.put("done")
                break
            else:
                self.log('Unsupported cmd: %s' % cmd)
                q_to.put("error: unsupported cmd: %s" % cmd)
        self.log("Quiting from dut_thr")
        return

    def test_port_thr(self):
        self.log("test_port_thr started")
        while time.time() < self.stop_at:
            for test in self.tests:
                for port in test['acc_ports']:
                    nr_rcvd = self.testPort(port)
                    self.records[port][time.time()] = nr_rcvd
        self.log("Quiting from test_port_thr")
        return

    def readMacs(self):
        addrs = {}
        for intf in os.listdir('/sys/class/net'):
            if os.path.isdir('/sys/class/net/%s' % intf):
                with open('/sys/class/net/%s/address' % intf) as fp:
                    addrs[intf] = fp.read().strip()

        return addrs

    def generate_VlanPrefixes(self, gw, prefixlen, acc_ports):
        res = {}
        n_hosts = 2**(32 - prefixlen) - 3
        nr_of_dataplane_ports = len(self.dataplane.ports)

        if nr_of_dataplane_ports > n_hosts:
            raise Exception("The prefix len size is too small for the test")

        gw_addr_n = struct.unpack(">I", socket.inet_aton(gw))[0]
        mask = (2**32 - 1) ^ (2**(32 - prefixlen) - 1)
        net_addr_n = gw_addr_n & mask

        addr = 1
        for port in acc_ports:
            while True:
                host_addr_n = net_addr_n + addr
                host_ip = socket.inet_ntoa(struct.pack(">I", host_addr_n))
                if host_ip != gw:
                    break
                else:
                    addr += 1 # skip gw
            res[port] = host_ip
            addr += 1

        return res

    def generatePkts(self, gw, port_ip, port_mac):
        pkt = testutils.simple_arp_packet(
                        ip_snd=port_ip,
                        ip_tgt=gw,
                        eth_src=port_mac,
                        hw_snd=port_mac,
                       )
        exp_pkt = testutils.simple_arp_packet(
                        ip_snd=gw,
                        ip_tgt=port_ip,
                        eth_src=self.dut_mac,
                        eth_dst=port_mac,
                        hw_snd=self.dut_mac,
                        hw_tgt=port_mac,
                        arp_op=2,
                       )

        return str(pkt), str(exp_pkt)

    def generatePackets(self):
        self.gen_pkts = {}
        for test in self.tests:
            for port in test['acc_ports']:
                gw = test['vlan_gw']
                port_ip  = test['vlan_ip_prefixes'][port]
                port_mac = self.ptf_mac_addrs['eth%d' % port]
                self.gen_pkts[port] = self.generatePkts(gw, port_ip, port_mac)

        return

    def get_param(self, param_name, required=True, default = None):
        params = testutils.test_params_get()
        if param_name not in params:
            if required:
                raise Exception("required parameter '%s' is not presented" % param_name)
            else:
                return default
        else:
            return params[param_name]

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

        config = self.get_param('config_file')
        self.ferret_ip = self.get_param('ferret_ip')
        self.dut_ssh = self.get_param('dut_ssh')
        self.dut_username = self.get_param('dut_username')
        self.dut_password = self.get_param('dut_password')
        self.dut_alt_password=self.get_param('alt_password')
        self.dut_connection = DeviceConnection(self.dut_ssh,
                                            username=self.dut_username,
                                            password=self.dut_password,
                                            alt_password=self.dut_alt_password)
        self.how_long = int(self.get_param('how_long', required=False, default=300))

        if not os.path.isfile(config):
            raise Exception("the config file %s doesn't exist" % config)

        with open(config) as fp:
            graph = json.load(fp)

        self.tests = []
        vni_base = 0
        for name, data in graph['minigraph_vlans'].items():
            test = {}
            test['acc_ports'] = [graph['minigraph_port_indices'][member] for member in data['members']]
            vlan_id = int(name.replace('Vlan', ''))
            test['vni'] = vni_base + vlan_id

            gw = None
            prefixlen = None
            for d in graph['minigraph_vlan_interfaces']:
                if d['attachto'] == name:
                    gw = d['addr']
                    prefixlen = int(d['prefixlen'])
                    break
            else:
                raise Exception("Vlan '%s' is not found" % name)

            test['vlan_gw'] = gw
            test['vlan_ip_prefixes'] = self.generate_VlanPrefixes(gw, prefixlen, test['acc_ports'])

            self.tests.append(test)

        self.dut_mac = graph['dut_mac']

        self.ptf_mac_addrs = self.readMacs()

        self.generatePackets()

        self.cmd(["supervisorctl", "restart", "ferret"])

        self.dataplane.flush()

        return

    def tearDown(self):
        self.cmd(["supervisorctl", "stop", "ferret"])
        return

    def runTest(self):
        print
        thr = threading.Thread(target=self.dut_thr, kwargs={'q_from': self.q_to_dut, 'q_to': self.q_from_dut})
        thr.setDaemon(True)
        thr.start()

        uptime_before = self.req_dut('uptime')
        if uptime_before.startswith('error'):
            self.log("DUT returned error for first uptime request")
            self.req_dut('quit')
            self.assertTrue(False, "DUT returned error for first uptime request")

        self.records = defaultdict(dict)
        self.stop_at = time.time() + self.how_long

        test_port_thr = threading.Thread(target=self.test_port_thr)
        test_port_thr.setDaemon(True)
        test_port_thr.start()

        self.log("Issuing WR command")
        result = self.req_dut('WR')
        if result.startswith('ok'):
            self.log("WR OK!")
        else:
            self.log("Error in WR")
            self.req_dut('quit')
            self.assertTrue(False, "Error in WR")

        self.assertTrue(time.time() < self.stop_at, "warm-reboot took to long")

        test_port_thr.join(timeout=self.how_long)
        if test_port_thr.isAlive():
            self.log("Timed out waiting for warm reboot")
            self.req_dut('quit')
            self.assertTrue(False, "Timed out waiting for warm reboot")

        uptime_after = self.req_dut('uptime')
        if uptime_after.startswith('error'):
            self.log("DUT returned error for second uptime request")
            self.req_dut('quit')
            self.assertTrue(False, "DUT returned error for second uptime request")

        self.req_dut('quit')

        if uptime_before == uptime_after:
            self.log("The DUT wasn't rebooted. Uptime: %s vs %s" % (uptime_before, uptime_after))
            self.assertTrue(uptime_before != uptime_after, "The DUT wasn't rebooted. Uptime: %s vs %s" % (uptime_before, uptime_after))

        # check that every port didn't have pauses more than 25 seconds
        pauses = defaultdict(list)
        for port, data in self.records.items():
            was_active = True
            last_inactive = None
            for t in sorted(data.keys()):
                active = data[t] > 0
                if was_active and not active:
                    last_inactive = t
                elif not was_active and active:
                    pauses[port].append(t - last_inactive)
                was_active = active
            if not was_active:
                pauses[port].append(sorted(data.keys())[-1] - last_inactive)

        m_pauses = { port:max(pauses[port]) for port in pauses.keys() if max(pauses[port]) > 25 }
        for port in m_pauses.keys():
            self.log("Port eth%d. Max pause in arp_response %d sec" % (port, int(m_pauses[port])))
        print
        sys.stdout.flush()
        self.assertTrue(len(m_pauses) == 0, "Too long pauses in arp responses")

        return

    def testPort(self, port):
        pkt, exp_pkt = self.gen_pkts[port]
        testutils.send_packet(self, port, pkt)
        nr_rcvd = testutils.count_matched_packets(self, exp_pkt, port, timeout=0.2)
        return nr_rcvd

    def req_dut(self, cmd):
        self.log("cmd: %s" % cmd)
        self.q_to_dut.put(cmd)
        reply = self.q_from_dut.get()
        self.log("reply: %s" % reply)
        return reply
