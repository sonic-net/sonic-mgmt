# ptf -t "config_file='/tmp/vxlan_decap.json';vxlan_enabled=True;dut_host=10.0.0.1;sonic_admin_user=admin;sonic_admin_password=admin" --platform-dir ptftests --test-dir ptftests --platform remote vxlan-decap

# The test checks vxlan decapsulation for the dataplane.
# The test runs three tests for each vlan on the DUT:
# 1. 'Vxlan'            : Sends encapsulated packets to PortChannel interfaces and expects to see the decapsulated inner packets on the corresponding vlan interface.
# 2. 'RegularLAGtoVLAN' : Sends regular packets to PortChannel interfaces and expects to see the packets on the corresponding vlan interface.
# 3. 'RegularVLANtoLAG' : Sends regular packets to Vlan member interfaces and expects to see the packets on the one of PortChannel interfaces.
#
# The test has 6 parameters:
# 1. 'config_file' is a filename of a file which contains all necessary information to run the test. The file is populated by ansible. This parameter is mandatory.
# 2. 'vxlan_enabled' is a boolean parameter. When the parameter is true the test will fail if vxlan test failing. When the parameter is false the test will not fail. By default this parameter is false.
# 3. 'count' is an integer parameter. It defines how many packets are sent for each combination of ingress/egress interfaces. By default the parameter equal to 1
# 4. 'dut_hostname' is the name of dut.
# 5. 'sonic_admin_user': User name to login dut
# 6. 'sonic_admin_password': Password for sonic_admin_user to login dut
# 7. 'sonic_admin_alt_password': Alternate Password for sonic_admin_user to login dut

import sys
import os.path
import json
import time
import pprint
import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils
from ptf.testutils import *
from ptf.dataplane import match_exp_pkt
from ptf.mask import Mask
from ptf.testutils import dp_poll
import datetime
import subprocess
import traceback
import socket
import struct
from device_connection import DeviceConnection
import re

def count_matched_packets_helper(test, exp_packet, exp_packet_number, port, device_number=0, timeout=1):
    """
    Add exp_packet_number to original ptf interface in order to
    stop waiting when expected number of packets is received
    """
    if timeout <= 0:
        raise Exception("%s() requires positive timeout value." % sys._getframe().f_code.co_name)

    total_rcv_pkt_cnt = 0
    end_time = time.time() + timeout
    while time.time() < end_time:
        result = dp_poll(test, device_number=device_number, port_number=port, timeout=timeout, exp_pkt=exp_packet)
        if isinstance(result, test.dataplane.PollSuccess):
            total_rcv_pkt_cnt += 1
            if total_rcv_pkt_cnt == exp_packet_number:
                break
        else:
            break

    return total_rcv_pkt_cnt

def count_matched_packets_all_ports_helper(test, exp_packet, exp_packet_number, ports=[], device_number=0, timeout=1):
    """
    Add exp_packet_number to original ptf interface in order to
    stop waiting when expected number of packets is received
    """
    if timeout <= 0:
        raise Exception("%s() requires positive timeout value." % sys._getframe().f_code.co_name)

    last_matched_packet_time = time.time()
    total_rcv_pkt_cnt = 0
    while True:
        if (time.time() - last_matched_packet_time) > timeout:
            break

        result = dp_poll(test, device_number=device_number, timeout=timeout)
        if isinstance(result, test.dataplane.PollSuccess):
            if (result.port in ports and
                  ptf.dataplane.match_exp_pkt(exp_packet, result.packet)):
                total_rcv_pkt_cnt += 1
                if total_rcv_pkt_cnt == exp_packet_number:
                    break
                last_matched_packet_time = time.time()
        else:
            break

    return total_rcv_pkt_cnt

class Vxlan(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

        self.vxlan_enabled = False
        self.random_mac = '8c:01:02:03:04:05'
        self.nr = 1
        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file_name = "/tmp/vxlan_decap_test.{}.log".format(current_time)
        self.log_fp = open(log_file_name, 'w')

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def log(self, message):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_fp.write("{} : {}\n".format(current_time, message))
        self.log_fp.flush()

    def readMacs(self):
        addrs = {}
        for intf in os.listdir('/sys/class/net'):
            if os.path.isdir('/sys/class/net/%s' % intf):
                with open('/sys/class/net/%s/address' % intf) as fp:
                    addrs[intf] = fp.read().strip()

        return addrs

    def generate_ArpResponderConfig(self):
        config = {}
        for test in self.tests:
            for port, ip in test['vlan_ip_prefixes'].items():
                config['eth%d' % port] = [ip]

        with open('/tmp/vxlan_arpresponder.conf', 'w') as fp:
            json.dump(config, fp)

        return

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

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

        self.test_params = testutils.test_params_get()
        if 'vxlan_enabled' in self.test_params and self.test_params['vxlan_enabled']:
            self.vxlan_enabled = True

        if 'count' in self.test_params:
            self.nr = int(self.test_params['count'])

        if 'config_file' not in self.test_params:
            raise Exception("required parameter 'config_file' is not present")
        config = self.test_params['config_file']

        if 'dut_hostname' not in self.test_params:
            raise Exception("required parameter 'dut_hostname' is not present")
        self.dut_hostname = self.test_params['dut_hostname']

        if 'sonic_admin_user' not in self.test_params:
            raise Exception("required parameter 'sonic_admin_user' is not present")
        self.sonic_admin_user = self.test_params['sonic_admin_user']

        if 'sonic_admin_password' not in self.test_params:
            raise Exception("required parameter 'sonic_admin_password' is not present")
        self.sonic_admin_password = self.test_params['sonic_admin_password']

        if 'sonic_admin_alt_password' not in self.test_params:
            raise Exception("required parameter 'sonic_admin_alt_password' is not present")
        self.sonic_admin_alt_password = self.test_params['sonic_admin_alt_password']

        if not os.path.isfile(config):
            raise Exception("the config file %s doesn't exist" % config)

        with open(config) as fp:
            graph = json.load(fp)

        self.pc_info = []
        self.net_ports = []
        for name, val in graph['minigraph_portchannels'].items():
            members = [graph['minigraph_port_indices'][member] for member in val['members']]
            self.net_ports.extend(members)
            ip = None

            for d in graph['minigraph_portchannel_interfaces']:
                if d['attachto'] == name:
                    ip = d['peer_addr']
                    break
            else:
                raise Exception("Portchannel '%s' ip address is not found" % name)

            self.pc_info.append((ip, members))

        self.tests = []
        vni_base = 336
        for name, data in graph['minigraph_vlans'].items():
            test = {}
            test['name'] = name
            test['intf_alias'] = data['members']
            test['acc_ports'] = [graph['minigraph_port_indices'][member] for member in data['members']]
            vlan_id = int(name.replace('Vlan', ''))
            test['vni'] = vni_base + vlan_id
            test['src_ip'] = "8.8.8.8"

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
        self.log('Collected tests: {}'.format(pprint.pformat(self.tests)))

        self.dut_mac = graph['dut_mac']

        ip = None
        for data in graph['minigraph_lo_interfaces']:
            if data['prefixlen'] == 32:
                ip = data['addr']
                break
        else:
            raise Exception("ipv4 lo interface not found")

        self.loopback_ip = ip

        self.ptf_mac_addrs = self.readMacs()

        self.generate_ArpResponderConfig()

        self.cmd(["supervisorctl", "restart", "arp_responder"])
        #Wait a short time for asp_reponder to be ready
        time.sleep(10)
        self.dataplane.flush()
        self.dut_connection = DeviceConnection(
            self.dut_hostname,
            self.sonic_admin_user,
            password=self.sonic_admin_password,
            alt_password=self.sonic_admin_alt_password
        )

        return

    def check_arp_table_on_dut(self, test):
        COMMAND = 'show arp'
        stdout, stderr, return_code = self.dut_connection.execCommand(COMMAND)
        for idx, port in enumerate(test['acc_ports']):
            intf_alias = test['intf_alias'][idx]
            ip_prefix = test['vlan_ip_prefixes'][port]
            for line in stdout:
                if re.match(r"{}.*{}.*".format(ip_prefix, intf_alias), line, re.IGNORECASE):
                    break
            else:
                return False
        return True

    def check_fdb_on_dut(self, test):
        COMMAND = 'fdbshow'
        stdout, stderr, return_code = self.dut_connection.execCommand(COMMAND)
        for idx, port in enumerate(test['acc_ports']):
            mac_addr = self.ptf_mac_addrs['eth%d' % port]
            intf_alias = test['intf_alias'][idx]
            for line in stdout:
                if re.match(r".*{}.*{}.*".format(mac_addr, intf_alias), line, re.IGNORECASE):
                    break
            else:
                return False
        return True

    def wait_dut(self, test, timeout):
        start_time = datetime.datetime.now()
        while True:
            if self.check_fdb_on_dut(test) and self.check_arp_table_on_dut(test):
                return True
            if (datetime.datetime.now() - start_time).seconds > timeout:
                return False
            time.sleep(3)

    def tearDown(self):
        self.cmd(["supervisorctl", "stop", "arp_responder"])
        self.log_fp.close()
        return

    def warmup(self):
        self.log("Warming up")
        err = ''
        trace = ''
        ret = 0
        TIMEOUT = 60
        try:
            for test in self.tests:
                self.RegularLAGtoVLAN(test, True)
                #wait sometime for DUT to build FDB and ARP table
                res = self.wait_dut(test, TIMEOUT)
                self.log_dut_status()
                self.assertTrue(res, "DUT is not ready after {} seconds".format(TIMEOUT))

        except Exception as e:
            err = str(e)
            trace = traceback.format_exc()
            ret = -1
        if ret != 0:
            self.log("The warmup failed")
            self.log("Error: %s" % err)
            self.log(trace)
        else:
            self.log("Warmup successful")
        sys.stdout.flush()
        if ret != 0:
            raise AssertionError("Warmup failed")

    def log_dut_status(self):
        COMMAND = 'show arp'
        stdout, stderr, return_code = self.dut_connection.execCommand(COMMAND)
        self.log("ARP table on DUT \n{}".format(stdout))

        COMMAND = 'fdbshow'
        stdout, stderr, return_code = self.dut_connection.execCommand(COMMAND)
        self.log("MAC table on DUT \n{}".format(stdout))

        COMMAND = 'show vxlan tunnel'
        stdout, stderr, return_code = self.dut_connection.execCommand(COMMAND)
        self.log("vxlan config on DUT \n{}".format(stdout))

    def work_test(self):
        self.log("Testing")
        err = ''
        trace = ''
        ret = 0
        try:
            for test in self.tests:
                self.log(test['name'])

                res_f, out_f = self.RegularLAGtoVLAN(test)
                self.log("RegularLAGtoVLAN = {} {}".format(res_f, out_f))
                if not res_f:
                    self.log_dut_status()
                self.assertTrue(res_f, "RegularLAGtoVLAN test failed:\n  %s\n" % (out_f))

                res_t, out_t = self.RegularVLANtoLAG(test)
                self.log("RegularVLANtoLAG = {} {}".format(res_t, out_t))
                if not res_t:
                    self.log_dut_status()
                self.assertTrue(res_t, "RegularVLANtoLAG test failed:\n  %s\n" % (out_t))

                res_v, out_v = self.Vxlan(test)
                self.log("Vxlan = {} {}".format(res_v, out_v))
                if self.vxlan_enabled:
                    if not res_v:
                        self.log_dut_status()
                    self.assertTrue(res_v, "VxlanTest failed:\n  %s\n"  % (out_v))
                else:
                    if res_v:
                        self.log_dut_status()
                    self.assertFalse(res_v, "VxlanTest: vxlan works, but it must have been disabled!\n")
        except AssertionError as e:
            err = str(e)
            trace = traceback.format_exc()
            ret = -1
        if ret != 0:
            self.log("The test failed")
            self.log("Error: {}".format(err))
            self.log(trace)
        else:
            self.log("The test was successful")
        sys.stdout.flush()
        if ret != 0:
            raise AssertionError(err)


    def runTest(self):
        # Warm-up first
        self.warmup()
        # test itself
        self.work_test()


    def Vxlan(self, test):
        for i, n in enumerate(test['acc_ports']):
            for j, a in enumerate(test['acc_ports']):
                res, out = self.checkVxlan(a, n, test)
                if not res:
                    return False, out + " | net_port_rel(acc)=%d acc_port_rel=%d" % (i, j)

        for i, n in enumerate(self.net_ports):
            for j, a in enumerate(test['acc_ports']):
                res, out = self.checkVxlan(a, n, test)
                if not res:
                    return False, out + " | net_port_rel=%d acc_port_rel=%d" % (i, j)
        return True, ""

    def RegularLAGtoVLAN(self, test, wu = False):
        for i, n in enumerate(self.net_ports):
            for j, a in enumerate(test['acc_ports']):
                res, out = self.checkRegularRegularLAGtoVLAN(a, n, test, wu)
                if wu:
                    #Wait a short time for building FDB and ARP table
                    time.sleep(0.5)
                if not res and not wu:
                    return False, out + " | net_port_rel=%d acc_port_rel=%d" % (i, j)
            #We only loop all acc_ports in warmup
            if wu:
                break
        return True, ""

    def RegularVLANtoLAG(self, test):
        for i, (dst, ports) in enumerate(self.pc_info):
            for j, a in enumerate(test['acc_ports']):
                res, out = self.checkRegularRegularVLANtoLAG(a, ports, dst, test)
                if not res:
                    return False, out + " | pc_info_rel=%d acc_port_rel=%d" % (i, j)
        return True, ""

    def checkRegularRegularVLANtoLAG(self, acc_port, pc_ports, dst_ip, test):
        src_mac = self.ptf_mac_addrs['eth%d' % acc_port]
        dst_mac = self.dut_mac
        src_ip = test['vlan_ip_prefixes'][acc_port]

        packet = simple_tcp_packet(
                         eth_dst=dst_mac,
                         eth_src=src_mac,
                         ip_src=src_ip,
                         ip_dst=dst_ip,
                       )
        exp_packet = simple_tcp_packet(
                         eth_dst=self.random_mac,
                         eth_src=dst_mac,
                         ip_src=src_ip,
                         ip_dst=dst_ip,
                         ip_ttl = 63,
                       )

        exp_packet = Mask(exp_packet)
        exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")

        self.dataplane.flush()
        for i in xrange(self.nr):
            testutils.send_packet(self, acc_port, packet)
        nr_rcvd = count_matched_packets_all_ports_helper(self, exp_packet, self.nr, pc_ports, timeout=20)
        rv = nr_rcvd == self.nr
        out = ""
        if not rv:
            arg = self.nr, nr_rcvd, str(acc_port), str(pc_ports), src_mac, dst_mac, src_ip, dst_ip
            out = "sent = %d rcvd = %d | src_port=%s dst_ports=%s | src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s" % arg
        return rv, out


    def checkRegularRegularLAGtoVLAN(self, acc_port, net_port, test, wu):
        src_mac = self.random_mac
        dst_mac = self.dut_mac
        src_ip = test['src_ip']
        dst_ip = test['vlan_ip_prefixes'][acc_port]

        packet = simple_tcp_packet(
                         eth_dst=dst_mac,
                         eth_src=src_mac,
                         ip_src=src_ip,
                         ip_dst=dst_ip,
                       )

        exp_packet = simple_tcp_packet(
                         eth_dst=self.ptf_mac_addrs['eth%d' % acc_port],
                         eth_src=dst_mac,
                         ip_src=src_ip,
                         ip_dst=dst_ip,
                         ip_ttl = 63,
                       )

        self.dataplane.flush()
        for i in xrange(self.nr):
            testutils.send_packet(self, net_port, packet)
        # We don't care if expected packet is received during warming up
        if not wu:
            nr_rcvd = count_matched_packets_helper(self, exp_packet, self.nr, acc_port, timeout=20)
        else:
            nr_rcvd = 0
        rv = nr_rcvd == self.nr
        out = ""
        if not rv:
            arg = self.nr, nr_rcvd, str(net_port), str(acc_port), src_mac, dst_mac, src_ip, dst_ip
            out = "sent = %d rcvd = %d | src_port=%s dst_port=%s | src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s" % arg
        return rv, out

    def checkVxlan(self, acc_port, net_port, test):
        inner_dst_mac = self.ptf_mac_addrs['eth%d' % acc_port]
        inner_src_mac = self.dut_mac
        inner_src_ip = test['vlan_gw']
        inner_dst_ip = test['vlan_ip_prefixes'][acc_port]
        dst_mac = self.dut_mac
        src_mac = self.random_mac
        ip_dst = self.loopback_ip

        inpacket = simple_arp_packet(
                         eth_dst=inner_dst_mac,
                         eth_src=inner_src_mac,
                         arp_op=2,
                         ip_snd=inner_src_ip,
                         ip_tgt=inner_dst_ip,
                         hw_snd=inner_src_mac,
                         hw_tgt=inner_dst_mac
                       )

        packet = simple_vxlan_packet(
                       eth_dst=dst_mac,
                       eth_src=src_mac,
                       ip_src=test['src_ip'],
                       ip_dst=ip_dst,
                       vxlan_vni=test['vni'],
                       inner_frame=inpacket
                 )

        self.dataplane.flush()
        for i in xrange(self.nr):
            testutils.send_packet(self, net_port, packet)
        nr_rcvd = count_matched_packets_helper(self, inpacket, self.nr, acc_port, timeout=20)
        rv = nr_rcvd == self.nr
        out = ""
        if not rv:
            arg = self.nr, nr_rcvd, str(net_port), str(acc_port), src_mac, dst_mac, test['src_ip'], ip_dst, inner_src_mac, inner_dst_mac, inner_src_ip, inner_dst_ip, test['vni']
            out = "sent = %d rcvd = %d | src_port=%s dst_port=%s | src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s | Inner: src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s vni=%s" % arg
        return rv, out
