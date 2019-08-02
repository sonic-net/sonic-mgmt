# ptf -t "config_file='/tmp/vxlan_decap.json';vxlan_enabled=True" --platform-dir ptftests --test-dir ptftests --platform remote vxlan-decap

# The test checks vxlan decapsulation for the dataplane.
# The test runs three tests for each vlan on the DUT:
# 1. 'Vxlan'            : Sends encapsulated packets to PortChannel interfaces and expects to see the decapsulated inner packets on the corresponding vlan interface.
# 2. 'RegularLAGtoVLAN' : Sends regular packets to PortChannel interfaces and expects to see the packets on the corresponding vlan interface.
# 3. 'RegularVLANtoLAG' : Sends regular packets to Vlan member interfaces and expects to see the packets on the one of PortChannel interfaces.
#
# The test has two parameters:
# 1. 'config_file' is a filename of a file which contains all necessary information to run the test. The file is populated by ansible. This parameter is mandatory.
# 2. 'vxlan_enabled' is a boolean parameter. When the parameter is true the test will fail if vxlan test failing. When the parameter is false the test will not fail. By default this parameter is false.
# 3. 'count' is an integer parameter. It defines how many packets are sent for each combination of ingress/egress interfaces. By default the parameter equal to 1

import sys
import os.path
import json
import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils
from ptf.testutils import *
from ptf.dataplane import match_exp_pkt
from ptf.mask import Mask
import datetime
import subprocess
import traceback
from pprint import pprint
from pprint import pformat

class Vxlan(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

        self.vxlan_enabled = False
        self.random_mac = '8c:01:02:03:04:05'
        self.nr = 1

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def readMacs(self):
        addrs = {}
        for intf in os.listdir('/sys/class/net'):
            with open('/sys/class/net/%s/address' % intf) as fp:
                addrs[intf] = fp.read().strip()

        return addrs

    def generate_ArpResponderConfig(self):
        config = {}
        for test in self.tests:
            for port in test['acc_ports']:
                config['eth%d' % port] = [test['vlan_ip_prefix'] % port]

        with open('/tmp/vxlan_arpresponder.conf', 'w') as fp:
            json.dump(config, fp)

        return

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
        src_ip = "8.8.%d.%d"
        for name, data in graph['minigraph_vlans'].items():
            test = {}
            test['name'] = name
            test['acc_ports'] = [graph['minigraph_port_indices'][member] for member in data['members']]
            vlan_id = int(name.replace('Vlan', ''))
            test['vni'] = vni_base + vlan_id
            test['src_ip'] = src_ip % (vlan_id / 256, vlan_id % 254 + 1)

            gw = None
            prefixlen = None
            for d in graph['minigraph_vlan_interfaces']:
                if d['attachto'] == name:
                    gw = d['addr']
                    prefixlen = d['prefixlen']
                    break
            else:
                raise Exception("Vlan '%s' is not found" % name)

            test['vlan_gw'] = gw

            number_of_dataplane_ports = len(self.dataplane.ports)
            if number_of_dataplane_ports > 256:
                raise Exception("Too much dataplane ports for the test")
            if prefixlen > 24:
                raise Exception("The prefix len size is too small for the test")

            test['vlan_ip_prefix'] = '.'.join(gw.split('.')[0:3])+".%d"

            self.tests.append(test)

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

        self.cmd(["supervisorctl", "start", "arp_responder"])

        self.dataplane.flush()

        return

    def tearDown(self):
        self.cmd(["supervisorctl", "stop", "arp_responder"])

        return

    def runTest(self):
        print
        err = ''
        trace = ''
        ret = 0
        try:
            for test in self.tests:
                print test['name']
                res_v, out_v = self.Vxlan(test)
                print "  Vxlan            = ", res_v
                res_f, out_f = self.RegularLAGtoVLAN(test)
                print "  RegularLAGtoVLAN = ", res_f
                res_t, out_t = self.RegularVLANtoLAG(test)
                print "  RegularVLANtoLAG = ", res_t
                print
                if self.vxlan_enabled:
                    self.assertTrue(res_v, "VxlanTest failed:\n  %s\n\ntest:\n%s"  % (out_v, pformat(test)))
                else:
                    self.assertFalse(res_v, "VxlanTest: vxlan works, but it must have been disabled!\n\ntest:%s" % pformat(test))
                self.assertTrue(res_f, "RegularLAGtoVLAN test failed:\n  %s\n\ntest:\n%s" % (out_f, pformat(test)))
                self.assertTrue(res_t, "RegularVLANtoLAG test failed:\n  %s\n\ntest:\n%s" % (out_t, pformat(test)))
        except AssertionError as e:
            err = str(e)
            trace = traceback.format_exc()
            ret = -1
        if ret != 0:
            print "The test failed"
            print
            print "Error: %s" % err
            print
            print trace
        else:
            print "The test was successful"
        sys.stdout.flush()
        if ret != 0:
            raise AssertionError(err)

    def Vxlan(self, test):
        for n in self.net_ports:
            for a in test['acc_ports']:
                res, out = self.checkVxlan(a, n, test)
                if not res:
                    return False, out
        return True, ""

    def RegularLAGtoVLAN(self, test):
        for n in self.net_ports:
            for a in test['acc_ports']:
                res, out = self.checkRegularRegularLAGtoVLAN(a, n, test)
                if not res:
                    return False, out
        return True, ""

    def RegularVLANtoLAG(self, test):
        for dst, ports in self.pc_info:
            for a in test['acc_ports']:
                res, out = self.checkRegularRegularVLANtoLAG(a, ports, dst, test)
                if not res:
                    return False, out
        return True, ""

    def checkRegularRegularVLANtoLAG(self, acc_port, pc_ports, dst_ip, test):
        src_mac = self.ptf_mac_addrs['eth%d' % acc_port]
        dst_mac = self.dut_mac
        src_ip = test['vlan_ip_prefix'] % acc_port

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

        for i in xrange(self.nr):
            testutils.send_packet(self, acc_port, packet)
        nr_rcvd = testutils.count_matched_packets_all_ports(self, exp_packet, pc_ports, timeout=0.5)
        rv = nr_rcvd == self.nr
        out = ""
        if not rv:
            arg = self.nr, nr_rcvd, str(acc_port), str(pc_ports), src_mac, dst_mac, src_ip, dst_ip
            out = "sent = %d rcvd = %d | src_port=%s dst_ports=%s | src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s" % arg
        return rv, out


    def checkRegularRegularLAGtoVLAN(self, acc_port, net_port, test):
        src_mac = self.random_mac
        dst_mac = self.dut_mac
        src_ip = test['src_ip']
        dst_ip = test['vlan_ip_prefix'] % acc_port

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

        for i in xrange(self.nr):
            testutils.send_packet(self, net_port, packet)
        nr_rcvd = testutils.count_matched_packets(self, exp_packet, acc_port, timeout=0.5)
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
        inner_dst_ip = test['vlan_ip_prefix'] % acc_port
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
        for i in xrange(self.nr):
            testutils.send_packet(self, net_port, packet)
        nr_rcvd = testutils.count_matched_packets(self, inpacket, acc_port, timeout=0.5)
        rv = nr_rcvd == self.nr
        out = ""
        if not rv:
            arg = self.nr, nr_rcvd, str(net_port), str(acc_port), src_mac, dst_mac, test['src_ip'], ip_dst, inner_src_mac, inner_dst_mac, inner_src_ip, inner_dst_ip, test['vni']
            out = "sent = %d rcvd = %d | src_port=%s dst_port=%s | src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s | Inner: src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s vni=%s" % arg
        return rv, out


