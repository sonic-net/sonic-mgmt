# This is Control Plane Assistent test for Warm-Reboot.
# The test first start Ferret server, implemented in Python. Then initiate Warm-Rebbot procedure.
# While the host in Warm-Reboot test continiously sending ARP request to the Vlan member ports and
# expect to receive ARP replies. The test will fail as soon as there is no replies for more than 25 seconds
# for one of the Vlan member ports
# To Run the test from the command line:
# ptf --test-dir 1 1.ArpTest  --platform-dir ptftests --platform remote -t "config_file='/tmp/vxlan_decap.json';
#     ferret_ip='10.64.246.21';dut_ssh='10.3.147.243';how_long=370"
#
import time
import json
import subprocess
import datetime
import os
import sys
import struct
import random
import socket
import threading
from collections import defaultdict
from six.moves.queue import Queue

import ptf
from ptf.base_tests import BaseTest
from ptf.mask import Mask
import ptf.testutils as testutils
import ptf.packet as scapy    # noqa: F401
from scapy.arch.linux import attach_filter as attach_filter
from device_connection import DeviceConnection
from utilities import parse_show
import ipaddress


class ArpTest(BaseTest):
    VXLAN_TUNNEL_NAME = 'neigh_adv'
    PING_TIMEOUT = 0.2
    PING_STABLE_COUNT = 3
    STATE_POLL_INTERVAL = 1

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
        print("%s : %s" % (current_time, message))
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
        stdout, stderr, return_code = self.dut_connection.execCommand(
            cmd, timeout=120)
        self.log("return_code={}, stdout={}, stderr={}".format(
            return_code, stdout, stderr))

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
                res, res_text = self.dut_exec_cmd(
                    "sudo warm-reboot -c {}".format(self.ferret_ip))
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
        stop_at = time.time() + self.how_long
        while True:
            for test in self.tests:
                self.log("Looping through tests: {}".format(test))
                for port in test['acc_ports']:
                    if time.time() > stop_at:
                        break
                    nr_rcvd = self.testPort(port)
                    self.records[port][time.time()] = nr_rcvd
                else:
                    continue
                break
            else:
                continue
            break
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
                    addr += 1  # skip gw
            res[port] = host_ip
            addr += 1

        return res

    def generatePkts(self, gw, port_ip, port_mac, vlan_id):
        pkt = testutils.simple_arp_packet(
            ip_snd=port_ip,
            ip_tgt=gw,
            eth_src=port_mac,
            hw_snd=port_mac,
            vlan_vid=vlan_id
        )

        exp_pkt = testutils.simple_arp_packet(
            pktlen=42,
            ip_snd=gw,
            ip_tgt=port_ip,
            eth_src=self.dut_mac,
            eth_dst=port_mac,
            hw_snd=self.dut_mac,
            hw_tgt=port_mac,
            arp_op=2,
            vlan_vid=vlan_id
        )
        masked_exp_pkt = Mask(exp_pkt)
        # Ignore the Ethernet padding zeros
        masked_exp_pkt.set_ignore_extra_bytes()
        return pkt, masked_exp_pkt

    def generatePackets(self):
        self.gen_pkts = {}
        self.gen_erspan_pkts = {}
        for test in self.tests:
            for port in test['acc_ports']:
                gw = test['vlan_gw']
                port_ip = test['vlan_ip_prefixes'][port]
                port_mac = self.ptf_mac_addrs['eth%d' % port]
                tagging_mode = test['tagging_mode'][port]
                if tagging_mode == 'tagged':
                    vlan_id = test['vlan_id']
                else:
                    vlan_id = 0
                self.gen_pkts[port] = self.generatePkts(
                    gw, port_ip, port_mac, vlan_id)
                if self.advance:
                    pkt, _ = self.gen_pkts[port]
                    self.gen_erspan_pkts[port] = self.generateErspanRequest(pkt)

        return

    def generateErspanRequest(self, arp_request):
        payload = arp_request
        if self.asic_type == 'mellanox':
            payload = b'\x00' * 22 + bytes(arp_request)

        if self.asic_type == 'barefoot':
            exp_pkt = testutils.ipv4_erspan_pkt(
                eth_src=self.dut_mac,
                ip_src=self.dut_loopback_ip,
                ip_dst=self.ferret_endpoint_ip,
                inner_frame=bytes(arp_request)
            )
        elif self.asic_type == 'cisco-8000':
            exp_pkt = testutils.ipv4_erspan_pkt(
                eth_src=self.dut_mac,
                ip_src=self.dut_loopback_ip,
                ip_dst=self.ferret_endpoint_ip,
                inner_frame=bytes(arp_request),
                version=1
            )
            exp_pkt['ERSPAN II'].ver = 1
        else:
            exp_pkt = testutils.simple_gre_packet(
                pktlen=0,
                eth_src=self.dut_mac,
                ip_src=self.dut_loopback_ip,
                ip_dst=self.ferret_endpoint_ip,
                inner_frame=payload
            )

        masked_exp_pkt = Mask(exp_pkt)
        inner_frame_offset = len(bytes(exp_pkt)) - len(bytes(arp_request))

        # Match only outer Ethernet source, outer IP source/destination, and
        # the complete inner ARP request.
        masked_exp_pkt.set_do_not_care(0, 6 * 8)
        masked_exp_pkt.set_do_not_care(12 * 8, 14 * 8)
        masked_exp_pkt.set_do_not_care(
            34 * 8, (inner_frame_offset - 34) * 8)
        masked_exp_pkt.set_ignore_extra_bytes()
        return masked_exp_pkt

    def get_param(self, param_name, required=True, default=None):
        params = testutils.test_params_get()
        if param_name not in params:
            if required:
                raise Exception(
                    "required parameter '%s' is not presented" % param_name)
            else:
                return default
        else:
            return params[param_name]

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

        config = self.get_param('config_file')
        self.ferret_ip = self.get_param('ferret_ip')
        self.advance = self.get_param('advance')
        self.dut_ssh = self.get_param('dut_ssh')
        self.dut_username = self.get_param('dut_username')
        self.dut_password = self.get_param('dut_password')
        self.dut_alt_password = self.get_param('alt_password')
        self.dut_connection = DeviceConnection(self.dut_ssh,
                                               username=self.dut_username,
                                               password=self.dut_password,
                                               alt_password=self.dut_alt_password)
        self.how_long = int(self.get_param(
            'how_long', required=False, default=300))

        if not os.path.isfile(config):
            raise Exception("the config file %s doesn't exist" % config)

        with open(config) as fp:
            graph = json.load(fp)

        packet_filter = 'arp and not ether dst ff:ff:ff:ff:ff:ff'
        if self.advance:
            self.asic_type = self.get_param('asic_type')
            self.ferret_endpoint_ip = self.get_param('ferret_endpoint_ip')
            for data in graph['minigraph_lo_interfaces']:
                if int(data['prefixlen']) == 32:
                    self.dut_loopback_ip = data['addr']
                    break
            else:
                raise Exception("IPv4 loopback interface not found")

            packet_filter = '({}) or ip proto 47'.format(packet_filter)
        for p in self.dataplane.ports.values():
            packet_source = p.get_packet_source()
            attach_filter(packet_source.socket, packet_filter,
                          packet_source.interface_name)

        self.portchannel_ports = sorted({
            graph['minigraph_port_indices'][member]
            for portchannel in graph['minigraph_portchannels'].values()
            for member in portchannel['members']
        })

        self.tests = []
        vni_base = 0
        for vlan, config in graph['vlan_facts'].items():
            test = {}
            test['acc_ports'] = []
            test['tagging_mode'] = {}
            for member, mode in config['members'].items():
                ptf_port_idx = graph['minigraph_port_indices'][member]
                test['acc_ports'].append(ptf_port_idx)
                test['tagging_mode'].update(
                    {
                        ptf_port_idx: mode['tagging_mode']
                    }
                )
            test['vlan_id'] = int(config['vlanid'])
            test['vni'] = vni_base + test['vlan_id']

            prefixlen = None
            for d in config['interfaces']:
                if sys.version_info < (3, 0):
                    ip = ipaddress.ip_address(d['addr'].decode('utf8'))
                else:
                    ip = ipaddress.ip_address(d['addr'])
                if ip.version == 4:
                    test['vlan_gw'] = d['addr']
                    prefixlen = int(d['prefixlen'])
                    test['vlan_ip_prefixes'] = self.generate_VlanPrefixes(
                        d['addr'], prefixlen, test['acc_ports'])
                    break
            else:
                raise Exception(
                    "No invalid IPv4 address found for Vlan '%s'" % vlan)

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
        print()
        thr = threading.Thread(target=self.dut_thr, kwargs={
                               'q_from': self.q_to_dut, 'q_to': self.q_from_dut})
        thr.setDaemon(True)
        thr.start()

        if self.advance is False:
            # test warm reboot arp basic
            self.test_wrarp_basic()
        else:
            # test warm reboot arp, ferret/non-broadcast/vxlan
            self.test_wrarp_advance()

        # end of testing
        self.end_of_test()
        return

    def get_uptime(self):
        uptime = self.req_dut('uptime')
        if uptime.startswith('error'):
            self.log("DUT returned error for uptime request")
            self.req_dut('quit')
            self.assertTrue(False, "DUT returned error for uptime request")
        return uptime

    def warm_reboot(self):
        self.log("Issuing WR command")
        self.stop_at = time.time() + self.how_long
        result = self.req_dut('WR')
        if result.startswith('ok'):
            self.log("WR OK!")
        else:
            self.log("Error in WR")
            self.req_dut('quit')
            self.assertTrue(False, "Error in WR")

        self.assertTrue(time.time() < self.stop_at, "warm-reboot took to long")

    def end_of_test(self):
        self.req_dut('quit')

    def test_wrarp_basic(self):
        self.records = defaultdict(dict)

        test_port_thr = threading.Thread(target=self.test_port_thr)
        test_port_thr.setDaemon(True)
        test_port_thr.start()

        uptime_before = self.get_uptime()
        self.warm_reboot()

        test_port_thr.join(timeout=self.how_long)
        if test_port_thr.is_alive():
            self.log("Timed out waiting for traffic-sender (test_port_thr thread)")
            self.req_dut('quit')
            self.assertTrue(
                False, "Timed out waiting for traffic-sender (test_port_thr thread)")

        uptime_after = self.get_uptime()

        if uptime_before == uptime_after:
            self.log("The DUT wasn't rebooted. Uptime: %s vs %s" %
                     (uptime_before, uptime_after))
            self.assertTrue(uptime_before != uptime_after,
                            "The DUT wasn't rebooted. Uptime: %s vs %s" % (uptime_before, uptime_after))

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

        m_pauses = {port: max(pauses[port])
                    for port in pauses.keys() if max(pauses[port]) > 25}
        for port in m_pauses.keys():
            self.log("Port eth%d. Max pause in arp_response %d sec" %
                     (port, int(m_pauses[port])))
        print()
        sys.stdout.flush()
        self.assertTrue(len(m_pauses) == 0, "Too long pauses in arp responses")

    def testPort(self, port):
        pkt, exp_pkt = self.gen_pkts[port]
        testutils.send_packet(self, port, pkt)
        nr_rcvd = testutils.count_matched_packets(
            self, exp_pkt, port, timeout=0.2)
        return nr_rcvd

    def req_dut(self, cmd):
        self.log("cmd: %s" % cmd)
        self.q_to_dut.put(cmd)
        reply = self.q_from_dut.get()
        self.log("reply: %s" % reply)
        return reply

    # make sure setUp is done before run this test case
    def test_wrarp_advance(self):
        release = self.get_release_version()
        if release is not None and release < '202205':
            self.log("release version does not support advance test case")
            return

        first_run = True
        final_elapsed = 0
        for test in self.tests:
            start_time = time.time()
            # The case should wait long enough for next warm reboot
            # To make sure to wait the previous warm reboot to finish
            if not first_run and final_elapsed < self.how_long:
                self.log(f"Sleeping for {self.how_long - final_elapsed} seconds before next test")
                time.sleep(self.how_long - final_elapsed)
            port = random.choice(test['acc_ports'])
            thread_errors = []

            def _run_non_broadcast_reply():
                try:
                    self.test_non_broadcast_reply_thr(port=port)
                except Exception as e:
                    self.log("test_non_broadcast_reply_thr failed: {!r}".format(e))
                    thread_errors.append(e)

            test_non_broadcast_reply_thread = threading.Thread(
                target=_run_non_broadcast_reply)
            test_non_broadcast_reply_thread.setDaemon(True)
            test_non_broadcast_reply_thread.start()

            uptime_before = self.get_uptime()
            self.warm_reboot()

            test_non_broadcast_reply_thread.join(timeout=self.how_long)

            wr_state = self.get_warm_restart_state()
            if wr_state is not False:
                self.assertTrue(False, "CPA quit before warm reboot finished")

            if test_non_broadcast_reply_thread.is_alive():
                self.log("Timed out waiting for test_non_broadcast_reply_thread")
                self.assertTrue(
                    False, "Timed out waiting for test_non_broadcast_reply_thread")

            if thread_errors:
                self.assertTrue(
                    False,
                    "test_non_broadcast_reply_thr failed: {}".format(thread_errors[0]))

            uptime_after = self.get_uptime()
            if uptime_before == uptime_after:
                self.log("The DUT wasn't rebooted. Uptime: %s vs %s" %
                         (uptime_before, uptime_after))
                self.assertTrue(uptime_before != uptime_after,
                                "The DUT wasn't rebooted. Uptime: %s vs %s" % (uptime_before, uptime_after))
            final_elapsed = time.time() - start_time
            first_run = False

    def test_non_broadcast_reply_thr(self, port):
        pkt, exp_pkt = self.gen_pkts[port]
        exp_erspan_pkt = self.gen_erspan_pkts[port]

        stop_at = time.time() + self.how_long
        reachable = None
        reboot_downtime_observed = False

        while time.time() < stop_at:
            send_pkt = False
            reachable = self.get_stable_ping_state(reachable)
            if reachable is None:
                # Test just started and ping is not stable
                time.sleep(self.STATE_POLL_INTERVAL)
                continue

            if not reachable:
                # DUT is rebooting, CPA should work
                if not reboot_downtime_observed:
                    self.log("DUT becomes unreachable; reboot downtime detected")
                self.log("DUT is unreachable; sending ARP")
                reboot_downtime_observed = True
                send_pkt = True
            elif not reboot_downtime_observed:
                # Reboot has not started; CPA state may be transient, so do not query it or send traffic.
                self.log("Wait for reboot to begin")
            else:
                cpa_state = self.get_cpa_state()
                if cpa_state is True:
                    self.log("CPA is still enabled; keep sending ARP")
                    send_pkt = True
                elif cpa_state is None:
                    self.log("CPA state is unavailable after downtime; continue sending ARP while DUT recovers")
                    send_pkt = True
                else:
                    self.log("DUT finalized warm reboot and disabled CPA; stopping test")
                    return

            if not send_pkt:
                time.sleep(self.STATE_POLL_INTERVAL)
                continue

            self.dataplane.flush()
            testutils.send_packet(self, port, pkt)
            try:
                self.log("Verifying mirrored ARP request in ERSPAN packet")
                testutils.verify_packet_any_port(
                    self, exp_erspan_pkt, ports=self.portchannel_ports)
                # check arp reply should come from same port
                # clean arp, test broadcast reply if needed
                self.log("Verifying ARP reply on requester port {}".format(port))
                testutils.verify_packet_any_port(self, exp_pkt, ports=[port])
            except AssertionError:
                # CPA may be disabled between the state check and ARP transmission.
                # Recheck its state to determine whether verification overlapped teardown.
                if reboot_downtime_observed:
                    time.sleep(self.STATE_POLL_INTERVAL)
                    if self.ping_dut() and self.get_cpa_state() is False:
                        self.log("Packet verification overlapped CPA teardown; stopping test")
                        return
                raise

        self.assertTrue(False, "Timed out waiting for CPA teardown")

    def ping_dut(self):
        _, _, return_code = self.cmd([
            'ping', '-n', '-q', '-c', '1',
            '-W', str(self.PING_TIMEOUT), self.dut_ssh
        ])
        return return_code == 0

    def get_stable_ping_state(self, current_state):
        observed_state = self.ping_dut()
        if observed_state == current_state:
            return current_state

        for _ in range(self.PING_STABLE_COUNT - 1):
            if self.ping_dut() != observed_state:
                return current_state

        self.log("DUT ping state changed to {}".format(
            "reachable" if observed_state else "unreachable"))
        return observed_state

    def get_cpa_state(self):
        everflow_acl_state = self.get_everflow_acl_state()
        vxlan_state = self.check_neighbor_advertise_vxlan()

        if everflow_acl_state is None or vxlan_state is None:
            return None
        elif everflow_acl_state and vxlan_state:
            return True
        return False

    def get_everflow_acl_state(self):
        try:
            output, _, return_code = self.dut_connection.execCommand(
                'aclshow -a', timeout=3)
        except Exception:
            return None
        if not output or return_code != 0:
            return None
        result = parse_show(output)

        if len(result) == 0:
            self.log("Failed to retrieve acl counter {}".format(output))
            return False
        for rule in result:
            if "EVERFLOW" == rule['table name'] and "rule_arp" == rule['rule name']:
                self.log("retrieve rule_arp EVERFLOW counter {}".format(
                    rule['packets count']))
                if rule['packets count'] == 'N/A':
                    return False
                else:
                    return True
        # warm reboot may not started, or warm reboot finished
        self.log("Failed to retrieve acl counter for EVERFLOW|rule_arp")
        return False

    def check_neighbor_advertise_vxlan(self):
        try:
            output, _, return_code = self.dut_connection.execCommand(
                'show vxlan name {}'.format(self.VXLAN_TUNNEL_NAME), timeout=3)
        except Exception:
            return None
        if not output or return_code != 0:
            return None
        result = parse_show(output)
        return len(result) > 0

    # master branch return None
    def get_release_version(self):
        output, _, _ = self.dut_connection.execCommand(
            "sonic-cfggen -y /etc/sonic/sonic_version.yml -v release")
        if len(output) == 0:
            return None
        return output[0]

    def get_warm_restart_state(self):
        output, _, _ = self.dut_connection.execCommand(
            "sonic-db-cli STATE_DB hget 'WARM_RESTART_ENABLE_TABLE|system' enable")

        if len(output) == 0:
            self.assertTrue(
                False, "Failed to get warm restart state {}".format(output))

        return True if "true" in output else False
