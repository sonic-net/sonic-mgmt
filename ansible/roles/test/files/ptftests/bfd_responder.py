# PTF bfd responder. Responds to any BFD packet that we received.
# Uses a monitor file as input. The monitor file has 2 lines:
#   Line 1: list of port indices to monitor
#   Line 2: list of ip addresses to respond to.

import ptf
import time
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from scapy.contrib.bfd import BFD
from ptf.testutils import (send_packet, test_params_get)
from ipaddress import ip_address, IPv4Address, IPv6Address
session_timeout = 1


class BFD_Responder(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.DEFAULT_PKT_LEN = 100
        self.sessions = {}
        self.local_disc_base = 0xcdba0000
        self.local_src_port = 14000

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        self.dut_mac = self.test_params['dut_mac']
        self.dut_loop_ips = self.test_params['dut_loop_ips']
        for ipaddr in self.dut_loop_ips:
            if isinstance(ip_address(ipaddr.decode()), IPv4Address):
                self.dut_loop_ipv4 = ipaddr
            if isinstance(ip_address(ipaddr.decode()), IPv6Address):
                self.dut_loop_ipv6 = ipaddr
        self.monitor_file = self.test_params['monitor_file']

    def respond_to_packet(self, port_number, received_pkt):
        received_pkt = scapy.Ether(received_pkt)
        args = {}
        args['dst_mac'] = received_pkt['Ether'].dst
        args['version'] = received_pkt['BFD'].version
        args['diag'] = received_pkt['BFD'].diag
        args['sta'] = received_pkt['BFD'].sta
        args['flags'] = received_pkt['BFD'].flags
        args['detect_multi'] = received_pkt['BFD'].detect_multi
        args['len'] = received_pkt['BFD'].len
        args['my_discriminator'] = received_pkt['BFD'].my_discriminator
        args['your_discriminator'] = received_pkt['BFD'].your_discriminator
        args['min_tx_interval'] = received_pkt['BFD'].min_tx_interval
        args['min_rx_interval'] = received_pkt['BFD'].min_rx_interval
        args['echo_rx_interval'] = received_pkt['BFD'].echo_rx_interval

        pkt = BFD(args)
        count = send_packet(self, port_number, str(pkt))
        if count == 0:
            raise RuntimeError(
                "send_packet failed args:port_number{}, "
                "dp_tuple:{}".format(port_number, str(pkt)))

    def runTest(self):
        while True:
            valid_monit_file = True
            with open(self.monitor_file) as fd:
                full_strings = fd.readlines()
            try:
                ports_to_monitor = full_strings[0].strip()
                all_monitored_addresses = full_strings[1].strip()
            except IndexError:
                valid_monit_file = False
            if ports_to_monitor == "" or all_monitored_addresses == "":
                valid_monit_file = False

            if not valid_monit_file:
                time.sleep(1)
                continue
            ports_to_monitor = [int(x) for x in ports_to_monitor.split(',')]
            all_monitored_addresses = all_monitored_addresses.split(',')

            result = self.dataplane.poll(device_number=0, timeout=0.1)
            if not isinstance(result, self.dataplane.PollSuccess) or \
                    result.port not in ports_to_monitor or \
                    "UDP" not in scapy.Ether(result.packet):
                continue
            if scapy.Ether(result.packet)['UDP'].dport != 4784:
                continue
            received_pkt = result.packet
            port_number = result.port
            mac_src, mac_dst, ip_src, ip_dst,  bfd_remote_disc, bfd_state = \
                self.extract_bfd_info(received_pkt)
            if ip_dst not in all_monitored_addresses:
                continue
            try:
                session = self.sessions[ip_dst]
            except KeyError:
                self.sessions[ip_dst] = {}

            if bfd_state == 3:
                count = send_packet(self, result.port, str(session["pkt"]))
                if count == 0:
                    raise RuntimeError(
                        "send_packet failed args:port_number{}, "
                        "dp_tuple:{}".format(port_number, str(session['pkt'])))

            if bfd_state == 2:
                continue

            session = {}
            if self.sessions[ip_dst] != {}:
                session['my_disc'] = self.sessions[ip_dst]['my_disc']
                session["src_port"] = self.sessions[ip_dst]["src_port"]
            else:
                session["src_port"] = self.local_src_port
                self.local_disc_base += 1
                self.local_src_port += 1
                session['my_disc'] = self.local_disc_base

            session['addr'] = ip_dst
            session['remote_addr'] = ip_src
            session['intf'] = result.port
            session['multihop'] = True
            session['mac'] = mac_dst
            session['pkt'] = ''
            session["other_disc"] = bfd_remote_disc

            bfd_pkt_init = self.craft_bfd_packet(
                session['my_disc'],
                received_pkt,
                mac_src,
                mac_dst,
                ip_src,
                ip_dst,
                bfd_remote_disc,
                2)
            count = send_packet(self, session['intf'], str(bfd_pkt_init))
            if count == 0:
                raise RuntimeError(
                    "send_packet failed args:port_number{}, "
                    "dp_tuple:{}".format(port_number, str(bfd_pkt_init)))
            bfd_pkt_init.payload.payload.payload.load.sta = 3
            session["pkt"] = bfd_pkt_init
            self.sessions[ip_dst] = session

    def extract_bfd_info(self, data):
        # remote_mac, remote_ip, request_ip, op_type
        ether = scapy.Ether(data)
        mac_src = ether.src
        mac_dst = ether.dst
        ip_src = ether.payload.src
        ip_dst = ether.payload.dst
        bfdpkt = BFD(ether.payload.payload.payload.load)
        bfd_remote_disc = bfdpkt.my_discriminator
        bfd_state = bfdpkt.sta
        return mac_src, mac_dst, ip_src, ip_dst, bfd_remote_disc, bfd_state

    def craft_bfd_packet(self,
                         my_discriminator,
                         data,
                         mac_src,
                         mac_dst,
                         ip_src,
                         ip_dst,
                         bfd_remote_disc,
                         bfd_state):
        ethpart = scapy.Ether(data)
        bfdpart = BFD(ethpart.payload.payload.payload.load)
        bfdpart.my_discriminator = my_discriminator
        bfdpart.your_discriminator = bfd_remote_disc
        bfdpart.sta = bfd_state

        ethpart.payload.payload.payload.load = bfdpart
        ethpart.src = mac_dst
        ethpart.dst = mac_src
        ethpart.payload.src = ip_dst
        ethpart.payload.dst = ip_src
        return ethpart
