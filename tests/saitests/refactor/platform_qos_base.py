#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

# The modules sai_base_test.py, switch.py, and texttable.py are already available in the legacy directory (../py3).
# To avoid maintaining duplicate files in the refactor directory, we import these modules from the legacy directory.
# Once the refactor directory is stable and the migration is complete, we can consider moving these files to the
# refactor directory.
# Somehow, relative paths may not be correctly resolved, leading to modules not being found.
# Using absolute paths ensures that the paths are correctly resolved, allowing the modules to be imported.
current_dir = os.path.dirname(os.path.abspath(__file__))
legacy_dir = os.path.abspath(os.path.join(current_dir, "../py3"))
sys.path.append(legacy_dir)

import ptf.packet as scapy
from scapy.all import Ether, IP

import sai_base_test
from ptf.testutils import send_packet, simple_ip_packet
from ptf.mask import Mask


#
# common function
#


def construct_ip_pkt(pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs):
    ecn = kwargs.get("ecn", 1)
    ip_id = kwargs.get("ip_id", None)
    ttl = kwargs.get("ttl", None)
    exp_pkt = kwargs.get("exp_pkt", False)

    tos = (dscp << 2) | ecn
    pkt_args = {
        "pktlen": pkt_len,
        "eth_dst": dst_mac,
        "eth_src": src_mac,
        "ip_src": src_ip,
        "ip_dst": dst_ip,
        "ip_tos": tos,
    }
    if ip_id is not None:
        pkt_args["ip_id"] = ip_id

    if ttl is not None:
        pkt_args["ip_ttl"] = ttl

    if src_vlan is not None:
        pkt_args["dl_vlan_enable"] = True
        pkt_args["vlan_vid"] = int(src_vlan)
        pkt_args["vlan_pcp"] = dscp

    pkt = simple_ip_packet(**pkt_args)

    if exp_pkt:
        masked_exp_pkt = Mask(pkt, ignore_extra_bytes=True)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        if src_vlan is not None:
            masked_exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
        return masked_exp_pkt
    else:
        return pkt


from qos_helper import log_message


class PlatformQosBase:

    #
    # PI methods
    #

    def build_param(self):
        pass

    def disable_port_transmit(self, client, asic_type, port_list):
        sai_base_test.sai_thrift_port_tx_disable(client, asic_type, port_list)

    def enable_port_transmit(self, client, asic_type, port_list):
        sai_base_test.sai_thrift_port_tx_enable(client, asic_type, port_list)

    def build_packet(self, pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs):
        return construct_ip_pkt(pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs)

    def fill_leakout(self, src_port_id, dst_port_id, packet, pg, asic_type, pkts_num_egr_mem):
        # For some platform, prefer handle leakout before sending packets, by default it does nothing.
        # If a specific platform requires a different approach to handle leakout,
        # override this method in the platform-specific class.
        return 0

    def send_packet(self, port, packet, packet_number):
        send_packet(self.testcase, port, packet, packet_number)

    def compensate_leakout(self):
        # For some platform, prefer handle leakout after sending packets, by default it does nothing.
        # If a specific platform requires a different approach to handle leakout,
        # override this method in the platform-specific class.
        pass
