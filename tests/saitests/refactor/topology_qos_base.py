#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import time

from ptf.testutils import send_packet

from platform_qos_base import PlatformQosBase


#
# topology common function
#


def get_rx_port(dp, device_number, src_port_id, dst_mac, dst_ip, src_ip, src_vlan=None):
    ip_id = 0xBABE
    src_port_mac = dp.dataplane.get_mac(device_number, src_port_id)

    pkt = dp.platform.build_packet(64, dst_mac, src_port_mac, src_ip, dst_ip, 0, src_vlan, ip_id=ip_id)
    # Send initial packet for any potential ARP resolution, which may cause the LAG
    # destination to change. Can occur especially when running tests in isolation on a
    # first test attempt.
    send_packet(dp, src_port_id, pkt, 1)
    # Observed experimentally this sleep needs to be at least 0.02 seconds. Setting higher.
    time.sleep(1)
    send_packet(dp, src_port_id, pkt, 1)

    masked_exp_pkt = dp.platform.build_packet(
        48, dst_mac, src_port_mac, src_ip, dst_ip, 0, src_vlan, ip_id=ip_id, exp_pkt=True
    )

    pre_result = dp.dataplane.poll(device_number=0, exp_pkt=masked_exp_pkt, timeout=3)
    result = dp.dataplane.poll(device_number=0, exp_pkt=masked_exp_pkt, timeout=3)
    if pre_result.port != result.port:
        logging.debug(
            "During get_rx_port, corrected LAG destination from {} to {}".format(pre_result.port, result.port)
        )
    if isinstance(result, dp.dataplane.PollFailure):
        dp.fail("Expected packet was not received. Received on port:{} {}".format(result.port, result.format()))

    return result.port


class TopologyQosBase:

    #
    # common topology functions
    #

    def populate_arp(self):
        pass

    def detect_rx_port(self):
        return get_rx_port(
            self.testcase,
            0,
            self.testcase.src_port_id,
            self.testcase.pkt_dst_mac,
            self.testcase.dst_port_ip,
            self.testcase.src_port_ip,
            self.testcase.src_port_vlan,
        )
