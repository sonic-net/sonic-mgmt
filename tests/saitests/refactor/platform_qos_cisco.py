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

import time
import ptf.packet as scapy
from scapy.all import Ether, IP
from ptf.testutils import send_packet
from ptf.mask import Mask
from switch import port_list, sai_thrift_read_queue_occupancy


#
# Cisco specific functions
#


def fill_leakout_plus_one(test_case, src_port_id, dst_port_id, pkt, queue, asic_type, pkts_num_egr_mem=None):
    # Attempts to queue 1 packet while compensating for a varying packet leakout.
    # Returns whether 1 packet was successfully enqueued.
    if pkts_num_egr_mem is not None:
        if test_case.clients["dst"] != test_case.clients["src"]:
            fill_egress_plus_one(test_case, src_port_id, pkt, queue, asic_type, int(pkts_num_egr_mem))
        return

    queue_counters_base = sai_thrift_read_queue_occupancy(test_case.dst_client, "dst", dst_port_id)
    max_packets = 500
    for packet_i in range(max_packets):
        send_packet(test_case, src_port_id, pkt, 1)
        queue_counters = sai_thrift_read_queue_occupancy(test_case.clients["dst"], "dst", dst_port_id)
        if queue_counters[queue] > queue_counters_base[queue]:
            print(
                "fill_leakout_plus_one: Success, sent %d packets, "
                "queue occupancy bytes rose from %d to %d"
                % (packet_i + 1, queue_counters_base[queue], queue_counters[queue]),
                file=sys.stderr,
            )
            return True
    raise RuntimeError(
        "fill_leakout_plus_one: Fail: src_port_id:{}"
        " dst_port_id:{}, pkt:{}, queue:{}".format(src_port_id, dst_port_id, pkt.__repr__()[0:180], queue)
    )


def fill_egress_plus_one(test_case, src_port_id, pkt, queue, asic_type, pkts_num_egr_mem):
    # Attempts to enqueue 1 packet while compensating for a varying packet leakout and egress queues.
    # pkts_num_egr_mem is the number of packets in full egress queues, to provide an initial filling boost
    # Returns whether 1 packet is successfully enqueued.
    if asic_type not in ["cisco-8000"]:
        return False
    pg_cntrs_base = test_case.sai_thrift_read_pg_occupancy(test_case.src_client, port_list["src"][src_port_id])
    send_packet(test_case, src_port_id, pkt, pkts_num_egr_mem)
    max_packets = 1000
    for packet_i in range(max_packets):
        send_packet(test_case, src_port_id, pkt, 1)
        pg_cntrs = test_case.sai_thrift_read_pg_occupancy(test_case.src_client, port_list["src"][src_port_id])
        if pg_cntrs[queue] > pg_cntrs_base[queue]:
            print(
                "fill_egress_plus_one: Success, sent %d packets, SQ occupancy bytes rose from %d to %d"
                % (pkts_num_egr_mem + packet_i + 1, pg_cntrs_base[queue], pg_cntrs[queue]),
                file=sys.stderr,
            )
            return True
    raise RuntimeError(
        "fill_egress_plus_one: Failure, sent %d packets, SQ occupancy bytes rose from %d to %d"
        % (pkts_num_egr_mem + max_packets, pg_cntrs_base[queue], pg_cntrs[queue])
    )


def overflow_egress(test_case, src_port_id, pkt, queue, asic_type):
    # Attempts to queue 1 packet while compensating for a varying packet
    # leakout and egress queues. Returns pkts_num_egr_mem: number of packets
    # short of filling egress memory and leakout.
    # Returns extra_bytes_occupied:
    #    extra number of bytes occupied in source port
    pkts_num_egr_mem = 0
    extra_bytes_occupied = 0
    if asic_type not in ["cisco-8000"]:
        return pkts_num_egr_mem, extra_bytes_occupied

    pg_cntrs_base = test_case.sai_thrift_read_pg_occupancy(test_case.src_client, port_list["src"][src_port_id])
    max_cycles = 1000
    for cycle_i in range(max_cycles):
        send_packet(test_case, src_port_id, pkt, 1000)
        pg_cntrs = testcase.sai_thrift_read_pg_occupancy(test_case.src_client, port_list["src"][src_port_id])
        if pg_cntrs[queue] > pg_cntrs_base[queue]:
            print(
                "get_pkts_num_egr_mem: Success, sent %d packets, "
                "SQ occupancy bytes rose from %d to %d" % ((cycle_i + 1) * 1000, pg_cntrs_base[queue], pg_cntrs[queue]),
                file=sys.stderr,
            )
            pkts_num_egr_mem = cycle_i * 1000
            extra_bytes_occupied = pg_cntrs[queue] - pg_cntrs_base[queue]
            print(
                "overflow_egress:pkts_num_egr_mem:{}, extra_bytes_occupied:{}".format(
                    pkts_num_egr_mem, extra_bytes_occupied
                )
            )
            return pkts_num_egr_mem, extra_bytes_occupied
    raise RuntimeError("Couldn't overflow the egress memory after 1000 iterations.")


from platform_qos_base import PlatformQosBase


class PlatformQosCisco(PlatformQosBase):

    hwsku_name = ["Cisco-8102-C64"]

    #
    # PD methods
    #

    def disable_port_transmit(self, client, asic_type, port_list):
        # generate pkts_num_egr_mem in runtime
        if hasattr(self.testcase, "src_dst_asic_diff") and self.testcase.src_dst_asic_diff:
            self.testcase.sai_thrift_port_tx_disable(client, asic_type, port_list)
            pkts_num_egr_mem, extra_bytes_occupied = overflow_egress(
                self.testcase, src_port_id, pkt, int(self.testcase.test_params["pg"]), asic_type
            )
            self.testcase.sai_thrift_port_tx_enable(client, asic_type, port_list)
            time.sleep(2)
        super().disable_port_transmit(client, asic_type, port_list)

    def fill_leakout(self, src_port_id, dst_port_id, packet, pg, asic_type, pkts_num_egr_mem):
        # For some platform, prefer handle leakout before send_packet
        fill_leakout_plus_one(self.testcase, src_port_id, dst_port_id, packet, pg, asic_type, pkts_num_egr_mem)
        # One extra packet is sent to fill the leakout, and number of extra packet is returned to the caller,
        # so that the caller knows to send one less packet next time.
        return 1
