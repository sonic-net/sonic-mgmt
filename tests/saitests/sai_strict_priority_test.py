"""PTF dataplane test for strict priority scheduling validation.

This test class is invoked by the pytest test in test_qos_strict_priority.py.
It sends traffic across multiple traffic classes to the same egress port and
verifies that strict priority ordering is maintained.

Covers issue #22405:
https://github.com/sonic-net/sonic-mgmt/issues/22405
"""

import logging
import time
import json

from ptf.testutils import send_packet, simple_tcp_packet
import ptf.testutils as testutils
from sai_qos_tests import QosTestBase


class StrictPriorityTest(QosTestBase):
    """Verify default strict priority scheduling across traffic classes.

    Sends equal traffic volumes for each TC to the same egress port under
    congestion and verifies that higher priority TCs are served first.

    Required test parameters:
        dst_port_id (int): Destination port ID
        dst_port_ip (str): Destination port IP
        src_port_id (int): Source port ID
        src_port_ip (str): Source port IP
        src_port_vlan (str/None): Source port VLAN
        pkts_num_leak_out (int): Number of leak out packets
        pkt_count (int): Number of test packets per TC (default: 10000)
        packet_size (int): Packet size in bytes (default: 64)
        test_queues (list): Queue indices to test in descending priority
            order (default: [7, 6, 5, 4, 3, 2, 1, 0])
        dscp_list (list): DSCP values corresponding to each queue in
            test_queues (default: [56, 48, 40, 32, 24, 16, 8, 0])
        tolerance (int): Tolerance percentage for throughput comparison
            (default: 10)
        dry_run (bool): If True, skip validation (used to warm up queues)
    """

    def setUp(self):
        QosTestBase.setUp(self)

        self.dst_port_id = int(self.test_params['dst_port_id'])
        self.dst_port_ip = self.test_params['dst_port_ip']
        self.src_port_id = int(self.test_params['src_port_id'])
        self.src_port_ip = self.test_params['src_port_ip']
        self.src_port_vlan = self.test_params.get('src_port_vlan')
        self.pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        self.pkt_count = int(self.test_params.get('pkt_count', 10000))
        self.packet_size = int(self.test_params.get('packet_size', 64))
        self.dry_run = self.test_params.get('dry_run', False)

        # Queue indices to test, in descending priority order
        default_queues = [7, 6, 5, 4, 3, 2, 1, 0]
        self.test_queues = self.test_params.get('test_queues', default_queues)
        if isinstance(self.test_queues, str):
            self.test_queues = json.loads(self.test_queues)
        self.test_queues = [int(q) for q in self.test_queues]

        # DSCP values corresponding to each queue
        default_dscps = [56, 48, 40, 32, 24, 16, 8, 0]
        self.dscp_list = self.test_params.get('dscp_list', default_dscps)
        if isinstance(self.dscp_list, str):
            self.dscp_list = json.loads(self.dscp_list)
        self.dscp_list = [int(d) for d in self.dscp_list]

        assert len(self.test_queues) == len(self.dscp_list), \
            "test_queues and dscp_list must have the same length"

        self.tolerance = int(self.test_params.get('tolerance', 10))

    def runTest(self):
        """
        Test Procedure:
        1. Clear queue counters on the egress port.
        2. For each TC (from highest to lowest priority), send pkt_count
           packets with the corresponding DSCP value to the same egress port.
           All packets use the same src/dst port to create congestion.
        3. Wait for all packets to be processed.
        4. Read queue counters from the egress port.
        5. Verify strict priority ordering:
           - packets_forwarded[TC_high] >= packets_forwarded[TC_low]
             for all adjacent TC pairs.
           - The highest priority TC achieves near line-rate throughput.
        """
        # Step 1: Clear queue counters
        self.sai_thrift_clear_queue_counters(self.dst_port_id)

        # Step 2: Send traffic for each TC
        for i, queue_idx in enumerate(self.test_queues):
            dscp = self.dscp_list[i]
            pkt = self.construct_tcp_pkt(
                src_port=self.src_port_id,
                dst_port_ip=self.dst_port_ip,
                src_port_ip=self.src_port_ip,
                dscp=dscp,
                pkt_size=self.packet_size,
                vlan=self.src_port_vlan
            )
            logging.info(
                "Sending %d packets for queue %d (DSCP %d)",
                self.pkt_count, queue_idx, dscp
            )
            # Send leak out packets first, then test packets
            total_pkts = self.pkts_num_leak_out + self.pkt_count
            send_packet(self, self.src_port_id, pkt, total_pkts)

        # Step 3: Wait for processing
        time.sleep(8)

        # Step 4: Read queue counters
        queue_counters = self.sai_thrift_read_queue_counters(self.dst_port_id)

        logging.info("Queue counters after strict priority test:")
        for i, queue_idx in enumerate(self.test_queues):
            count = queue_counters.get(queue_idx, 0)
            logging.info("  Queue %d (TC%d): %d packets", queue_idx, queue_idx, count)

        if self.dry_run:
            logging.info("Dry run complete - skipping validation")
            return

        # Step 5: Validate strict priority ordering
        for i in range(len(self.test_queues) - 1):
            high_q = self.test_queues[i]
            low_q = self.test_queues[i + 1]
            high_count = queue_counters.get(high_q, 0)
            low_count = queue_counters.get(low_q, 0)

            logging.info(
                "Comparing Queue %d (%d pkts) >= Queue %d (%d pkts)",
                high_q, high_count, low_q, low_count
            )
            assert high_count >= low_count, \
                "Strict priority violation: Queue {} ({} pkts) should have " \
                ">= throughput than Queue {} ({} pkts)".format(
                    high_q, high_count, low_q, low_count
                )

        # Verify highest priority queue gets near line-rate
        highest_q = self.test_queues[0]
        highest_count = queue_counters.get(highest_q, 0)
        expected_min = self.pkt_count * (100 - self.tolerance) / 100
        assert highest_count >= expected_min, \
            "Highest priority Queue {} should receive near line-rate. " \
            "Expected >= {} packets, got {}".format(
                highest_q, int(expected_min), highest_count
            )

        logging.info(
            "Strict priority test PASSED: all queues served in correct "
            "descending priority order"
        )
