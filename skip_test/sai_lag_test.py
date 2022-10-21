"""
Skip test for broadcom, can't disable ingress of lag member
Item: 14988584
"""
class DisableIngressTest(T0TestBase):
    """
    When disable ingress on a lag member, we expect traffic drop on the disabled lag member.
    """

    def setUp(self):
        """
        Test the basic setup process
        """                        
        T0TestBase.setUp(
            self,
            skip_reason = "SKIP! Skip test for broadcom, can't disable ingress of lag member. Item: 14988584")

    def runTest(self):
        """
        1. Generate different packets by updating src_port
        2. send these packets on port 18
        3. Check if packets are received on port1
        4. Disable port18 ingress
        5. Generate same different packets in step 1 by updating src_port
        6. send these packets on port 18
        7. Check if packets are received on port1
        """
        try:
            print("Lag disable ingress lag member test")
            
            pkts_num = 10
            begin_port = 2000
            for i in range(0, pkts_num):
                src_port = begin_port + i
                pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                        eth_src=self.servers[11][1].l3_lag_obj.neighbor_mac,
                                        ip_dst=self.servers[1][1].ipv4,
                                        ip_src=self.servers[11][1].ipv4,
                                        tcp_sport=src_port,
                                        ip_id=105,
                                        ip_ttl=64)
                exp_pkt = simple_tcp_packet(eth_dst=self.servers[1][1].mac,
                                            eth_src=ROUTER_MAC,
                                            ip_dst=self.servers[1][1].ipv4,
                                            ip_src=self.servers[11][1].ipv4,
                                            tcp_sport=src_port,
                                            ip_id=105,
                                            ip_ttl=63)
                send_packet(self, self.dut.port_obj_list[18].dev_port_index, pkt)
                verify_packet(self, exp_pkt, self.dut.port_obj_list[1].dev_port_index)
            # git disable ingress of lag member: port18
            print("disable port18 ingress")
            status = sai_thrift_set_lag_member_attribute(
                self.client, self.lag_list[0].lag_members[1], ingress_disable=True)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            for i in range(0, pkts_num):
                src_port = begin_port + i
                pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                        eth_src=self.servers[11][1].l3_lag_obj.neighbor_mac,
                                        ip_dst=self.servers[1][1].ipv4,
                                        ip_src=self.servers[11][1].ipv4,
                                        tcp_sport=src_port,
                                        ip_id=105,
                                        ip_ttl=64)
                exp_pkt = simple_tcp_packet(eth_dst=self.servers[1][1].mac,
                                            eth_src=ROUTER_MAC,
                                            ip_dst=self.servers[1][1].ipv4,
                                            ip_src=self.servers[11][1].ipv4,
                                            tcp_sport=src_port,
                                            ip_id=105,
                                            ip_ttl=63)
                send_packet(self, self.dut.port_obj_list[18].dev_port_index, pkt)
                verify_no_packet(self, exp_pkt, self.dut.port_obj_list[1].dev_port_index)
        finally:
            pass

    def tearDown(self):
        super().tearDown()
        