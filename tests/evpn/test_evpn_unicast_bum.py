import logging

import pytest
import time


import ptf.testutils as testutils

from conftest import PCH_Param
from conftest import evpn_neighbor_list
from conftest import DUT_VTEP_IP, NUM_CONTINUOUS_PKT_COUNT

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]


class Test_Unicast_BUM_in_L2_VNI():
    # constant
    INDEX_OF_PORT_SEND = 3
    VLAN_ID = 1000
    vni = 10000
    VLAN_IP = "192.168.0.1"
    pch_param = PCH_Param([2, 3], "PortChannel1", "pch1")

    @pytest.fixture(scope="class")
    def setup_ptf(self, evpn_env, neighbor_size, setup_dut):
        neighbor_list = evpn_neighbor_list[:1] if neighbor_size == "one_neighbor" else evpn_neighbor_list
        evpn_env.setup_ptf_base(neighbor_list)
        yield
        evpn_env.teardown_ptf_base(neighbor_list)

    @pytest.fixture(scope="class")
    def setup_dut(self, evpn_env, neighbor_size):
        neighbor_list = evpn_neighbor_list[:1] if neighbor_size == "one_neighbor" else evpn_neighbor_list
        evpn_env.setup_dut_base(neighbor_list)
        yield
        evpn_env.teardown_dut_base(neighbor_list)

    @pytest.fixture(scope="class")
    def set_portchannel(self, access_ports_type, evpn_env):
        if access_ports_type == "with_portchannel":
            logging.info("Create portchannel in ptf and dut.")
            evpn_env.create_portchannels_and_start(pch_param_list=[self.pch_param])
            logging.info("Restart ptf_nn_agent.")
            evpn_env.ptf_helper.restart_ptf_nn_agent()
            logging.info("portchannel vlan setup")
            evpn_env.dut_helper.add_portchannel_to_vlan(self.pch_param.dut_pch_name, vlanid=1000, untagged=True)
            time.sleep(5)
        yield
        if access_ports_type == "with_portchannel":
            logging.info("portchannel vlan teardown")
            evpn_env.dut_helper.del_portchannel_from_vlan(self.pch_param.dut_pch_name, vlanid=1000)
            logging.info("Remove portchannel in ptf and dut")
            evpn_env.remove_portchannel(pch_param_list=[self.pch_param])
            logging.info("Restart ptf_nn_agent.")
            evpn_env.ptf_helper.restart_ptf_nn_agent()
            time.sleep(5)

    @pytest.fixture(scope="class", autouse=True)
    def setup_and_teardown(self, setup_ptf, neighbor_size, access_ports_type, set_portchannel, evpn_env):
        neighbor_list = evpn_neighbor_list[:1] if neighbor_size == "one_neighbor" else evpn_neighbor_list

        logging.info("Add type 3 route for transporting packet")
        for item in neighbor_list:
            port = item.gobgp_port
            as_number = item.as_number_ptf
            ip = str(item.ip_ptf.ip)
            evpn_env.gobgp_helper.add_type3(as_ptf=as_number, vni=self.vni, vtep_ip=ip, gobgp_port=port)

        yield

        logging.info("Delete type 3 route for recover")
        for item in neighbor_list:
            port = item.gobgp_port
            as_number = item.as_number_ptf
            ip = str(item.ip_ptf.ip)
            evpn_env.gobgp_helper.del_type3(as_ptf=as_number, vni=self.vni, vtep_ip=ip, gobgp_port=port)

    test_data = [("FF:FF:FF:FF:FF:FF", "255.255.255.255"),
                 ("00:11:22:33:55:99", "192.168.0.99"),
                 ("01:00:5e:01:01:01", "225.1.1.1")]
    test_id = ["Broadcast",
               "Unknown unicast",
               "Multicast"]

    @pytest.mark.parametrize("pkt_dst_mac, pkt_dst_ip", test_data, ids=test_id)
    def test_BUM_in_l2_vni(self, ptfhost, duthost, ptfadapter, pkt_dst_mac, pkt_dst_ip, neighbor_size, access_ports_type, evpn_env):
        neighbor_list = evpn_neighbor_list[:1] if neighbor_size == "one_neighbor" else evpn_neighbor_list
        index_of_port_vxlan = neighbor_list[0][0]
        vtep_ip = str(neighbor_list[0][1].ip)

        # send packet from local
        logging.info("BUM encap: local to remote; BUM decap: local to local")
        # the port index represented remote vtep in ptf, which will receive vxlan packet
        received_port_list = [item[0] for item in neighbor_list]
        # the remainder ports which in the same vlan
        port_index_list = [index for index in range(1, 25) if index not in received_port_list]

        access_port_list = [self.INDEX_OF_PORT_SEND] if access_ports_type == "normal_port" \
            else self.pch_param.member_index_list

        # remove the port which sends the packet
        for port in access_port_list:
            port_index_list.remove(port)
        # add ports which will receive the untagged packet
        received_port_list.extend(port_index_list)

        pkt_untagged = testutils.simple_udp_packet(
            eth_dst=pkt_dst_mac,
            eth_src="00:11:22:33:55:66",
            ip_dst=pkt_dst_ip,
            ip_src="192.168.100.1",
        )

        # the packet that received in remote
        expected_packet_list = []
        for item in neighbor_list:
            ptf_vtep_index = item[0]
            # mac for vxlan tunnel
            dut_mac = evpn_env.dut_helper.get_index_mac(ptf_vtep_index)
            ptf_mac = evpn_env.ptf_helper.get_index_mac(ptf_vtep_index)
            ip = str(item[1].ip)
            pkt_expected_vxlan = evpn_env.pkt_helper.compose_expected_vxlan_packet(
                outer_sa=dut_mac,
                outer_da=ptf_mac,
                outer_sip=DUT_VTEP_IP,
                outer_dip=ip,
                vni=self.vni,
                pkt=pkt_untagged,
                GPE_flag=True)
            expected_packet_list.append(pkt_expected_vxlan)
        # the packets received in local
        expected_packet_list.extend([pkt_untagged] * (len(received_port_list) - len(neighbor_list)))

        # check packet [remote pkt, local pkt, local pkt, ...] in [port 1, port 2, port 3, ...] and not received in other ports.
        for port in access_port_list:
            logging.info("expected received from port {}".format(received_port_list))
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, port, pkt_untagged)
            testutils.verify_each_packet_on_each_port(ptfadapter, expected_packet_list, received_port_list)

        # send packet from remote
        logging.info("BUM decap: remote to local; BUM encap: remote to remote")
        pkt_vxlan, pkt_untagged = evpn_env.pkt_helper.create_vxlan_packet(
            outer_da=dut_mac,
            outer_sa=ptf_mac,
            outer_dip=DUT_VTEP_IP,
            outer_sip=vtep_ip,
            vni=self.vni,
            inner_da=pkt_dst_mac,
            inner_dip=pkt_dst_ip)

        vtep_index_list = [item[0] for item in neighbor_list]

        # for untagged packet
        received_port_list = [index for index in range(1, 25) if index not in vtep_index_list]
        expected_packet_list = [pkt_untagged] * len(received_port_list)

        # check packet is received in all vlan member
        if access_ports_type == "normal_port":
            logging.info("expected received from {}".format(received_port_list))
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, index_of_port_vxlan, pkt_vxlan)
            testutils.verify_each_packet_on_each_port(ptfadapter, expected_packet_list, received_port_list)
        elif access_ports_type == "with_portchannel":
            # pkt_num = 20
            packet_count = 0
            ptfadapter.dataplane.flush()
            for j in range(0, NUM_CONTINUOUS_PKT_COUNT):
                pkt_vxlan['UDP'].sport = pkt_vxlan['UDP'].sport + 1
                testutils.send(ptfadapter, index_of_port_vxlan, pkt_vxlan)
                index, _ = evpn_env.pkt_helper.verify_packet_count(pkt_untagged, self.pch_param.member_index_list[0])
                packet_count = packet_count + index
            assert packet_count != 0
            # FIXME
            # assert testutils.count_matched_packets_all_ports(ptfadapter, pkt_untagged, PORTCHANNEL_PORT_LIST, timeout = 10) == 20

    def test_unicast_in_l2_vni(self, duthost, ptfadapter, neighbor_size, access_ports_type, evpn_env):
        neighbor_list = evpn_neighbor_list[:1] if neighbor_size == "one_neighbor" else evpn_neighbor_list

        # for packet from local to remote
        dst_mac_1 = "00:11:22:33:33:33"
        dst_ip_1 = "192.168.1.10"

        # for packet from remote to local
        dst_mac_2 = "00:11:22:33:33:44"
        dst_ip_2 = "192.168.1.20"

        access_port_list = [self.INDEX_OF_PORT_SEND] if access_ports_type == "normal_port" \
            else self.pch_param.member_index_list

        # local -> remote #
        for item in neighbor_list:
            ptf_vtep_index = item.if_index
            ptf_vtep_ip = str(item.ip_ptf.ip)
            ptf_vtep_as = item.as_number_ptf
            gobgp_port = item.gobgp_port
            dut_mac = evpn_env.dut_helper.get_index_mac(ptf_vtep_index)
            ptf_mac = evpn_env.ptf_helper.get_index_mac(ptf_vtep_index)
            logging.info("encap test: local to remote, index:{}, gobgp port:{}".format(ptf_vtep_index, gobgp_port))
            # let dut learn mac route from remote
            evpn_env.gobgp_helper.add_type2(dst_mac_1, dst_ip_1, None, as_ptf=ptf_vtep_as, vni=self.vni, vtep_ip=ptf_vtep_ip, gobgp_port=gobgp_port)

            # tagged packet is for sending
            pkt_untagged = testutils.simple_udp_packet(
                eth_dst=dst_mac_1,
                eth_src="00:11:22:33:55:66",
                ip_dst=dst_ip_1,
                ip_src="192.168.100.1",
            )

            # expected packet is for receiving
            pkt_expected = evpn_env.pkt_helper.compose_expected_vxlan_packet(
                outer_sa=dut_mac,
                outer_da=ptf_mac,
                outer_sip=DUT_VTEP_IP,
                outer_dip=ptf_vtep_ip,
                vni=self.vni,
                pkt=pkt_untagged,
                GPE_flag=False)

            for port in access_port_list:
                ptfadapter.dataplane.flush()
                testutils.send(ptfadapter, port, pkt_untagged)
                testutils.verify_packets(ptfadapter, pkt_expected, [ptf_vtep_index])

            # recover
            evpn_env.gobgp_helper.del_type2(dst_mac_1, dst_ip_1, None, as_ptf=ptf_vtep_as, vni=self.vni, vtep_ip=ptf_vtep_ip, gobgp_port=gobgp_port)

        # remote -> local #
        # let dut learn mac route from local
        pkt = testutils.simple_arp_packet(
            eth_src=dst_mac_2,
            vlan_vid=self.VLAN_ID,
            arp_op=1,
            ip_snd=dst_ip_2,
            ip_tgt=self.VLAN_IP,
            hw_snd=dst_mac_2,
        )

        # vxlan packet is for sending
        for item in neighbor_list:
            ptf_vtep_index = item.if_index
            ptf_vtep_ip = str(item.ip_ptf.ip)
            ptf_vtep_as = item.as_number_ptf
            gobgp_port = item.gobgp_port

            dut_mac = evpn_env.dut_helper.get_index_mac(ptf_vtep_index)
            ptf_mac = evpn_env.ptf_helper.get_index_mac(ptf_vtep_index)

            pkt_vxlan, pkt_expected = evpn_env.pkt_helper.create_vxlan_packet(
                outer_da=dut_mac,
                outer_sa=ptf_mac,
                outer_dip=DUT_VTEP_IP,
                outer_sip=ptf_vtep_ip,
                vni=self.vni,
                inner_sa="00:11:22:33:55:66",
                inner_sip="192.168.0.44",
                inner_da=dst_mac_2,
                inner_dip=dst_ip_2)

            # port move from local to remote. mac="00:11:22:33:55:66" because it is the src mac of the packet sent in local->remote

            logging.info("decap test: remote to local, index:{}, gobgp port:{}".format(ptf_vtep_index, gobgp_port))

            for send_port in access_port_list:
                testutils.send(ptfadapter, send_port, pkt)
                evpn_env.gobgp_helper.add_type2("00:11:22:33:55:66", "192.168.0.44", None, as_ptf=ptf_vtep_as, vni=self.vni, vtep_ip=ptf_vtep_ip, gobgp_port=gobgp_port)
                try:
                    evpn_env.pkt_helper.verify_decap_receive_packet(ptf_vtep_index, access_port_list, pkt_vxlan, pkt_expected)
                finally:
                    evpn_env.gobgp_helper.del_type2("00:11:22:33:55:66", "192.168.0.44", None, as_ptf=ptf_vtep_as, vni=self.vni, vtep_ip=ptf_vtep_ip, gobgp_port=gobgp_port)
