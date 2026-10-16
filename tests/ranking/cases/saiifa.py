#
# The below software in this distribution may have been modified
# by Clounix ("Clounix Modifications"). All Clounix Modifications
# are copyright © Clounix(Shanghai) Technology Limited.
#

"""
Thrift SAI interface IFA tests
"""
"""
1.ifa模块测试需要在fun_profile中配置SAI_TWAMP_NTP_SYNC_INTRVAL参数，单位是s，表示ctc SAI侧将系统时间同步给芯片的时间间隔
2.fun_profile中SAI_INT_METADATA_TIMESTAMP_GRANULARITY可以配置时戳精度，TS 32bit s+ns组合如下：
 1）0(2,30)：2bitS(4s) +30bit ns(1ns粒度)
 2）1(5,37): 2bitS(4s) +27bit ns(8ns粒度)
 3）2(8,24): 2bitS(4s) +24bit ns(64ns粒度)
 4）3(11,21): 11bitS(2048s) +21bit ns(512ns粒度)
Latency 32bits(32ns粒度)
3.如果配置时戳精度模式为3，由于时戳粒度为512ns，通常会大于实际报文pipeline消耗时长，因此int报文 metadata中的出入时间戳一样，此时可参考Latency*32ns计算pipeline耗时。

"""
from sai_thrift.sai_headers import *

from sai_base_test import *
from ptf import packet
from ptf.mask import Mask
import ctypes
import random

def hex_to_ascii(h):
    hexstr = hex(h)
    return hexstr_to_ascii(hexstr[2:])

def ifa2_udp_packet(pktlen=82, eth_dst='00:01:02:03:04:05', eth_src='00:06:07:08:09:0a',
                    dl_vlan_enable=False, vlan_pcp=0, vlan_vid=0,
                    ip_src='192.168.0.1', ip_dst='192.168.0.2', ip_dscp=None, ip_ecn=None, ip_ttl=64,
                    udp_sport=1234, udp_dport=80, ip_proto=253, with_ifa_ih = True, with_ifa_imh = True, with_ifa_ims = True,
                    request_vector=0x3f, hop_limit=5, max_length=42, current_length=7,
                    metadata='eeeeeeee1111111122222222333333334444444455555555ffffffff'):

    ifa_header = chr(0x2f) + chr(0x11) + chr(0x00) + chr(max_length)
    metadata_header = chr(request_vector) + chr(0x00) + chr(hop_limit) + chr(current_length)
    udp_hdr = packet.UDP(sport=udp_sport, dport=udp_dport, chksum=0)
    ip_tos = ip_make_tos(0, ip_ecn, ip_dscp)
    pkt = packet.Ether(dst=eth_dst, src=eth_src)
    if (dl_vlan_enable or vlan_vid or vlan_pcp):
        pkt /= packet.Dot1Q(prio=vlan_pcp, vlan=vlan_vid)
    pkt /= packet.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, proto=ip_proto)
    if with_ifa_ih:
        pkt /= ifa_header
        pkt /= udp_hdr
        if with_ifa_imh:
            pkt /= metadata_header
        if with_ifa_ims:
            pkt /= hexstr_to_ascii(metadata).encode('latin1')
    else:
        pkt /= udp_hdr
    pkt = pkt/(chr(0) * (pktlen - len(pkt)))
    return pkt

def ifa2_udpv6_packet(pktlen=82, eth_dst='00:01:02:03:04:05', eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False, vlan_pcp=0, vlan_vid=0, ipv6_dscp=None, ipv6_ecn=None, ip_ttl=64,
                      ip_src='2001:db8:85a3::8a2e:370:7334', ip_dst='2001:db8:85a3::8a2e:370:7335',
                      udp_sport=1234, udp_dport=80, ip_proto=253, with_ifa_ih = True, with_ifa_imh = True, with_ifa_ims = True,
                      request_vector=0x3f, hop_limit=5, max_length=42, current_length=7,
                      metadata='eeeeeeee1111111122222222333333334444444455555555ffffffff'):

    ifa_header = chr(0x2f) + chr(0x11) + chr(0x00) + chr(max_length)
    metadata_header = chr(request_vector) + chr(0x00) + chr(hop_limit) + chr(current_length)
    udp_hdr = packet.UDP(sport=udp_sport, dport=udp_dport, chksum=0)
    ipv6_tc = ip_make_tos(0, ipv6_ecn, ipv6_dscp)
    pkt = packet.Ether(dst=eth_dst, src=eth_src)
    if (dl_vlan_enable or vlan_vid or vlan_pcp):
        pkt /= packet.Dot1Q(prio=vlan_pcp, vlan=vlan_vid)
    pkt /= packet.IPv6(src=ip_src, dst=ip_dst, tc=ipv6_tc, nh=ip_proto, hlim=ip_ttl)
    if with_ifa_ih:
        pkt /= ifa_header
        pkt /= udp_hdr
        if with_ifa_imh:
            pkt /= metadata_header
        if with_ifa_ims:
            pkt /= hexstr_to_ascii(metadata).encode('latin1')
    else:
        pkt /= udp_hdr
    pkt = pkt/(chr(0) * (pktlen - len(pkt)))
    return pkt

@group("draft")
class IFAv2TransitNode(SaiHelperSimplified):
    '''
    Verify ifa2.0 inband transit node function
    '''
    def setUp(self):
        super(IFAv2TransitNode, self).setUp()

        self.create_routing_interfaces(ports=[0, 1])
        device_id = 0x12345678
        self.l3_protocol = 253
        self.int_oid = sai_thrift_create_tam_int(self.client, type=SAI_TAM_INT_TYPE_IFA2,
                                            name_space_id=0xf, device_id=device_id, inline=False,
                                            int_presence_type=SAI_TAM_INT_PRESENCE_TYPE_L3_PROTOCOL,
                                            int_presence_l3_protocol=(ctypes.c_int8(self.l3_protocol)).value)

        if get_platform() == "clx":
            self.tam_oid = sai_thrift_create_tam(self.client)
            tam_int_list = sai_thrift_object_list_t(count=1, idlist=[self.int_oid])
            sai_thrift_set_tam_attribute(self.client, self.tam_oid, int_objects_list=tam_int_list)

            tam_list = sai_thrift_object_list_t(count=1, idlist=[self.tam_oid])
            sai_thrift_set_port_attribute(self.client, self.port0, tam_object=tam_list)

        self.ip_addr_subnet = '172.16.10.0/24'
        self.ip_addr = '172.16.10.1'
        self.dmac = '00:11:22:33:44:55'
        self.mac_src = '00:22:22:22:22:22'
        self.ip_addr_src = '192.168.100.100'

        print("Create neighbor with %s ip address, %d router interface"
              " id and %s destination mac" % (
                  self.ip_addr, self.port1_rif, self.dmac))
        self.nbr_entry = sai_thrift_neighbor_entry_t(
            rif_id=self.port1_rif,
            ip_address=sai_ipaddress(self.ip_addr))
        sai_thrift_create_neighbor_entry(
            self.client, self.nbr_entry, dst_mac_address=self.dmac)

        print("Create nhop with %s ip address and %d router"
              " interface id" % (self.ip_addr, self.port1_rif))
        self.nhop = sai_thrift_create_next_hop(
            self.client, ip=sai_ipaddress(self.ip_addr),
            router_interface_id=self.port1_rif,
            type=SAI_NEXT_HOP_TYPE_IP)

        print("Create route with %s ip prefix and %d router"
              " interface id" % (self.ip_addr_subnet, self.port1_rif))
        self.route_entry = sai_thrift_route_entry_t(
            vr_id=self.default_vrf, destination=sai_ipprefix(
                self.ip_addr_subnet))
        sai_thrift_create_route_entry(self.client, self.route_entry,
                                      next_hop_id=self.nhop)

        self.ipv6_addr = '1234:5678:9abc:def0:4422:1133:5577:99aa'
        self.ipv6_mask = '/112'
        self.ipv6_addr_src = '2001:db8:85a3::8a2e:370:7335'

        self.v6nbr_entry = sai_thrift_neighbor_entry_t(
            rif_id=self.port1_rif,
            ip_address=sai_ipaddress(self.ipv6_addr))
        sai_thrift_create_neighbor_entry(
            self.client, self.v6nbr_entry, dst_mac_address=self.dmac)

        print("Create nhop with %s ip address and %d router"
              " interface id" % (self.ipv6_addr, self.port1_rif))
        self.nhopv6 = sai_thrift_create_next_hop(
            self.client, ip=sai_ipaddress(self.ipv6_addr),
            router_interface_id=self.port1_rif,
            type=SAI_NEXT_HOP_TYPE_IP)

        print("Create route with %s ip prefix and %d router"
              " interface id" % (self.ipv6_addr, self.port1_rif))
        self.route_entryv6 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf, destination=sai_ipprefix(
                self.ipv6_addr + self.ipv6_mask))
        sai_thrift_create_route_entry(self.client, self.route_entryv6,
                                      next_hop_id=self.nhopv6)

        print("Create ACL tables groups")
        group_stage_ingress = SAI_ACL_STAGE_INGRESS
        group_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL
        group_bind_point_type_list = sai_thrift_s32_list_t(
            count=len(group_bind_point_list), int32list=group_bind_point_list)
        self.acl_group_ingress = sai_thrift_create_acl_table_group(
            self.client,
            acl_stage=group_stage_ingress,
            acl_bind_point_type_list=group_bind_point_type_list,
            type=group_type)
        # create ipv4 ACL table
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_points = [SAI_ACL_BIND_POINT_TYPE_PORT]
        table_bind_point_type_list = sai_thrift_s32_list_t(
            count=len(table_bind_points), int32list=table_bind_points)
        self.acl_table_v4 = sai_thrift_create_acl_table(
            self.client,
            acl_stage=table_stage,
            acl_bind_point_type_list=table_bind_point_type_list,
            size=256,
            field_src_ip=True,
            field_dst_ip=True,
            field_ip_protocol=True,
            field_dscp=True,
            field_ecn=True,
            field_l4_src_port=True,
            field_l4_dst_port=True,
            field_acl_ip_type=True)
        # create ipv6 ACL table
        self.acl_table_v6 = sai_thrift_create_acl_table(
            self.client,
            acl_stage=table_stage,
            acl_bind_point_type_list=table_bind_point_type_list,
            size=256,
            field_src_ipv6=True,
            field_dst_ipv6=True,
            field_ip_protocol=True,
            field_dscp=True,
            field_ecn=True)
        # create ACL table group members
        print("Create ACL group members")
        self.acl_group_ingress_ipv4_member_id = \
            sai_thrift_create_acl_table_group_member(
                self.client,
                acl_table_group_id=self.acl_group_ingress,
                acl_table_id=self.acl_table_v4,
                priority=100)
        self.acl_group_ingress_ipv6_member_id = \
            sai_thrift_create_acl_table_group_member(
                self.client,
                acl_table_group_id=self.acl_group_ingress,
                acl_table_id=self.acl_table_v6,
                priority=100)
        # create ipv4 ACL table entry
        dst_ip_mask = '255.255.255.255'
        dst_ip_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(ip4=self.ip_addr),
            mask=sai_thrift_acl_field_data_mask_t(ip4=dst_ip_mask))
        field_dscp = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(u8=63),
            mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xff)).value))
        field_ecn = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(u8=1),
            mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xf)).value))
        int_insert_action = sai_thrift_acl_action_data_t(
            enable=True,
            parameter=sai_thrift_acl_action_parameter_t(
                s32=SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT))
        tam_int_object_action = sai_thrift_acl_action_data_t(
            enable=True,
            parameter=sai_thrift_acl_action_parameter_t(
                oid=self.int_oid))
        self.acl_entry = sai_thrift_create_acl_entry(
            self.client,
            table_id=self.acl_table_v4,
            priority=10,
            field_dst_ip=dst_ip_t,
            # field_dscp=field_dscp,
            field_ecn=field_ecn,
            action_int_insert=int_insert_action,
            action_tam_int_object=tam_int_object_action
            )
        # create ACL counter
        self.acl_counter_ingress = sai_thrift_create_acl_counter(
            self.client, table_id=self.acl_table_v4,enable_packet_count=True, enable_byte_count=True)
        # attach ACL counter to ipv4 ACL entry
        action_counter_ingress = sai_thrift_acl_action_data_t(
            parameter=sai_thrift_acl_action_parameter_t(
                oid=self.acl_counter_ingress),
            enable=True)


        sai_thrift_set_acl_entry_attribute(
            self.client, self.acl_entry,
            action_counter=action_counter_ingress)
        # create ipv6 ACL table entry
        self.dst_ipv6_mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        dst_ipv6_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(ip6=self.ipv6_addr),
            mask=sai_thrift_acl_field_data_mask_t(ip6=self.dst_ipv6_mask))
        field_dscp_v6 = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(u8=62),
            mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xff)).value))
        field_ecn_v6 = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(u8=2),
            mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xf)).value))
        self.acl_entry_v6 = sai_thrift_create_acl_entry(
            self.client,
            table_id=self.acl_table_v6,
            priority=10,
            field_dst_ipv6=dst_ipv6_t,
            # field_dscp=field_dscp_v6,
            field_ecn=field_ecn_v6,
            action_int_insert=int_insert_action,
            action_tam_int_object=tam_int_object_action
            )
        # create ACL counter for ipv6
        self.acl_counter_ingress_v6 = sai_thrift_create_acl_counter(
            self.client, table_id=self.acl_table_v6,enable_packet_count=True, enable_byte_count=True)
        # attach ACL counter to ACL entry for ipv6
        action_counter_ingress_v6 = sai_thrift_acl_action_data_t(
            parameter=sai_thrift_acl_action_parameter_t(
                oid=self.acl_counter_ingress_v6),
            enable=True)
        sai_thrift_set_acl_entry_attribute(
            self.client, self.acl_entry_v6,
            action_counter=action_counter_ingress_v6)
        # bind ACL table group to ingress port 0

        sai_thrift_set_port_attribute(
            self.client, self.port0, ingress_acl=self.acl_group_ingress)

    def tearDown(self):
        # unbind this ACL table from rif_id1s object id
        sai_thrift_set_port_attribute(
            self.client, self.port0, ingress_acl=int(SAI_NULL_OBJECT_ID))
        # cleanup ipv4 ACL
        action_counter_ingress = sai_thrift_acl_action_data_t(
            parameter=sai_thrift_acl_action_parameter_t(
                oid=0),
            enable=True)
        sai_thrift_set_acl_entry_attribute(
            self.client, self.acl_entry,
            action_counter=action_counter_ingress)
        sai_thrift_set_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=0)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=True)
        self.assertEqual(packets['packets'], 0)
        sai_thrift_remove_acl_counter(self.client, self.acl_counter_ingress)
        sai_thrift_remove_acl_entry(self.client, self.acl_entry)
        # cleanup ipv6 ACL
        action_counter_ingress_v6 = sai_thrift_acl_action_data_t(
            parameter=sai_thrift_acl_action_parameter_t(
                oid=0),
            enable=True)
        sai_thrift_set_acl_entry_attribute(
            self.client, self.acl_entry_v6,
            action_counter=action_counter_ingress_v6)
        sai_thrift_set_acl_counter_attribute(
            self.client, self.acl_counter_ingress_v6, packets=0)
        packets_v6 = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress_v6, packets=True)
        self.assertEqual(packets_v6['packets'], 0)
        sai_thrift_remove_acl_counter(self.client, self.acl_counter_ingress_v6)
        sai_thrift_remove_acl_entry(self.client, self.acl_entry_v6)
        sai_thrift_remove_acl_table_group_member(
            self.client, self.acl_group_ingress_ipv4_member_id)
        sai_thrift_remove_acl_table_group_member(
            self.client, self.acl_group_ingress_ipv6_member_id)
        sai_thrift_remove_acl_table(self.client, self.acl_table_v4)
        sai_thrift_remove_acl_table(self.client, self.acl_table_v6)
        sai_thrift_remove_acl_table_group(self.client, self.acl_group_ingress)
        sai_thrift_remove_route_entry(self.client, self.route_entry)
        sai_thrift_remove_route_entry(self.client, self.route_entryv6)
        sai_thrift_remove_next_hop(self.client, self.nhop)
        sai_thrift_remove_next_hop(self.client, self.nhopv6)
        sai_thrift_remove_neighbor_entry(self.client, self.nbr_entry)
        sai_thrift_remove_neighbor_entry(self.client, self.v6nbr_entry)
        self.destroy_routing_interfaces()
        if get_platform() == "clx":
            tam_list = sai_thrift_object_list_t(count=0, idlist=[])
            sai_thrift_set_port_attribute(self.client, self.port0, tam_object=tam_list)
            tam_int_list = sai_thrift_object_list_t(count=0, idlist=[])
            sai_thrift_set_tam_attribute(self.client, self.tam_oid, int_objects_list=tam_int_list)
            sai_thrift_remove_tam(self.client, self.tam_oid)
        sai_thrift_remove_tam_int(self.client, self.int_oid)
        super(IFAv2TransitNode, self).tearDown()

    def gen_metadata(self,length=7):
        '''
        generate metadata
        '''
        hex_chars='0123456789abcdef'
        metadata_str = ''.join(random.choice(hex_chars) for _ in range(length))
        return metadata_str

@group("draft")
class IFAv2TransitNodeIPv4Test(IFAv2TransitNode):
    '''
    Verify that ifa transit node can insert ifa metadata correctly when forwarding ipv4 ifa packet.
    '''
    def setUp(self):
        super(IFAv2TransitNodeIPv4Test, self).setUp()

    def runTest(self):
        print("IFAv2TransitNodeIPv4Test")
        print("Sending packet on port %d, forward" % self.dev_port0)
        pkt_length1=100
        metadata1_num=7
        metadata1 = self.gen_metadata(length=metadata1_num*8)
        metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
        pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                    eth_src=self.mac_src,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=64,
                                    pktlen=pkt_length1,
                                    ip_proto=self.l3_protocol,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    hop_limit=5,
                                    max_length=42,
                                    current_length=metadata1_num,
                                    metadata=metadata1)
        pkt_transit = Mask(ifa2_udp_packet(eth_dst=self.dmac,
                                    eth_src=ROUTER_MAC,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=63,
                                    pktlen=pkt_length1+len(metadata2)//2,
                                    ip_proto=self.l3_protocol,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    hop_limit=4,
                                    max_length=42,
                                    current_length=metadata1_num+len(metadata2)//8,
                                    metadata=metadata2+metadata1))

        pkt_transit.set_do_not_care(400,256)

        send_packet(self, self.dev_port0, pkt_initiator)
        verify_packet(self, pkt_transit, self.dev_port1)
        time.sleep(1)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=True)
        self.assertEqual(packets['packets'], 1)

    def tearDown(self):
        super(IFAv2TransitNodeIPv4Test, self).tearDown()

@group("draft")
class IFAv2TransitMultiMSIPv4Test(IFAv2TransitNode):
    '''
    Verify that ifa transit node can insert ifa metadata correctly when forwarding ipv4 ifa packet with multi-layers IMS.
    '''
    def setUp(self):
        super(IFAv2TransitMultiMSIPv4Test, self).setUp()

    def runTest(self):
        print("IFAv2TransitNodeIPv4Test")
        print("Sending packet on port %d, forward" % self.dev_port0)
        metadata1_num=119
        metadata1 = self.gen_metadata(length=metadata1_num*8)
        pkt_length1=100+len(metadata1)//2
        metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
        pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                    eth_src=self.mac_src,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=64,
                                    pktlen=pkt_length1,
                                    ip_proto=self.l3_protocol,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    hop_limit=2,
                                    max_length=127,
                                    current_length=metadata1_num,
                                    metadata=metadata1)
        pkt_transit = Mask(ifa2_udp_packet(eth_dst=self.dmac,
                                    eth_src=ROUTER_MAC,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=63,
                                    pktlen=pkt_length1+len(metadata2)//2,
                                    ip_proto=self.l3_protocol,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    hop_limit=1,
                                    max_length=127,
                                    current_length=metadata1_num+len(metadata2)//8,
                                    metadata=metadata2+metadata1))

        pkt_transit.set_do_not_care(400,256)
        send_packet(self, self.dev_port0, pkt_initiator)
        verify_packet(self, pkt_transit, self.dev_port1)
        time.sleep(1)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=True)
        self.assertEqual(packets['packets'], 1)

    def tearDown(self):
        super(IFAv2TransitMultiMSIPv4Test, self).tearDown()

@group("draft")
class IFAv2TransitSingleMSIPv6Test(IFAv2TransitNode):
    '''
    Verify that ifa transit node can insert ifa metadata correctly when forwarding ipv4 ifa packet with IMS.
    '''
    def setUp(self):
        super(IFAv2TransitSingleMSIPv6Test, self).setUp()

    def runTest(self):
        print("IFAv2TransitSingleMSIPv6Test")
        print("Sending packet on port %d, forward" % self.dev_port0)
        metadata1_num=7
        metadata1 = self.gen_metadata(length=metadata1_num*8)
        pkt_length1=100+len(metadata1)//2
        metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
        pkt_initiator = ifa2_udpv6_packet(eth_dst=ROUTER_MAC,
                                    eth_src=self.mac_src,
                                    ip_dst=self.ipv6_addr,
                                    ip_src=self.ipv6_addr_src,
                                    ip_ttl=64,
                                    pktlen=pkt_length1,
                                    ip_proto=self.l3_protocol,
                                    ipv6_dscp=62,
                                    ipv6_ecn=2,
                                    hop_limit=5,
                                    max_length=42,
                                    current_length=metadata1_num,
                                    metadata=metadata1)
        pkt_transit = Mask( ifa2_udpv6_packet(eth_dst=self.dmac,
                                    eth_src=ROUTER_MAC,
                                    ip_dst=self.ipv6_addr,
                                    ip_src=self.ipv6_addr_src,
                                    ip_ttl=63,
                                    pktlen=pkt_length1+len(metadata2)//2,
                                    ip_proto=self.l3_protocol,
                                    ipv6_dscp=62,
                                    ipv6_ecn=2,
                                    hop_limit=4,
                                    max_length=42,
                                    current_length=metadata1_num+len(metadata2)//8,
                                    metadata=metadata2+metadata1))
        pkt_transit.set_do_not_care(552,256)
        send_packet(self, self.dev_port0, pkt_initiator)
        verify_packet(self, pkt_transit, self.dev_port1)
        time.sleep(1)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress_v6, packets=True)
        self.assertEqual(packets['packets'], 1)

    def tearDown(self):
        super(IFAv2TransitSingleMSIPv6Test, self).tearDown()

@group("draft")
class IFAv2TransitMultiMSIPv6Test(IFAv2TransitNode):
    '''
    Verify that ifa transit node can insert ifa metadata correctly when forwarding ipv6 ifa packet with multi-layers IMS.
    '''
    def setUp(self):
        super(IFAv2TransitMultiMSIPv6Test, self).setUp()

    def runTest(self):
        print("IFAv2TransitMultiMSIPv6Test")
        print("Sending packet on port %d, forward" % self.dev_port0)
        metadata1_num=119
        metadata1 = self.gen_metadata(length=metadata1_num*8)
        pkt_length1=100+len(metadata1)//2
        metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
        pkt_initiator = ifa2_udpv6_packet(eth_dst=ROUTER_MAC,
                                    eth_src=self.mac_src,
                                    ip_dst=self.ipv6_addr,
                                    ip_src=self.ipv6_addr_src,
                                    ip_ttl=64,
                                    pktlen=pkt_length1,
                                    ip_proto=self.l3_protocol,
                                    ipv6_dscp=62,
                                    ipv6_ecn=2,
                                    hop_limit=2,
                                    max_length=127,
                                    current_length=metadata1_num,
                                    metadata=metadata1)
        pkt_transit = Mask(ifa2_udpv6_packet(eth_dst=self.dmac,
                                    eth_src=ROUTER_MAC,
                                    ip_dst=self.ipv6_addr,
                                    ip_src=self.ipv6_addr_src,
                                    ip_ttl=63,
                                    pktlen=pkt_length1+len(metadata2)//2,
                                    ip_proto=self.l3_protocol,
                                    ipv6_dscp=62,
                                    ipv6_ecn=2,
                                    hop_limit=1,
                                    max_length=127,
                                    current_length=metadata1_num+len(metadata2)//8,
                                    metadata=metadata2+metadata1))
        pkt_transit.set_do_not_care(552,256)
        send_packet(self, self.dev_port0, pkt_initiator)
        verify_packet(self, pkt_transit, self.dev_port1)
        time.sleep(1)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress_v6, packets=True)
        self.assertEqual(packets['packets'], 1)

    def tearDown(self):
        super(IFAv2TransitMultiMSIPv6Test, self).tearDown()

@group("draft")
class IFAv2TransitNodeMultiSession(SaiHelperSimplified):
    '''
    Verify creating multi-acl entry for ifa transit action and inserting ifa metadata correctly.
    '''
    def setUp(self):
        super(IFAv2TransitNodeMultiSession, self).setUp()

        self.create_routing_interfaces(ports=[0, 1])

        device_id = 0x12345678
        self.l3_protocol = 253
        self.int_oid = sai_thrift_create_tam_int(self.client, type=SAI_TAM_INT_TYPE_IFA2,
                                            name_space_id=0xf, device_id=device_id, inline=False,
                                            int_presence_type=SAI_TAM_INT_PRESENCE_TYPE_L3_PROTOCOL,
                                            int_presence_l3_protocol=(ctypes.c_int8(self.l3_protocol)).value)

        if get_platform() == "clx":
            self.tam_oid = sai_thrift_create_tam(self.client)
            tam_int_list = sai_thrift_object_list_t(count=1, idlist=[self.int_oid])
            sai_thrift_set_tam_attribute(self.client, self.tam_oid, int_objects_list=tam_int_list)

            tam_list = sai_thrift_object_list_t(count=1, idlist=[self.tam_oid])
            sai_thrift_set_port_attribute(self.client, self.port0, tam_object=tam_list)

        self.ip_addr_subnet = '172.16.10.0/24'
        self.ip_addr = '172.16.10.1'
        self.dmac = '00:11:22:33:44:55'
        self.mac_src = '00:22:22:22:22:22'
        self.ip_addr_src = '192.168.100.100'

        print("Create neighbor with %s ip address, %d router interface"
              " id and %s destination mac" % (
                  self.ip_addr, self.port1_rif, self.dmac))
        self.nbr_entry = sai_thrift_neighbor_entry_t(
            rif_id=self.port1_rif,
            ip_address=sai_ipaddress(self.ip_addr))
        sai_thrift_create_neighbor_entry(
            self.client, self.nbr_entry, dst_mac_address=self.dmac)

        print("Create nhop with %s ip address and %d router"
              " interface id" % (self.ip_addr, self.port1_rif))
        self.nhop = sai_thrift_create_next_hop(
            self.client, ip=sai_ipaddress(self.ip_addr),
            router_interface_id=self.port1_rif,
            type=SAI_NEXT_HOP_TYPE_IP)

        print("Create route with %s ip prefix and %d router"
              " interface id" % (self.ip_addr_subnet, self.port1_rif))
        self.route_entry = sai_thrift_route_entry_t(
            vr_id=self.default_vrf, destination=sai_ipprefix(
                self.ip_addr_subnet))
        sai_thrift_create_route_entry(self.client, self.route_entry,
                                      next_hop_id=self.nhop)

        self.ipv6_addr = '1234:5678:9abc:def0:4422:1133:5577:99aa'
        self.ipv6_mask = '/112'
        self.ipv6_addr_src = '2001:db8:85a3::8a2e:370:7335'
        self.dst_ipv6_mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

        self.v6nbr_entry = sai_thrift_neighbor_entry_t(
            rif_id=self.port1_rif,
            ip_address=sai_ipaddress(self.ipv6_addr))
        sai_thrift_create_neighbor_entry(
            self.client, self.v6nbr_entry, dst_mac_address=self.dmac)

        print("Create nhop with %s ip address and %d router"
              " interface id" % (self.ipv6_addr, self.port1_rif))
        self.nhopv6 = sai_thrift_create_next_hop(
            self.client, ip=sai_ipaddress(self.ipv6_addr),
            router_interface_id=self.port1_rif,
            type=SAI_NEXT_HOP_TYPE_IP)

        print("Create route with %s ip prefix and %d router"
              " interface id" % (self.ipv6_addr, self.port1_rif))
        self.route_entryv6 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf, destination=sai_ipprefix(
                self.ipv6_addr + self.ipv6_mask))
        sai_thrift_create_route_entry(self.client, self.route_entryv6,
                                      next_hop_id=self.nhopv6)

        dst_ipv6_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(ip6=self.ipv6_addr),
            mask=sai_thrift_acl_field_data_mask_t(ip6=self.dst_ipv6_mask))

        print("Create ACL tables groups")
        group_stage_ingress = SAI_ACL_STAGE_INGRESS
        group_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL
        group_bind_point_type_list = sai_thrift_s32_list_t(
            count=len(group_bind_point_list), int32list=group_bind_point_list)
        self.acl_group_ingress = sai_thrift_create_acl_table_group(
            self.client,
            acl_stage=group_stage_ingress,
            acl_bind_point_type_list=group_bind_point_type_list,
            type=group_type)
        # create ipv4 ACL table
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_points = [SAI_ACL_BIND_POINT_TYPE_PORT]
        table_bind_point_type_list = sai_thrift_s32_list_t(
            count=len(table_bind_points), int32list=table_bind_points)
        self.acl_table_v4 = sai_thrift_create_acl_table(
            self.client,
            acl_stage=table_stage,
            acl_bind_point_type_list=table_bind_point_type_list,
            size=256,
            field_src_ip=True,
            field_dst_ip=True,
            field_ip_protocol=True,
            field_dscp=True,
            field_ecn=True,
            field_l4_src_port=True,
            field_l4_dst_port=True,
            field_acl_ip_type=True)
        # create ipv6 ACL table
        self.acl_table_v6 = sai_thrift_create_acl_table(
            self.client,
            acl_stage=table_stage,
            acl_bind_point_type_list=table_bind_point_type_list,
            size=256,
            field_src_ipv6=True,
            field_dst_ipv6=True,
            field_ip_protocol=True,
            field_dscp=True,
            field_ecn=True)
        # create ACL table group members
        print("Create ACL group members")
        self.acl_group_ingress_ipv4_member_id = \
            sai_thrift_create_acl_table_group_member(
                self.client,
                acl_table_group_id=self.acl_group_ingress,
                acl_table_id=self.acl_table_v4,
                priority=100)
        self.acl_group_ingress_ipv6_member_id = \
            sai_thrift_create_acl_table_group_member(
                self.client,
                acl_table_group_id=self.acl_group_ingress,
                acl_table_id=self.acl_table_v6,
                priority=100)
        # create ipv4 ACL table entry
        dst_ip_mask = '255.255.255.255'
        dst_ip_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(ip4=self.ip_addr),
            mask=sai_thrift_acl_field_data_mask_t(ip4=dst_ip_mask))
        int_insert_action = sai_thrift_acl_action_data_t(
            enable=True,
            parameter=sai_thrift_acl_action_parameter_t(
                s32=SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT))
        tam_int_object_action = sai_thrift_acl_action_data_t(
            enable=True,
            parameter=sai_thrift_acl_action_parameter_t(
                oid=self.int_oid))

        self.ipv4_acl_entries_dict={}
        self.ipv4_acl_counter_ingress_dict={}
        self.ipv6_acl_entries_dict={}
        self.ipv6_acl_counter_ingress_dict={}
        for dscp_value in range(64):
            self.ipv4_acl_entries_dict[dscp_value]={}
            self.ipv4_acl_counter_ingress_dict[dscp_value]={}
            self.ipv6_acl_entries_dict[dscp_value]={}
            self.ipv6_acl_counter_ingress_dict[dscp_value]={}
            for ecn_value in range(4):
                field_dscp = sai_thrift_acl_field_data_t(
                    enable=True,
                    data=sai_thrift_acl_field_data_data_t(u8=dscp_value),
                    mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xff)).value))
                field_ecn = sai_thrift_acl_field_data_t(
                    enable=True,
                    data=sai_thrift_acl_field_data_data_t(u8=ecn_value),
                    mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xf)).value))
                self.ipv4_acl_entries_dict[dscp_value][ecn_value] = sai_thrift_create_acl_entry(
                    self.client,
                    table_id=self.acl_table_v4,
                    priority=10,
                    field_dst_ip=dst_ip_t,
                    field_dscp=field_dscp,
                    field_ecn=field_ecn,
                    action_int_insert=int_insert_action,
                    action_tam_int_object=tam_int_object_action
                    )
                # create ACL counter
                self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value] = sai_thrift_create_acl_counter(
                    self.client, table_id=self.acl_table_v4,enable_packet_count=True, enable_byte_count=True)
                # attach ACL counter to ipv4 ACL entry
                action_counter_ingress = sai_thrift_acl_action_data_t(
                    parameter=sai_thrift_acl_action_parameter_t(
                        oid=self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value]),
                    enable=True)
                sai_thrift_set_acl_entry_attribute(
                    self.client, self.ipv4_acl_entries_dict[dscp_value][ecn_value],
                    action_counter=action_counter_ingress)
                # create ipv6 ACL table entry
                self.ipv6_acl_entries_dict[dscp_value][ecn_value] = sai_thrift_create_acl_entry(
                    self.client,
                    table_id=self.acl_table_v6,
                    priority=10,
                    field_dst_ipv6=dst_ipv6_t,
                    field_dscp=field_dscp,
                    field_ecn=field_ecn,
                    action_int_insert=int_insert_action,
                    action_tam_int_object=tam_int_object_action
                    )
                # create ACL counter for ipv6
                self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value] = sai_thrift_create_acl_counter(
                    self.client, table_id=self.acl_table_v6,enable_packet_count=True, enable_byte_count=True)
                # attach ACL counter to ACL entry for ipv6
                action_counter_ingress_v6 = sai_thrift_acl_action_data_t(
                    parameter=sai_thrift_acl_action_parameter_t(
                        oid=self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value]),
                    enable=True)
                sai_thrift_set_acl_entry_attribute(
                    self.client, self.ipv6_acl_entries_dict[dscp_value][ecn_value],
                    action_counter=action_counter_ingress_v6)
        # bind ACL table group to ingress port 0
        sai_thrift_set_port_attribute(
            self.client, self.port0, ingress_acl=self.acl_group_ingress)

    def tearDown(self):
        # unbind this ACL table from rif_id1s object id
        sai_thrift_set_port_attribute(
            self.client, self.port0, ingress_acl=int(SAI_NULL_OBJECT_ID))
        # cleanup ipv4 ACL
        action_counter_ingress = sai_thrift_acl_action_data_t(
            parameter=sai_thrift_acl_action_parameter_t(
                oid=0),
            enable=True)
        for dscp_value in range(64):
            for ecn_value in range(4):
                sai_thrift_set_acl_entry_attribute(
                    self.client, self.ipv4_acl_entries_dict[dscp_value][ecn_value],
                    action_counter=action_counter_ingress)
                sai_thrift_set_acl_counter_attribute(
                    self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                packets = sai_thrift_get_acl_counter_attribute(
                    self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                self.assertEqual(packets['packets'], 0)
                sai_thrift_remove_acl_counter(self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value])
                sai_thrift_remove_acl_entry(self.client, self.ipv4_acl_entries_dict[dscp_value][ecn_value])
                # cleanup ipv6 ACL
                action_counter_ingress_v6 = sai_thrift_acl_action_data_t(
                    parameter=sai_thrift_acl_action_parameter_t(
                        oid=0),
                    enable=True)
                sai_thrift_set_acl_entry_attribute(
                    self.client, self.ipv6_acl_entries_dict[dscp_value][ecn_value],
                    action_counter=action_counter_ingress_v6)
                sai_thrift_set_acl_counter_attribute(
                    self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                packets_v6 = sai_thrift_get_acl_counter_attribute(
                    self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                self.assertEqual(packets_v6['packets'], 0)
                sai_thrift_remove_acl_counter(self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value])
                sai_thrift_remove_acl_entry(self.client, self.ipv6_acl_entries_dict[dscp_value][ecn_value])

        sai_thrift_remove_acl_table_group_member(
            self.client, self.acl_group_ingress_ipv4_member_id)
        sai_thrift_remove_acl_table_group_member(
            self.client, self.acl_group_ingress_ipv6_member_id)
        sai_thrift_remove_acl_table(self.client, self.acl_table_v4)
        sai_thrift_remove_acl_table(self.client, self.acl_table_v6)
        sai_thrift_remove_acl_table_group(self.client, self.acl_group_ingress)
        sai_thrift_remove_route_entry(self.client, self.route_entry)
        sai_thrift_remove_route_entry(self.client, self.route_entryv6)
        sai_thrift_remove_next_hop(self.client, self.nhop)
        sai_thrift_remove_next_hop(self.client, self.nhopv6)
        sai_thrift_remove_neighbor_entry(self.client, self.nbr_entry)
        sai_thrift_remove_neighbor_entry(self.client, self.v6nbr_entry)
        self.destroy_routing_interfaces()
        if get_platform() == "clx":
            tam_list = sai_thrift_object_list_t(count=0, idlist=[])
            sai_thrift_set_port_attribute(self.client, self.port0, tam_object=tam_list)
            tam_int_list = sai_thrift_object_list_t(count=0, idlist=[])
            sai_thrift_set_tam_attribute(self.client, self.tam_oid, int_objects_list=tam_int_list)
            sai_thrift_remove_tam(self.client, self.tam_oid)
        sai_thrift_remove_tam_int(self.client, self.int_oid)
        super(IFAv2TransitNodeMultiSession, self).tearDown()

    def gen_metadata(self,length=7):
        '''
        generate metadata
        '''
        hex_chars='0123456789abcdef'
        metadata_str = ''.join(random.choice(hex_chars) for _ in range(length))
        return metadata_str

@group("draft")
class IFAv2TransitMultiAclEntryTest(IFAv2TransitNodeMultiSession):
    '''
    Verify creating multi-acl entry for ifa transit action and inserting ifa metadata correctly.
    '''
    def setUp(self):
        super(IFAv2TransitMultiAclEntryTest, self).setUp()

    def runTest(self):
        print("IFAv2TransitMultiAclEntryTest")
        self.transitIPv4PacketWithIMSTest()
        self.transitIPv4PacketWithoutIMSTest()
        self.transitIPv6PacketWithIMSTest()
        self.transitIPv6PacketWithoutIMSTest()

    def transitIPv4PacketWithIMSTest(self):
        try:
            print("transitIPv4PacketWithIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata1 = 'eeeeeeee1111111122222222333333334444444455555555ffffffff'
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ip_addr,
                                                ip_src=self.ip_addr_src,
                                                ip_ttl=64,
                                                pktlen=100,
                                                ip_proto=self.l3_protocol,
                                                ip_dscp=dscp_value,
                                                ip_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=7,
                                                metadata=metadata1)
                    pkt_transit = Mask(ifa2_udp_packet(eth_dst=self.dmac,
                                                eth_src=ROUTER_MAC,
                                                ip_dst=self.ip_addr,
                                                ip_src=self.ip_addr_src,
                                                ip_ttl=63,
                                                pktlen=132,
                                                ip_proto=self.l3_protocol,
                                                ip_dscp=dscp_value,
                                                ip_ecn=ecn_value,
                                                hop_limit=4,
                                                max_length=42,
                                                current_length=15,
                                                metadata=metadata2+metadata1))
                    pkt_transit.set_do_not_care(400,256)
                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
            for dscp_value in range(64):
                for ecn_value in range(4):
                    sai_thrift_set_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 0)

    def transitIPv4PacketWithoutIMSTest(self):
        try:
            print("transitIPv4PacketWithoutIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ip_addr,
                                                ip_src=self.ip_addr_src,
                                                ip_ttl=64,
                                                pktlen=100,
                                                ip_proto=self.l3_protocol,
                                                ip_dscp=dscp_value,
                                                ip_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=0,
                                                with_ifa_ims = False)
                    pkt_transit = Mask(ifa2_udp_packet(eth_dst=self.dmac,
                                                eth_src=ROUTER_MAC,
                                                ip_dst=self.ip_addr,
                                                ip_src=self.ip_addr_src,
                                                ip_ttl=63,
                                                pktlen=132,
                                                ip_proto=self.l3_protocol,
                                                ip_dscp=dscp_value,
                                                ip_ecn=ecn_value,
                                                hop_limit=4,
                                                max_length=42,
                                                current_length=8,
                                                metadata=metadata2))
                    pkt_transit.set_do_not_care(400,256)
                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
            for dscp_value in range(64):
                for ecn_value in range(4):
                    sai_thrift_set_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 0)

    def transitIPv6PacketWithIMSTest(self):
        try:
            print("transitIPv6PacketWithIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata1 = 'eeeeeeee1111111122222222333333334444444455555555ffffffff'
            pkt_length1=100+len(metadata1)//2
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udpv6_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ipv6_addr,
                                                ip_src=self.ipv6_addr_src,
                                                ip_ttl=64,
                                                pktlen=pkt_length1,
                                                ip_proto=self.l3_protocol,
                                                ipv6_dscp=dscp_value,
                                                ipv6_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=7,
                                                metadata=metadata1)
                    pkt_transit = Mask(ifa2_udpv6_packet(eth_dst=self.dmac,
                                                eth_src=ROUTER_MAC,
                                                ip_dst=self.ipv6_addr,
                                                ip_src=self.ipv6_addr_src,
                                                ip_ttl=63,
                                                pktlen=pkt_length1+len(metadata2)//2,
                                                ip_proto=self.l3_protocol,
                                                ipv6_dscp=dscp_value,
                                                ipv6_ecn=ecn_value,
                                                hop_limit=4,
                                                max_length=42,
                                                current_length=15,
                                                metadata=metadata2+metadata1))
                    pkt_transit.set_do_not_care(552,256)
                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client,  self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
            for dscp_value in range(64):
                for ecn_value in range(4):
                    sai_thrift_set_acl_counter_attribute(
                        self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                    packets_v6 = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets_v6['packets'], 0)

    def transitIPv6PacketWithoutIMSTest(self):
        try:
            print("transitIPv6PacketWithoutIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udpv6_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ipv6_addr,
                                                ip_src=self.ipv6_addr_src,
                                                ip_ttl=64,
                                                pktlen=100,
                                                ip_proto=self.l3_protocol,
                                                ipv6_dscp=dscp_value,
                                                ipv6_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=0,
                                                with_ifa_ims=False)
                    pkt_transit = Mask(ifa2_udpv6_packet(eth_dst=self.dmac,
                                                eth_src=ROUTER_MAC,
                                                ip_dst=self.ipv6_addr,
                                                ip_src=self.ipv6_addr_src,
                                                ip_ttl=63,
                                                pktlen=100+len(metadata2)//2,
                                                ip_proto=self.l3_protocol,
                                                ipv6_dscp=dscp_value,
                                                ipv6_ecn=ecn_value,
                                                hop_limit=4,
                                                max_length=42,
                                                current_length=8,
                                                metadata=metadata2))
                    pkt_transit.set_do_not_care(552,256)
                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
            for dscp_value in range(64):
                for ecn_value in range(4):
                    sai_thrift_set_acl_counter_attribute(
                        self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                    packets_v6 = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets_v6['packets'], 0)

    def tearDown(self):
        super(IFAv2TransitMultiAclEntryTest, self).tearDown()

@group("draft")
class IFAv2TransitMultiAclEntryStressTest(IFAv2TransitNodeMultiSession):
    '''
    Verify creating multi-acl entry for ifa transit action and inserting ifa metadata correctly.
    '''
    def setUp(self):
        super(IFAv2TransitMultiAclEntryStressTest, self).setUp()

    def runTest(self):
        print("IFAv2TransitMultiAclEntryStressTest")
        for test_times in range(10):
            print("\n 第%d次测试。\n" % test_times)
            if get_platform() != "clx":
                int_insert_action = sai_thrift_acl_action_data_t(
                    enable=False,
                    parameter=sai_thrift_acl_action_parameter_t(
                        s32=SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT))
                tam_int_object_action = sai_thrift_acl_action_data_t(
                    enable=False,
                    parameter=sai_thrift_acl_action_parameter_t(
                        oid=self.int_oid))
                for dscp_value in range(64):
                    for ecn_value in range(4):
                        sai_thrift_set_acl_entry_attribute(
                            self.client, self.ipv4_acl_entries_dict[dscp_value][ecn_value],
                            action_int_insert=int_insert_action,
                            action_tam_int_object=tam_int_object_action)
                        sai_thrift_set_acl_entry_attribute(
                            self.client, self.ipv6_acl_entries_dict[dscp_value][ecn_value],
                            action_int_insert=int_insert_action,
                            action_tam_int_object=tam_int_object_action)

                self.transitIPv4PacketWithIMSTest(enable_ifa=0)
                self.transitIPv4PacketWithoutIMSTest(enable_ifa=0)
                self.transitIPv6PacketWithIMSTest(enable_ifa=0)
                self.transitIPv6PacketWithoutIMSTest(enable_ifa=0)

                int_insert_action = sai_thrift_acl_action_data_t(
                    enable=True,
                    parameter=sai_thrift_acl_action_parameter_t(
                        s32=SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT))
                tam_int_object_action = sai_thrift_acl_action_data_t(
                    enable=True,
                    parameter=sai_thrift_acl_action_parameter_t(
                        oid=self.int_oid))
                for dscp_value in range(64):
                    for ecn_value in range(4):
                        sai_thrift_set_acl_entry_attribute(
                            self.client, self.ipv4_acl_entries_dict[dscp_value][ecn_value],
                            action_int_insert=int_insert_action,
                            action_tam_int_object=tam_int_object_action)
                        sai_thrift_set_acl_entry_attribute(
                            self.client, self.ipv6_acl_entries_dict[dscp_value][ecn_value],
                            action_int_insert=int_insert_action,
                            action_tam_int_object=tam_int_object_action)

            self.transitIPv4PacketWithIMSTest(enable_ifa=1)
            self.transitIPv4PacketWithoutIMSTest(enable_ifa=1)
            self.transitIPv6PacketWithIMSTest(enable_ifa=1)
            self.transitIPv6PacketWithoutIMSTest(enable_ifa=1)


    def transitIPv4PacketWithIMSTest(self,enable_ifa=1):
        try:
            print("transitIPv4PacketWithIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata1 = 'eeeeeeee1111111122222222333333334444444455555555ffffffff'
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ip_addr,
                                                ip_src=self.ip_addr_src,
                                                ip_ttl=64,
                                                pktlen=100,
                                                ip_proto=self.l3_protocol,
                                                ip_dscp=dscp_value,
                                                ip_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=7,
                                                metadata=metadata1)
                    if enable_ifa:
                        pkt_transit = Mask(ifa2_udp_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ip_addr,
                                                    ip_src=self.ip_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=132,
                                                    ip_proto=self.l3_protocol,
                                                    ip_dscp=dscp_value,
                                                    ip_ecn=ecn_value,
                                                    hop_limit=4,
                                                    max_length=42,
                                                    current_length=15,
                                                    metadata=metadata2+metadata1))
                        pkt_transit.set_do_not_care(400,256)
                    else:
                        pkt_transit = ifa2_udp_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ip_addr,
                                                    ip_src=self.ip_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=100,
                                                    ip_proto=self.l3_protocol,
                                                    ip_dscp=dscp_value,
                                                    ip_ecn=ecn_value,
                                                    hop_limit=5,
                                                    max_length=42,
                                                    current_length=7,
                                                    metadata=metadata1)
                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
            for dscp_value in range(64):
                for ecn_value in range(4):
                    sai_thrift_set_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 0)

    def transitIPv4PacketWithoutIMSTest(self,enable_ifa=1):
        try:
            print("transitIPv4PacketWithoutIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ip_addr,
                                                ip_src=self.ip_addr_src,
                                                ip_ttl=64,
                                                pktlen=100,
                                                ip_proto=self.l3_protocol,
                                                ip_dscp=dscp_value,
                                                ip_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=0,
                                                with_ifa_ims = False)
                    if enable_ifa:
                        pkt_transit = Mask(ifa2_udp_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ip_addr,
                                                    ip_src=self.ip_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=132,
                                                    ip_proto=self.l3_protocol,
                                                    ip_dscp=dscp_value,
                                                    ip_ecn=ecn_value,
                                                    hop_limit=4,
                                                    max_length=42,
                                                    current_length=8,
                                                    metadata=metadata2))
                        pkt_transit.set_do_not_care(400,256)
                    else:
                        pkt_transit = ifa2_udp_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ip_addr,
                                                    ip_src=self.ip_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=100,
                                                    ip_proto=self.l3_protocol,
                                                    ip_dscp=dscp_value,
                                                    ip_ecn=ecn_value,
                                                    hop_limit=5,
                                                    max_length=42,
                                                    current_length=0,
                                                    with_ifa_ims = False)

                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
                for dscp_value in range(64):
                    for ecn_value in range(4):
                        sai_thrift_set_acl_counter_attribute(
                            self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                        packets = sai_thrift_get_acl_counter_attribute(
                            self.client, self.ipv4_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                        self.assertEqual(packets['packets'], 0)

    def transitIPv6PacketWithIMSTest(self,enable_ifa=1):
        try:
            print("transitIPv6PacketWithIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata1 = 'eeeeeeee1111111122222222333333334444444455555555ffffffff'
            pkt_length1=100+len(metadata1)//2
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udpv6_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ipv6_addr,
                                                ip_src=self.ipv6_addr_src,
                                                ip_ttl=64,
                                                pktlen=pkt_length1,
                                                ip_proto=self.l3_protocol,
                                                ipv6_dscp=dscp_value,
                                                ipv6_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=7,
                                                metadata=metadata1)
                    if enable_ifa:
                        pkt_transit = Mask(ifa2_udpv6_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ipv6_addr,
                                                    ip_src=self.ipv6_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=pkt_length1+len(metadata2)//2,
                                                    ip_proto=self.l3_protocol,
                                                    ipv6_dscp=dscp_value,
                                                    ipv6_ecn=ecn_value,
                                                    hop_limit=4,
                                                    max_length=42,
                                                    current_length=15,
                                                    metadata=metadata2+metadata1))
                        pkt_transit.set_do_not_care(552,256)
                    else:
                        pkt_transit = ifa2_udpv6_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ipv6_addr,
                                                    ip_src=self.ipv6_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=pkt_length1,
                                                    ip_proto=self.l3_protocol,
                                                    ipv6_dscp=dscp_value,
                                                    ipv6_ecn=ecn_value,
                                                    hop_limit=5,
                                                    max_length=42,
                                                    current_length=7,
                                                    metadata=metadata1)

                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client,  self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
                for dscp_value in range(64):
                    for ecn_value in range(4):
                        sai_thrift_set_acl_counter_attribute(
                            self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                        packets_v6 = sai_thrift_get_acl_counter_attribute(
                            self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                        self.assertEqual(packets_v6['packets'], 0)

    def transitIPv6PacketWithoutIMSTest(self,enable_ifa=1):
        try:
            print("transitIPv6PacketWithoutIMSTest")
            print("Sending packet on port %d, forward" % self.dev_port0)
            metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
            for dscp_value in range(64):
                for ecn_value in range(4):
                    pkt_initiator = ifa2_udpv6_packet(eth_dst=ROUTER_MAC,
                                                eth_src=self.mac_src,
                                                ip_dst=self.ipv6_addr,
                                                ip_src=self.ipv6_addr_src,
                                                ip_ttl=64,
                                                pktlen=100,
                                                ip_proto=self.l3_protocol,
                                                ipv6_dscp=dscp_value,
                                                ipv6_ecn=ecn_value,
                                                hop_limit=5,
                                                max_length=42,
                                                current_length=0,
                                                with_ifa_ims=False)
                    if enable_ifa:
                        pkt_transit = Mask(ifa2_udpv6_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ipv6_addr,
                                                    ip_src=self.ipv6_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=100+len(metadata2)//2,
                                                    ip_proto=self.l3_protocol,
                                                    ipv6_dscp=dscp_value,
                                                    ipv6_ecn=ecn_value,
                                                    hop_limit=4,
                                                    max_length=42,
                                                    current_length=8,
                                                    metadata=metadata2))
                        pkt_transit.set_do_not_care(552,256)
                    else:
                        pkt_transit = ifa2_udpv6_packet(eth_dst=self.dmac,
                                                    eth_src=ROUTER_MAC,
                                                    ip_dst=self.ipv6_addr,
                                                    ip_src=self.ipv6_addr_src,
                                                    ip_ttl=63,
                                                    pktlen=100,
                                                    ip_proto=self.l3_protocol,
                                                    ipv6_dscp=dscp_value,
                                                    ipv6_ecn=ecn_value,
                                                    hop_limit=5,
                                                    max_length=42,
                                                    current_length=0,
                                                    with_ifa_ims=False)

                    send_packet(self, self.dev_port0, pkt_initiator)
                    verify_packet(self, pkt_transit, self.dev_port1)
            time.sleep(1)
            #Getting all statistics at one time is to save test time.
            for dscp_value in range(64):
                for ecn_value in range(4):
                    packets = sai_thrift_get_acl_counter_attribute(
                        self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                    self.assertEqual(packets['packets'], 1)
        finally:
                for dscp_value in range(64):
                    for ecn_value in range(4):
                        sai_thrift_set_acl_counter_attribute(
                            self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=0)
                        packets_v6 = sai_thrift_get_acl_counter_attribute(
                            self.client, self.ipv6_acl_counter_ingress_dict[dscp_value][ecn_value], packets=True)
                        self.assertEqual(packets_v6['packets'], 0)

    def tearDown(self):
        super(IFAv2TransitMultiAclEntryStressTest, self).tearDown()

@group("draft")
class IFAv2TransitNodeForwardNonIFAPktTest(IFAv2TransitNode):
    '''
    Verify that ifa transit node won't insert ifa metadata when forwarding non-ifa packet.
    '''
    def setUp(self):
        super(IFAv2TransitNodeForwardNonIFAPktTest, self).setUp()

    def runTest(self):
        print("IFAv2TransitNodeForwardNonIFAPktTest")
        print("Sending packet on port %d, forward" % self.dev_port0)
        pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                    eth_src=self.mac_src,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=64,
                                    pktlen=100,
                                    ip_proto=self.l3_protocol-1,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    with_ifa_ih=False)
        pkt_transit = ifa2_udp_packet(eth_dst=self.dmac,
                                    eth_src=ROUTER_MAC,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=63,
                                    pktlen=100,
                                    ip_proto=self.l3_protocol-1,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    with_ifa_ih=False)
        send_packet(self, self.dev_port0, pkt_initiator)
        verify_packet(self, pkt_transit, self.dev_port1)
        time.sleep(1)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=True)
        self.assertEqual(packets['packets'], 1)

    def tearDown(self):
        super(IFAv2TransitNodeForwardNonIFAPktTest, self).tearDown()

@group("draft")
class IFAv2TransitNodeUsingIntAclTableTest(SaiHelperSimplified):
    '''
    Verify ifa2.0 inband transit node function using INT acl table.
    '''
    def setUp(self):
        super(IFAv2TransitNodeUsingIntAclTableTest, self).setUp()

        self.create_routing_interfaces(ports=[0, 1])

        device_id = 0x12345678
        self.l3_protocol = 253

        self.int_oid = sai_thrift_create_tam_int(self.client, type=SAI_TAM_INT_TYPE_IFA2,
                                            name_space_id=0xf, device_id=device_id, inline=False,
                                            int_presence_type=SAI_TAM_INT_PRESENCE_TYPE_L3_PROTOCOL,
                                            int_presence_l3_protocol=(ctypes.c_int8(self.l3_protocol)).value)
        if get_platform() == "clx":
            self.tam_oid = sai_thrift_create_tam(self.client)
            tam_int_list = sai_thrift_object_list_t(count=1, idlist=[self.int_oid])
            sai_thrift_set_tam_attribute(self.client, self.tam_oid, int_objects_list=tam_int_list)
            tam_list = sai_thrift_object_list_t(count=1, idlist=[self.tam_oid])
            sai_thrift_set_port_attribute(self.client, self.port0, tam_object=tam_list)

        self.ip_addr_subnet = '172.16.10.0/24'
        self.ip_addr = '172.16.10.1'
        self.dmac = '00:11:22:33:44:55'
        self.mac_src = '00:22:22:22:22:22'
        self.ip_addr_src = '192.168.100.100'

        print("Create neighbor with %s ip address, %d router interface"
              " id and %s destination mac" % (
                  self.ip_addr, self.port1_rif, self.dmac))
        self.nbr_entry = sai_thrift_neighbor_entry_t(
            rif_id=self.port1_rif,
            ip_address=sai_ipaddress(self.ip_addr))
        sai_thrift_create_neighbor_entry(
            self.client, self.nbr_entry, dst_mac_address=self.dmac)

        print("Create nhop with %s ip address and %d router"
              " interface id" % (self.ip_addr, self.port1_rif))
        self.nhop = sai_thrift_create_next_hop(
            self.client, ip=sai_ipaddress(self.ip_addr),
            router_interface_id=self.port1_rif,
            type=SAI_NEXT_HOP_TYPE_IP)

        print("Create route with %s ip prefix and %d router"
              " interface id" % (self.ip_addr_subnet, self.port1_rif))
        self.route_entry = sai_thrift_route_entry_t(
            vr_id=self.default_vrf, destination=sai_ipprefix(
                self.ip_addr_subnet))
        sai_thrift_create_route_entry(self.client, self.route_entry,
                                      next_hop_id=self.nhop)
        print("testINTTableAclIgrAdd")

        #create an ACL table group for ingress stage
        group_stage_ingress = SAI_ACL_STAGE_INGRESS
        group_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL
        group_bind_point_type_list = sai_thrift_s32_list_t(
            count=len(group_bind_point_list), int32list=group_bind_point_list)
        self.acl_group_ingress = sai_thrift_create_acl_table_group(
            self.client,
            acl_stage=group_stage_ingress,
            acl_bind_point_type_list=group_bind_point_type_list,
            type=group_type)
        assert(self.acl_group_ingress != SAI_NULL_OBJECT_ID)

        #Define the types of actions that the ACL table can perform
        self.INT_table_action_types = [SAI_ACL_ACTION_TYPE_COUNTER,
                                       SAI_ACL_ACTION_TYPE_TAM_INT_OBJECT,
                                       SAI_ACL_ACTION_TYPE_INT_INSERT,
                                       SAI_ACL_ACTION_TYPE_SET_TC,
                                       SAI_ACL_ACTION_TYPE_SET_DSCP]
        if get_platform() == "clx":
            self.INT_table_action_types.remove(SAI_ACL_ACTION_TYPE_SET_DSCP)

        self.INT_table_acl_action_type_list = sai_thrift_s32_list_t(
            count=len(self.INT_table_action_types), int32list=self.INT_table_action_types)
        self.table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_points = [SAI_ACL_BIND_POINT_TYPE_PORT]
        self.table_bind_point_type_list = sai_thrift_s32_list_t(
            count=len(table_bind_points), int32list=table_bind_points)
        #Create ACL table for ingress traffic
        self.INT_acl_table = sai_thrift_create_acl_table(
            self.client,
            acl_stage=self.table_stage,
            acl_bind_point_type_list=self.table_bind_point_type_list,
            acl_action_type_list=self.INT_table_acl_action_type_list,
            size=256,
            field_ttl=True,
            field_in_ports=True,
            field_dscp=True,
            field_ecn=True,
            field_ip_protocol=True,
            field_acl_ip_type=True,
            field_l4_dst_port=True,
            field_src_ip=True,
            field_src_ipv6=True,
            field_bth_reserved=True)
        assert(self.INT_acl_table != SAI_NULL_OBJECT_ID)

        #Create INT_acl_table as ACL table group member
        print("Create ACL group members")
        INT_group_member_priority = 100
        self.acl_group_ingress_member = sai_thrift_create_acl_table_group_member(
                                            self.client,
                                            self.acl_group_ingress,
                                            self.INT_acl_table,
                                            INT_group_member_priority)

        # create ipv4 ACL table entry
        src_ip_mask = '255.255.255.255'
        src_ip_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(ip4=self.ip_addr_src),
            mask=sai_thrift_acl_field_data_mask_t(ip4=src_ip_mask))
        field_dscp_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(u8=63),
            mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xff)).value))
        field_ecn_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(u8=1),
            mask=sai_thrift_acl_field_data_mask_t(u8=(ctypes.c_int8(0xf)).value))
        int_insert_action = sai_thrift_acl_action_data_t(
            enable=True,
            parameter=sai_thrift_acl_action_parameter_t(
                s32=SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT))
        tam_int_object_action = sai_thrift_acl_action_data_t(
            enable=True,
            parameter=sai_thrift_acl_action_parameter_t(
                oid=self.int_oid))
        self.acl_entry = sai_thrift_create_acl_entry(
            self.client,
            table_id=self.INT_acl_table,
            priority=10,
            field_src_ip=src_ip_t,
            field_dscp=field_dscp_t,
            field_ecn=field_ecn_t,
            action_int_insert=int_insert_action,
            action_tam_int_object=tam_int_object_action
            )
        # create ACL counter
        self.acl_counter_ingress = sai_thrift_create_acl_counter(
            self.client, table_id=self.INT_acl_table,enable_packet_count=True, enable_byte_count=True)
        # attach ACL counter to ipv4 ACL entry
        action_counter_ingress = sai_thrift_acl_action_data_t(
            parameter=sai_thrift_acl_action_parameter_t(
                oid=self.acl_counter_ingress),
            enable=True)
        sai_thrift_set_acl_entry_attribute(
            self.client, self.acl_entry,
            action_counter=action_counter_ingress)
        # bind ACL table group to ingress port 0
        sai_thrift_set_port_attribute(
            self.client, self.port0, ingress_acl=self.acl_group_ingress)

    def runTest(self):
        print("IFAv2TransitNodeUsingIntAclTableTest")
        print("Sending packet on port %d, forward" % self.dev_port0)
        pkt_length1=100
        metadata1_num=7
        metadata1 = self.gen_metadata(length=metadata1_num*8)
        metadata2 = 'f234567812345678000000100000000000000000000000000000000000000000'
        pkt_initiator = ifa2_udp_packet(eth_dst=ROUTER_MAC,
                                    eth_src=self.mac_src,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=64,
                                    pktlen=pkt_length1,
                                    ip_proto=self.l3_protocol,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    hop_limit=5,
                                    max_length=42,
                                    current_length=metadata1_num,
                                    metadata=metadata1)
        pkt_transit =Mask(ifa2_udp_packet(eth_dst=self.dmac,
                                    eth_src=ROUTER_MAC,
                                    ip_dst=self.ip_addr,
                                    ip_src=self.ip_addr_src,
                                    ip_ttl=63,
                                    pktlen=pkt_length1+len(metadata2)//2,
                                    ip_proto=self.l3_protocol,
                                    ip_dscp=63,
                                    ip_ecn=1,
                                    hop_limit=4,
                                    max_length=42,
                                    current_length=metadata1_num+len(metadata2)//8,
                                    metadata=metadata2+metadata1))
        pkt_transit.set_do_not_care(400,256)

        send_packet(self, self.dev_port0, pkt_initiator)
        verify_packet(self, pkt_transit, self.dev_port1)
        time.sleep(1)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=True)
        self.assertEqual(packets['packets'], 1)

    def tearDown(self):
        # unbind this ACL table from rif_id1s object id
        sai_thrift_set_port_attribute(
            self.client, self.port0, ingress_acl=int(SAI_NULL_OBJECT_ID))
        # cleanup ipv4 ACL
        action_counter_ingress = sai_thrift_acl_action_data_t(
            parameter=sai_thrift_acl_action_parameter_t(
                oid=0),
            enable=True)
        sai_thrift_set_acl_entry_attribute(
            self.client, self.acl_entry,
            action_counter=action_counter_ingress)
        sai_thrift_set_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=0)
        packets = sai_thrift_get_acl_counter_attribute(
            self.client, self.acl_counter_ingress, packets=True)
        self.assertEqual(packets['packets'], 0)
        sai_thrift_remove_acl_counter(self.client, self.acl_counter_ingress)
        sai_thrift_remove_acl_entry(self.client, self.acl_entry)
        sai_thrift_remove_acl_table_group_member(
            self.client, self.acl_group_ingress_member)
        sai_thrift_remove_acl_table(self.client, self.INT_acl_table)
        sai_thrift_remove_acl_table_group(self.client, self.acl_group_ingress)

        sai_thrift_remove_route_entry(self.client, self.route_entry)
        sai_thrift_remove_next_hop(self.client, self.nhop)
        sai_thrift_remove_neighbor_entry(self.client, self.nbr_entry)
        #cleanup ifa
        if get_platform() == "clx":
            tam_list = sai_thrift_object_list_t(count=0, idlist=[])
            sai_thrift_set_port_attribute(self.client, self.port0, tam_object=tam_list)
            tam_int_list = sai_thrift_object_list_t(count=0, idlist=[])
            sai_thrift_set_tam_attribute(self.client, self.tam_oid, int_objects_list=tam_int_list)
            sai_thrift_remove_tam(self.client, self.tam_oid)
        sai_thrift_remove_tam_int(self.client,self.int_oid)
        self.destroy_routing_interfaces()
        super(IFAv2TransitNodeUsingIntAclTableTest, self).tearDown()

    def gen_metadata(self,length=7):
        '''
        generate metadata
        '''
        hex_chars='0123456789abcdef'
        metadata_str = ''.join(random.choice(hex_chars) for _ in range(length))
        return metadata_str
