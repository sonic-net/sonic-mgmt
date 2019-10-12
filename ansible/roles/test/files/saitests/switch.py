# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface basic tests
"""

import switch_sai_thrift
from sai_base_test import *
import time
import sys
import logging

import unittest
import random

import sai_base_test

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *

import os

from switch_sai_thrift.ttypes import  *

from switch_sai_thrift.sai_headers import  *


this_dir = os.path.dirname(os.path.abspath(__file__))

switch_inited=0
port_list = {}
sai_port_list = []
front_port_list = []
table_attr_list = []
router_mac='00:77:66:55:44:00'
rewrite_mac1='00:77:66:55:45:01'
rewrite_mac2='00:77:66:55:46:01'

is_bmv2 = ('BMV2_TEST' in os.environ) and (int(os.environ['BMV2_TEST']) == 1)

def switch_init(client):
    global switch_inited
    if switch_inited:
        return

    switch_attr_list = client.sai_thrift_get_switch_attribute()
    attr_list = switch_attr_list.attr_list
    for attribute in attr_list:
        if attribute.id == SAI_SWITCH_ATTR_PORT_NUMBER:
            print "max ports: " + attribute.value.u32
        elif attribute.id == SAI_SWITCH_ATTR_PORT_LIST:
            for port_id in attribute.value.objlist.object_id_list:
                attr_value = sai_thrift_attribute_value_t(booldata=1)
                attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_ADMIN_STATE, value=attr_value)
                client.sai_thrift_set_port_attribute(port_id, attr)
                sai_port_list.append(port_id)
        else:
            print "unknown switch attribute"

    # TOFIX in brcm sai: This causes the following error on td2 (a7050-qx-32s)
    # ERR syncd: brcm_sai_set_switch_attribute:842 updating switch mac addr failed with error -2.
    attr_value = sai_thrift_attribute_value_t(mac='00:77:66:55:44:33')
    attr = sai_thrift_attribute_t(id=SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, value=attr_value)
    client.sai_thrift_set_switch_attribute(attr)

    # wait till the port are up
    time.sleep(10)

    thrift_attr = client.sai_thrift_get_port_list_by_front_port()
    if thrift_attr.id == SAI_SWITCH_ATTR_PORT_LIST:
        for port_id in thrift_attr.value.objlist.object_id_list:
            front_port_list.append(port_id)

    for interface,front in interface_to_front_mapping.iteritems():
        sai_port_id = client.sai_thrift_get_port_id_by_front_port(front);
        port_list[int(interface)]=sai_port_id

    switch_inited = 1


def sai_thrift_create_fdb(client, vlan_id, mac, port, mac_action):
    fdb_entry = sai_thrift_fdb_entry_t(mac_address=mac, vlan_id=vlan_id)
    #value 0 represents static entry, id=0, represents entry type
    fdb_attribute1_value = sai_thrift_attribute_value_t(s32=SAI_FDB_ENTRY_STATIC)
    fdb_attribute1 = sai_thrift_attribute_t(id=SAI_FDB_ENTRY_ATTR_TYPE,
                                            value=fdb_attribute1_value)
    #value oid represents object id, id=1 represents port id
    fdb_attribute2_value = sai_thrift_attribute_value_t(oid=port)
    fdb_attribute2 = sai_thrift_attribute_t(id=SAI_FDB_ENTRY_ATTR_PORT_ID,
                                            value=fdb_attribute2_value)
    #value oid represents object id, id=1 represents port id
    fdb_attribute3_value = sai_thrift_attribute_value_t(s32=mac_action)
    fdb_attribute3 = sai_thrift_attribute_t(id=SAI_FDB_ENTRY_ATTR_PACKET_ACTION,
                                            value=fdb_attribute3_value)
    fdb_attr_list = [fdb_attribute1, fdb_attribute2, fdb_attribute3]
    client.sai_thrift_create_fdb_entry(thrift_fdb_entry=fdb_entry, thrift_attr_list=fdb_attr_list)

def sai_thrift_delete_fdb(client, vlan_id, mac, port):
    fdb_entry = sai_thrift_fdb_entry_t(mac_address=mac, vlan_id=vlan_id)
    client.sai_thrift_delete_fdb_entry(thrift_fdb_entry=fdb_entry)

def sai_thrift_flush_fdb_by_vlan(client, vlan_id):
    fdb_attribute1_value = sai_thrift_attribute_value_t(u16=vlan_id)
    fdb_attribute1 = sai_thrift_attribute_t(id=SAI_FDB_FLUSH_ATTR_VLAN_ID,
                                            value=fdb_attribute1_value)
    fdb_attribute2_value = sai_thrift_attribute_value_t(s32=SAI_FDB_FLUSH_ENTRY_DYNAMIC)
    fdb_attribute2 = sai_thrift_attribute_t(id=SAI_FDB_FLUSH_ATTR_ENTRY_TYPE,
                                            value=fdb_attribute2_value)
    fdb_attr_list = [fdb_attribute1, fdb_attribute2]
    client.sai_thrift_flush_fdb_entries(thrift_attr_list=fdb_attr_list)

def sai_thrift_create_virtual_router(client, v4_enabled, v6_enabled):
    #v4 enabled
    vr_attribute1_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    vr_attribute1 = sai_thrift_attribute_t(id=SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE,
                                           value=vr_attribute1_value)
    #v6 enabled
    vr_attribute2_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    vr_attribute2 = sai_thrift_attribute_t(id=SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE,
                                           value=vr_attribute1_value)
    vr_attr_list = [vr_attribute1, vr_attribute2]
    vr_id = client.sai_thrift_create_virtual_router(thrift_attr_list=vr_attr_list)
    return vr_id

def sai_thrift_create_router_interface(client, vr_id, is_port, port_id, vlan_id, v4_enabled, v6_enabled, mac):
    #vrf attribute
    rif_attr_list = []
    rif_attribute1_value = sai_thrift_attribute_value_t(oid=vr_id)
    rif_attribute1 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID,
                                            value=rif_attribute1_value)
    rif_attr_list.append(rif_attribute1)
    if is_port:
        #port type and port id
        rif_attribute2_value = sai_thrift_attribute_value_t(s32=SAI_ROUTER_INTERFACE_TYPE_PORT)
        rif_attribute2 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_TYPE,
                                                value=rif_attribute2_value)
        rif_attr_list.append(rif_attribute2)
        rif_attribute3_value = sai_thrift_attribute_value_t(oid=port_id)
        rif_attribute3 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_PORT_ID,
                                                value=rif_attribute3_value)
        rif_attr_list.append(rif_attribute3)
    else:
        #vlan type and vlan id
        rif_attribute2_value = sai_thrift_attribute_value_t(s32=SAI_ROUTER_INTERFACE_TYPE_VLAN)
        rif_attribute2 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_TYPE,
                                                value=rif_attribute2_value)
        rif_attr_list.append(rif_attribute2)
        rif_attribute3_value = sai_thrift_attribute_value_t(u16=vlan_id)
        rif_attribute3 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_VLAN_ID,
                                                value=rif_attribute3_value)
        rif_attr_list.append(rif_attribute3)

    #v4_enabled
    rif_attribute4_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    rif_attribute4 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
                                            value=rif_attribute4_value)
    rif_attr_list.append(rif_attribute4)
    #v6_enabled
    rif_attribute5_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    rif_attribute5 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
                                            value=rif_attribute5_value)
    rif_attr_list.append(rif_attribute5)

    if mac:
        rif_attribute6_value = sai_thrift_attribute_value_t(mac=mac)
        rif_attribute6 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
                                                value=rif_attribute6_value)
        rif_attr_list.append(rif_attribute6)

    rif_id = client.sai_thrift_create_router_interface(rif_attr_list)
    return rif_id

def sai_thrift_create_route(client, vr_id, addr_family, ip_addr, ip_mask, nhop):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        mask = sai_thrift_ip_t(ip4=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr, mask=mask)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        mask = sai_thrift_ip_t(ip6=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr, mask=mask)
    route_attribute1_value = sai_thrift_attribute_value_t(oid=nhop)
    route_attribute1 = sai_thrift_attribute_t(id=SAI_ROUTE_ATTR_NEXT_HOP_ID,
                                              value=route_attribute1_value)
    route = sai_thrift_unicast_route_entry_t(vr_id, ip_prefix)
    route_attr_list = [route_attribute1]
    client.sai_thrift_create_route(thrift_unicast_route_entry=route, thrift_attr_list=route_attr_list)

def sai_thrift_remove_route(client, vr_id, addr_family, ip_addr, ip_mask, nhop):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        mask = sai_thrift_ip_t(ip4=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr, mask=mask)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        mask = sai_thrift_ip_t(ip6=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr, mask=mask)
    route = sai_thrift_unicast_route_entry_t(vr_id, ip_prefix)
    client.sai_thrift_remove_route(thrift_unicast_route_entry=route)

def sai_thrift_create_nhop(client, addr_family, ip_addr, rif_id):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr)
    nhop_attribute1_value = sai_thrift_attribute_value_t(ipaddr=ipaddr)
    nhop_attribute1 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_IP,
                                             value=nhop_attribute1_value)
    nhop_attribute2_value = sai_thrift_attribute_value_t(oid=rif_id)
    nhop_attribute2 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
                                             value=nhop_attribute2_value)
    nhop_attribute3_value = sai_thrift_attribute_value_t(s32=SAI_NEXT_HOP_IP)
    nhop_attribute3 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_TYPE,
                                             value=nhop_attribute3_value)
    nhop_attr_list = [nhop_attribute1, nhop_attribute2, nhop_attribute3]
    nhop = client.sai_thrift_create_next_hop(thrift_attr_list=nhop_attr_list)
    return nhop

def sai_thrift_create_neighbor(client, addr_family, rif_id, ip_addr, dmac):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr)
    neighbor_attribute1_value = sai_thrift_attribute_value_t(mac=dmac)
    neighbor_attribute1 = sai_thrift_attribute_t(id=SAI_NEIGHBOR_ATTR_DST_MAC_ADDRESS,
                                                 value=neighbor_attribute1_value)
    neighbor_attr_list = [neighbor_attribute1]
    neighbor_entry = sai_thrift_neighbor_entry_t(rif_id=rif_id, ip_address=ipaddr)
    client.sai_thrift_create_neighbor_entry(neighbor_entry, neighbor_attr_list)

def sai_thrift_remove_neighbor(client, addr_family, rif_id, ip_addr, dmac):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr)
    neighbor_entry = sai_thrift_neighbor_entry_t(rif_id=rif_id, ip_address=ipaddr)
    client.sai_thrift_remove_neighbor_entry(neighbor_entry)

def sai_thrift_create_next_hop_group(client, nhop_list):
    nhop_group_attribute1_value = sai_thrift_attribute_value_t(s32=SAI_NEXT_HOP_GROUP_ECMP)
    nhop_group_attribute1 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_GROUP_ATTR_TYPE,
                                                   value=nhop_group_attribute1_value)
    nhop_objlist = sai_thrift_object_list_t(count=len(nhop_list), object_id_list=nhop_list)
    nhop_group_attribute2_value = sai_thrift_attribute_value_t(objlist=nhop_objlist)
    nhop_group_attribute2 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_LIST,
                                                   value=nhop_group_attribute2_value)
    nhop_group_attr_list = [nhop_group_attribute1, nhop_group_attribute2]
    nhop_group = client.sai_thrift_create_next_hop_group(thrift_attr_list=nhop_group_attr_list)
    return nhop_group

def sai_thrift_create_lag(client, port_list):
    lag_port_list = sai_thrift_object_list_t(count=len(port_list), object_id_list=port_list)
    lag1_attr_value = sai_thrift_attribute_value_t(objlist=lag_port_list)
    lag1_attr = sai_thrift_attribute_t(id=SAI_LAG_ATTR_PORT_LIST,
                                       value=lag1_attr_value)
    lag_attr_list = [lag1_attr]
    lag = client.sai_thrift_create_lag(lag_attr_list)
    return lag

def sai_thrift_create_lag_member(client, lag_id, port_id):
    lag_member_attr1_value = sai_thrift_attribute_value_t(oid=lag_id)
    lag_member_attr1 = sai_thrift_attribute_t(id=SAI_LAG_MEMBER_ATTR_LAG_ID,
                                              value=lag_member_attr1_value)
    lag_member_attr2_value = sai_thrift_attribute_value_t(oid=port_id)
    lag_member_attr2 = sai_thrift_attribute_t(id=SAI_LAG_MEMBER_ATTR_PORT_ID,
                                              value=lag_member_attr2_value)
    lag_member_attr_list = [lag_member_attr1, lag_member_attr2]
    lag_member_id = client.sai_thrift_create_lag_member(lag_member_attr_list)
    return lag_member_id

def sai_thrift_create_stp_entry(client, vlan_list):
    vlanlist=sai_thrift_vlan_list_t(vlan_count=len(vlan_list), vlan_list=vlan_list)
    stp_attribute1_value = sai_thrift_attribute_value_t(vlanlist=vlanlist)
    stp_attribute1 = sai_thrift_attribute_t(id=SAI_STP_ATTR_VLAN_LIST,
                                            value=stp_attribute1_value)
    stp_attr_list = [stp_attribute1]
    stp_id = client.sai_thrift_create_stp_entry(stp_attr_list)
    return stp_id

def sai_thrift_create_hostif_trap_group(client, queue_id):
    attribute_value = sai_thrift_attribute_value_t(u32=queue_id)
    attribute = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE,
                                        value=attribute_value)
    attr_list = [attribute]
    trap_group_id = client.sai_thrift_create_hostif_trap_group(thrift_attr_list=attr_list)
    return trap_group_id

def sai_thrift_create_hostif_trap(client, trap_id, action, priority, channel, trap_group_id):
    attribute3_value = sai_thrift_attribute_value_t(s32=channel)
    attribute3 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_TRAP_CHANNEL,
                                        value=attribute3_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute3)
    attribute4_value = sai_thrift_attribute_value_t(oid=trap_group_id)
    attribute4 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP,
                                        value=attribute4_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute4)
    attribute1_value = sai_thrift_attribute_value_t(s32=action)
    attribute1 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION,
                                        value=attribute1_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute1)
    attribute2_value = sai_thrift_attribute_value_t(u32=priority)
    attribute2 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY,
                                        value=attribute2_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute2)

def sai_thrift_create_hostif(client, rif_or_port_id, intf_name):
    attribute1_value = sai_thrift_attribute_value_t(s32=SAI_HOSTIF_TYPE_NETDEV)
    attribute1 = sai_thrift_attribute_t(id=SAI_HOSTIF_ATTR_TYPE,
                                        value=attribute1_value)
    attribute2_value = sai_thrift_attribute_value_t(oid=rif_or_port_id)
    attribute2 = sai_thrift_attribute_t(id=SAI_HOSTIF_ATTR_RIF_OR_PORT_ID,
                                        value=attribute2_value)
    attribute3_value = sai_thrift_attribute_value_t(chardata=intf_name)
    attribute3 = sai_thrift_attribute_t(id=SAI_HOSTIF_ATTR_NAME,
                                        value=attribute3_value)
    attr_list = [attribute1, attribute2, attribute3]
    hif_id = client.sai_thrift_create_hostif(attr_list)
    return hif_id

def sai_thrift_create_acl_table(client, addr_family,
                                ip_src, ip_dst,
                                ip_proto,
                                in_ports, out_ports,
                                in_port, out_port):
    acl_attr_list = []
    if ip_src != None:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if ip_dst != None:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if ip_proto != None:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if in_ports:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if out_ports:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if in_port != None:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_IN_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if out_port != None:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    acl_table_id = client.sai_thrift_create_acl_table(acl_attr_list)
    return acl_table_id

def sai_thrift_create_acl_entry(client, acl_table_id,
                                action, addr_family,
                                ip_src, ip_src_mask,
                                ip_dst, ip_dst_mask,
                                ip_proto,
                                in_port_list, out_port_list,
                                in_port, out_port,
                                ingress_mirror, egress_mirror):
    acl_attr_list = []

    #OID
    attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=acl_table_id)))
    attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_TABLE_ID,
                                       value=attribute_value)
    acl_attr_list.append(attribute)

    #Priority
    attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(u32=10)))
    attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_PRIORITY,
                                       value=attribute_value)
    acl_attr_list.append(attribute)

    #Ip source
    if ip_src != None:
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(ip4=ip_src), mask =sai_thrift_acl_mask_t(ip4=ip_src_mask)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    #Input ports
    if in_port_list:
        acl_port_list = sai_thrift_object_list_t(count=len(in_port_list), object_id_list=in_port_list)
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(objlist=acl_port_list)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    #Output ports
    if out_port_list:
        acl_port_list = sai_thrift_object_list_t(count=len(out_port_list), object_id_list=out_port_list)
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(objlist=acl_port_list)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    if in_port != None:
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=in_port)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    if out_port != None:
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=out_port)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    #Packet action
    if action == 1:
        #Drop
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(u8=0)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_PACKET_ACTION,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    elif action == 2:
        #Ingress mirroring
        if ingress_mirror != None:
            attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=ingress_mirror)))
            attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, value=attribute_value)
            acl_attr_list.append(attribute)
        elif egress_mirror != None:
            attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=egress_mirror)))
            attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS, value=attribute_value)
            acl_attr_list.append(attribute)

    acl_entry_id = client.sai_thrift_create_acl_entry(acl_attr_list)
    return acl_entry_id

def sai_thrift_create_mirror_session(client, mirror_type, port,
                                     vlan, vlan_priority, vlan_tpid,
                                     src_mac, dst_mac,
                                     addr_family, src_ip, dst_ip,
                                     encap_type, protocol, ttl, tos):
    mirror_attr_list = []

    #Mirror type
    attribute1_value = sai_thrift_attribute_value_t(u8=mirror_type)
    attribute1 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_TYPE,
                                        value=attribute1_value)
    mirror_attr_list.append(attribute1)

    #Monitor port
    attribute2_value = sai_thrift_attribute_value_t(oid=port)
    attribute2 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_MONITOR_PORT,
                                        value=attribute2_value)
    mirror_attr_list.append(attribute2)

    if mirror_type == SAI_MIRROR_TYPE_LOCAL:
        attribute4_value = sai_thrift_attribute_value_t(u16=vlan)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_ID,
                                            value=attribute4_value)
        mirror_attr_list.append(attribute4)
    elif mirror_type == SAI_MIRROR_TYPE_REMOTE:
        #vlan tpid
        attribute3_value = sai_thrift_attribute_value_t(u16=vlan_tpid)
        attribute3 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_TPID,
                                            value=attribute3_value)
        mirror_attr_list.append(attribute3)

        #vlan
        attribute4_value = sai_thrift_attribute_value_t(u16=vlan)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_ID,
                                            value=attribute4_value)
        mirror_attr_list.append(attribute4)

        #vlan priority
        attribute5_value = sai_thrift_attribute_value_t(u16=vlan_priority)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_PRI,
                                            value=attribute5_value)
        mirror_attr_list.append(attribute5)
    elif mirror_type == SAI_MIRROR_TYPE_ENHANCED_REMOTE:
        #encap type
        attribute3_value = sai_thrift_attribute_value_t(u8=encap_type)
        attribute3 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_ENCAP_TYPE,
                                            value=attribute3_value)
        mirror_attr_list.append(attribute3)

        #source ip
        addr = sai_thrift_ip_t(ip4=src_ip)
        src_ip_addr = sai_thrift_ip_address_t(addr_family=addr_family, addr=addr)
        attribute4_value = sai_thrift_attribute_value_t(ipaddr=src_ip_addr)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS,
                                            value=attribute4_value)
        mirror_attr_list.append(attribute4)

        #dst ip
        addr = sai_thrift_ip_t(ip4=dst_ip)
        dst_ip_addr = sai_thrift_ip_address_t(addr_family=addr_family, addr=addr)
        attribute5_value = sai_thrift_attribute_value_t(ipaddr=dst_ip_addr)
        attribute5 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS,
                                            value=attribute5_value)
        mirror_attr_list.append(attribute5)

        #source mac
        attribute6_value = sai_thrift_attribute_value_t(mac=src_mac)
        attribute6 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS,
                                            value=attribute6_value)
        mirror_attr_list.append(attribute6)

        #dst mac
        attribute7_value = sai_thrift_attribute_value_t(mac=dst_mac)
        attribute7 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS,
                                            value=attribute7_value)
        mirror_attr_list.append(attribute7)

    mirror_id = client.sai_thrift_create_mirror_session(mirror_attr_list)
    return mirror_id

def sai_thrift_create_scheduler_profile(client, max_rate, algorithm=0):
    scheduler_attr_list = []
    attribute_value = sai_thrift_attribute_value_t(u64=max_rate)
    attribute = sai_thrift_attribute_t(id=SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE ,
                                       value=attribute_value)
    scheduler_attr_list.append(attribute)
    attribute_value = sai_thrift_attribute_value_t(s32=algorithm)
    attribute = sai_thrift_attribute_t(id=SAI_SCHEDULER_ATTR_SCHEDULING_TYPE,
                                       value=attribute_value)
    scheduler_attr_list.append(attribute)
    scheduler_profile_id = client.sai_thrift_create_scheduler_profile(scheduler_attr_list)
    return scheduler_profile_id

def sai_thrift_create_buffer_profile(client, pool_id, size, threshold, xoff_th, xon_th):
    buffer_attr_list = []
    attribute_value = sai_thrift_attribute_value_t(oid=pool_id)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_PROFILE_ATTR_POOL_ID ,
                                           value=attribute_value)
    buffer_attr_list.append(attribute)
    
    attribute_value = sai_thrift_attribute_value_t(u32=size)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_PROFILE_ATTR_BUFFER_SIZE ,
                                           value=attribute_value)
    buffer_attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(u8=threshold)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH ,
                                           value=attribute_value)
    buffer_attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(u32=xoff_th)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_PROFILE_ATTR_XOFF_TH ,
                                           value=attribute_value)
    buffer_attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(u32=xon_th)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_PROFILE_ATTR_XON_TH ,
                                           value=attribute_value)
    buffer_attr_list.append(attribute)

    buffer_profile_id = client.sai_thrift_create_buffer_profile(buffer_attr_list)
    return buffer_profile_id

def sai_thrift_create_pool_profile(client, pool_type, size, threshold_mode):
    pool_attr_list = []
    attribute_value = sai_thrift_attribute_value_t(s32=pool_type)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_POOL_ATTR_TYPE ,
                                           value=attribute_value)
    pool_attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(u32=size)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_POOL_ATTR_SIZE ,
                                           value=attribute_value)
    pool_attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(s32=threshold_mode)
    attribute = sai_thrift_attribute_t(id=SAI_BUFFER_POOL_ATTR_TH_MODE ,
                                           value=attribute_value)
    pool_attr_list.append(attribute)
    pool_id = client.sai_thrift_create_pool_profile(pool_attr_list)
    return pool_id

def sai_thrift_clear_all_counters(client):
    for port in sai_port_list:
        queue_list=[]
        client.sai_thrift_clear_port_all_stats(port)
        port_attr_list = client.sai_thrift_get_port_attribute(port)
        attr_list = port_attr_list.attr_list
        for attribute in attr_list:
            if attribute.id == SAI_PORT_ATTR_QOS_QUEUE_LIST:
                for queue_id in attribute.value.objlist.object_id_list:
                    queue_list.append(queue_id)

        cnt_ids=[]
        cnt_ids.append(SAI_QUEUE_STAT_PACKETS)
        for queue in queue_list:
            client.sai_thrift_clear_queue_stats(queue,cnt_ids,len(cnt_ids))

def sai_thrift_read_port_counters(client,port):
    port_cnt_ids=[]
    port_cnt_ids.append(SAI_PORT_STAT_IF_OUT_DISCARDS)
    port_cnt_ids.append(SAI_PORT_STAT_IF_IN_DISCARDS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_0_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_1_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_2_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_3_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_4_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_5_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_6_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_PFC_7_TX_PKTS)
    port_cnt_ids.append(SAI_PORT_STAT_IF_OUT_OCTETS)
    port_cnt_ids.append(SAI_PORT_STAT_IF_OUT_UCAST_PKTS)
    counters_results=[]
    counters_results = client.sai_thrift_get_port_stats(port,port_cnt_ids,len(port_cnt_ids))

    queue_list=[]
    port_attr_list = client.sai_thrift_get_port_attribute(port)
    attr_list = port_attr_list.attr_list
    for attribute in attr_list:
        if attribute.id == SAI_PORT_ATTR_QOS_QUEUE_LIST:
            for queue_id in attribute.value.objlist.object_id_list:
                queue_list.append(queue_id)
    cnt_ids=[]
    thrift_results=[]
    queue_counters_results=[]
    cnt_ids.append(SAI_QUEUE_STAT_PACKETS)
    queue1=0
    for queue in queue_list:
        if queue1 <= 7:
            thrift_results=client.sai_thrift_get_queue_stats(queue,cnt_ids,len(cnt_ids))
            queue_counters_results.append(thrift_results[0])
            queue1+=1
    return (counters_results, queue_counters_results)

def sai_thrift_read_port_watermarks(client,port):
    q_wm_ids=[]
    q_wm_ids.append(SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES)

    pg_wm_ids=[]
    pg_wm_ids.append(SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES)
    pg_wm_ids.append(SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES)

    queue_list=[]
    pg_list=[]
    port_attr_list = client.sai_thrift_get_port_attribute(port)
    attr_list = port_attr_list.attr_list
    for attribute in attr_list:
        if attribute.id == SAI_PORT_ATTR_QOS_QUEUE_LIST:
            for queue_id in attribute.value.objlist.object_id_list:
                queue_list.append(queue_id)
        elif attribute.id == SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST:
            for pg_id in attribute.value.objlist.object_id_list:
                pg_list.append(pg_id)

    thrift_results=[]
    queue_res=[]
    pg_shared_res=[]
    pg_headroom_res=[]

    # Only use the first 8 queues (unicast) - multicast queues are not used
    for queue in queue_list[:8]:
        thrift_results=client.sai_thrift_get_queue_stats(queue,q_wm_ids,len(q_wm_ids))
        queue_res.append(thrift_results[0])

    for pg in pg_list:
        thrift_results=client.sai_thrift_get_pg_stats(pg,pg_wm_ids,len(pg_wm_ids))
        pg_headroom_res.append(thrift_results[0])
        pg_shared_res.append(thrift_results[1])

    return (queue_res, pg_shared_res, pg_headroom_res)

def sai_thrift_read_pg_counters(client, port_id):
    pg_cntr_ids=[
        SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS
    ]

    # fetch pg ids under port id
    pg_ids = []
    port_attrs = client.sai_thrift_get_port_attribute(port_id)
    attrs = port_attrs.attr_list
    for attr in attrs:
        if attr.id == SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST:
            for pg_id in attr.value.objlist.object_id_list:
                pg_ids.append(pg_id)

    # get counter values of counter ids of interest under each pg
    pg_cntrs=[]
    for pg_id in pg_ids:
        cntr_vals = client.sai_thrift_get_pg_stats(pg_id, pg_cntr_ids, len(pg_cntr_ids))
        pg_cntrs.append(cntr_vals[0])

    return pg_cntrs

def sai_thrift_read_buffer_pool_watermark(client, buffer_pool_id):
    buffer_pool_wm_ids = [
        SAI_BUFFER_POOL_STAT_WATERMARK_BYTES
    ]

    wm_vals = client.sai_thrift_get_buffer_pool_stats(buffer_pool_id, buffer_pool_wm_ids)
    if not wm_vals:
        print >> sys.stderr, "sai_thrift_read_buffer_pool_watermark returns empty list"
        return None
    return wm_vals[0]

def sai_thrift_create_vlan_member(client, vlan_id, port_id, tagging_mode):
    vlan_member_attr_list = []
    attribute_value = sai_thrift_attribute_value_t(s32=vlan_id)
    attribute = sai_thrift_attribute_t(id=SAI_VLAN_MEMBER_ATTR_VLAN_ID,
                                           value=attribute_value)
    vlan_member_attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(oid=port_id)
    attribute = sai_thrift_attribute_t(id=SAI_VLAN_MEMBER_ATTR_PORT_ID,
                                           value=attribute_value)
    vlan_member_attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(s32=tagging_mode)
    attribute = sai_thrift_attribute_t(id=SAI_VLAN_MEMBER_ATTR_TAGGING_MODE,
                                           value=attribute_value)
    vlan_member_attr_list.append(attribute)
    vlan_member_id = client.sai_thrift_create_vlan_member(vlan_member_attr_list)
    return vlan_member_id

def sai_thrift_set_port_shaper(client, port_id, max_rate):
    sched_prof_id=sai_thrift_create_scheduler_profile(client, max_rate)
    attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
    attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
    client.sai_thrift_set_port_attribute(port_id,attr)
