#!/usr/bin/env python3

import argparse
import json
import logging
import os

def _create_parser():
    parser = argparse.ArgumentParser(description='Scale CLI utility.')
    parser.add_argument('-t', '--num_of_table_entries', type=int, help='Number of table entries',
                      required=True)
    parser.add_argument('-m', '--num_of_members', type=int, help='Number of members',
                      required=True)
    parser.add_argument('-ml', '--member_list', type=int, help='member list',
                      required=False)
    parser.add_argument('-d', '--traffic_direction', type=str, help='Traffic direction',
                      required=False)
    return parser

def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    num_of_table_entries = args['num_of_table_entries']
    num_of_members = args['num_of_members']
    traffic_direction = args.get('traffic_direction')
    member_list = args.get('member_list')
    if traffic_direction is None:
        traffic_direction = "uni"
    
    member_1 = 27
    member_2 = 29
    ip_addr_1 = "100.27.1"
    ip_addr_2 = "200.27.1"
    table_dict = dict()
    table_dict['target'] = "th3"
    table_dict['p4info'] = "build/basic.json"
    table_dict['table_name'] = "ingress.l3_fwd.l3_ipv4_vrf_table"
    table_dict['action_profile_name'] = "ingress.l3_fwd.l3_action_profile"
    table_entries_list = list()
    member_list = list()

    for i in range(1,num_of_members+1):
        member_dict = dict()
        action_params_dict = dict()

        member_dict['member_id'] = i
        member_dict['entry_oper'] = "INSERT"
        member_dict['action_profile_id'] = 285212673
        member_dict['action_profile_name'] = "ingress.l3_fwd.l3_action_profile"
        member_dict['action_name'] = "ingress.l3_fwd.set_nexthop"
        action_params_dict['port'] = i
        if i < 10:
            last_octet = "0{}".format(i)
        else:
            last_octet = i
        action_params_dict['smac'] = "02:01:02:03:04:{}".format(last_octet)
        action_params_dict['dmac'] = "00:10:94:00:00:{}".format(last_octet)
        action_params_dict['l3_class_id'] = 10
        member_dict['action_params'] = action_params_dict
        member_list.append(member_dict)

    for i in range(1,num_of_members+1):
        member_dict = dict()
        action_params_dict = dict()

        member_dict['member_id'] = i
        member_dict['entry_oper'] = "DELETE"
        member_dict['action_profile_id'] = 285212673
        member_dict['action_profile_name'] = "ingress.l3_fwd.l3_action_profile"
        member_dict['action_name'] = "ingress.l3_fwd.set_nexthop"
        action_params_dict['port'] = i
        if i < 10:
            last_octet = "0{}".format(i)
        else:
            last_octet = i
        action_params_dict['smac'] = "02:01:02:03:04:{}".format(last_octet)
        action_params_dict['dmac'] = "00:10:94:00:00:{}".format(last_octet)
        action_params_dict['l3_class_id'] = 10
        member_dict['action_params'] = action_params_dict
        member_list.append(member_dict)
        
    table_dict['member_entries'] = member_list
    
    for i in range(1,num_of_table_entries+1):
        tel_dict = dict()
        match_dict = dict()
        dst_addr = list()

        tel_dict['table'] = "ingress.l3_fwd.l3_ipv4_vrf_table"
        tel_dict['entry_oper'] = "INSERT"
        match_dict['local_metadata.vrf_id'] = i
        dst_addr = ["{}.{}".format(ip_addr_1,i), 32]
        match_dict['hdr.ipv4_base.dst_addr'] = dst_addr
        tel_dict['match'] = match_dict
        tel_dict['action_member'] = member_1
        tel_dict['priority'] = 0
        table_entries_list.append(tel_dict)

        if traffic_direction == "bi":
            tel_dict = dict()
            match_dict = dict()
            dst_addr = list()

            tel_dict['table'] = "ingress.l3_fwd.l3_ipv4_vrf_table"
            tel_dict['entry_oper'] = "INSERT"
            match_dict['local_metadata.vrf_id'] = i
            dst_addr = ["{}.{}".format(ip_addr_2,i), 32]
            match_dict['hdr.ipv4_base.dst_addr'] = dst_addr
            tel_dict['match'] = match_dict
            tel_dict['action_member'] = member_2
            tel_dict['priority'] = 0
            table_entries_list.append(tel_dict)

    for i in range(1,num_of_table_entries+1):
        tel_dict = dict()
        match_dict = dict()
        dst_addr = list()

        tel_dict = dict()
        match_dict = dict()
        tel_dict['entry_oper'] = "DELETE"
        tel_dict['table'] = "ingress.l3_fwd.l3_ipv4_vrf_table"
        match_dict['local_metadata.vrf_id'] = i
        dst_addr = ["{}.{}".format(ip_addr_1,i), 32]
        match_dict['hdr.ipv4_base.dst_addr'] = dst_addr
        tel_dict['match'] = match_dict
        tel_dict['action_member'] = member_1
        tel_dict['priority'] = 0
        table_entries_list.append(tel_dict)

        if traffic_direction == "bi":
            tel_dict = dict()
            match_dict = dict()
            dst_addr = list()

            tel_dict = dict()
            match_dict = dict()
            tel_dict['entry_oper'] = "DELETE"
            tel_dict['table'] = "ingress.l3_fwd.l3_ipv4_vrf_table"
            match_dict['local_metadata.vrf_id'] = i
            dst_addr = ["{}.{}".format(ip_addr_2,i), 32]
            match_dict['hdr.ipv4_base.dst_addr'] = dst_addr
            tel_dict['match'] = match_dict
            tel_dict['action_member'] = member_2
            tel_dict['priority'] = 0
            table_entries_list.append(tel_dict)

    table_dict['table_entries'] = table_entries_list

    j = json.dumps(table_dict, indent=4)
    f = open('scale.json', 'w')
    print(j, file=f)

if __name__ == '__main__':
  main()