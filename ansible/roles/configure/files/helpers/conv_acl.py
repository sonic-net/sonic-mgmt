#!/usr/bin/python

import calendar
import os
import sys
import socket
import struct
import json
import copy
import ipaddr as ipaddress
from collections import defaultdict

from lxml import etree as ET
from lxml.etree import QName

def dump_json(filename, data):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=True, separators=(',', ':'))

# Return: res, value, n (num of consumed elements)
def is_port(props, idx):
    if idx >= len(props):
        return False, "", 0
    if props[idx] == "eq":
        return True, props[idx+1], 2
    if props[idx] == "gt":
        return True, props[idx+1]+"-65535", 2
    if props[idx] == "lt":
        return True, "1-"+props[idx+1], 2
    if props[idx] == "range":
        return True, props[idx+1]+"-"+props[idx+2], 3
    return False, "", 0

def is_subnet(props, idx):
    if idx >= len(props):
        return False, "", 0
    if props[idx] == "any":
        return True, ""
    try:
        socket.inet_aton(props[idx].split("/")[0])
        return True, props[idx]
    except socket.error:
        False, ""

def generate_rule_json(table_name, rule_idx, rule):
    rule_props_list = rule.text.split()
    rule_props = {}
    rule_data = {}
    rule_data["ACL_RULE_TABLE:"+table_name+":Rule_"+str(rule_idx)] = rule_props
    rule_data["OP"] = "SET"
    rule_props["priority"] = "10"
    if rule_props_list[0] == "permit":
        rule_props["PACKET_ACTION"] = "FORWARD"
    elif rule_props_list[0] == "deny":
        rule_props["PACKET_ACTION"] = "DROP"
    else:
        print "Unknown rule action %s in table %s, rule %d!" % (rule_props_list[0], table_name, rule_idx)

    if rule_props_list[1] == "ip":
        rule_props["IP_TYPE"] = "IPV4ANY"
    elif rule_props_list[1] == "tcp":
        rule_props["IP_PROTOCOL"] = "6" # TCP protocol
    elif rule_props_list[1] == "icmp":
        rule_props["IP_PROTOCOL"] = "1" # ICMP protocol
    elif rule_props_list[1] == "udp":
        rule_props["IP_PROTOCOL"] = "17" # UDP protocol
    else:
        try:
            int(rule_props_list[1])
        except:
            print "Unknown rule protocol %s in table %s, rule %d!" % (rule_props_list[1], table_name, rule_idx)
            return {}
        else:
            rule_props["IP_PROTOCOL"] = rule_props_list[1]


    res, val = is_subnet(rule_props_list, 2)
    if not res:
        print "Src subnet error\n"
        return {}
    elif val:
        rule_props["SRC_IP"] = val

    i = 3
    res, val, n = is_port(rule_props_list, i)
    if res:
        if val.find("-") < 0:
            rule_props["L4_SRC_PORT"] = val
        else:
            rule_props["L4_SRC_PORT_RANGE"] = val

        i+=n


    res, val = is_subnet(rule_props_list, i)
    if not res:
        print "Dst subnet error"
        return {}
    elif val:
        rule_props["DST_IP"] = val
    i+=1

    res, val, n = is_port(rule_props_list, i)
    if res:
        if val.find("-") < 0:
            rule_props["L4_DST_PORT"] = val
        else:
            rule_props["L4_DST_PORT_RANGE"] = val
        i+=n

    if i < len(rule_props_list):
        if rule_props_list[i] == "rst":
            rule_props["TCP_FLAGS"] = "0xFF/0x04"
        if rule_props_list[i] == "ack":
            rule_props["TCP_FLAGS"] = "0xFF/0x10"
        if rule_props_list[i] == "syn":
            rule_props["TCP_FLAGS"] = "0xFF/0x02"

    return rule_data


def generate_table_json(policies):
    table_name = ""
    #print policy.attrib
    table_name = "ACL_Table"

    table_props = {}
    table_props["policy_desc"] = table_name
    table_props["type"] = "L3"
    table_props["ports"] = ",".join("Ethernet%d" % x for x in range(0, 128, 4))

    table_data = [{}]
    table_data[0]["ACL_TABLE:"+table_name] = table_props
    table_data[0]["OP"] = "SET"
    dump_json("table_"+table_name+".json", table_data)

    rule_idx = 0
    rule_data = []
    for policy in policies:
        for rule in policy.findall("Rule"):
            rule_props = generate_rule_json(table_name, rule_idx, rule)
            if rule_props:
                rule_data.append(rule_props)
            rule_idx+=1

    dump_json("rules_for_"+table_name+".json", rule_data)

def xml_to_json(filename):
    root = ET.parse(filename).getroot()

    for acl in root.findall("AccessControlList"):
        for aclgr in acl.findall("AclGroup"):
            generate_table_json(aclgr.findall("Policy"))

    return


def main():
        xml_to_json(sys.argv[1])

def debug_main():
    print_parse_xml('switch1')

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
