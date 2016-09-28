#!/usr/bin/python

# Note:
# Do not use 'env python' in shebang because Ansbile parses it straightforwardly and try to
# replace it with var ansible_python_interpreter. We exploit this var to implement docker exec support.
#
# ref: https://github.com/ansible/ansible/blob/devel/lib/ansible/executor/module_common.py

DOCUMENTATION = '''
---
module: switch_tables
version_added: "1.9"
short_description: Retrieve layer 3 tables
description:
    - Retrieve route, neighbor, nexthop, nexthopgroup table from ACS device
 
    Table format:
    results[route][prefix] = nhid/nhgid
    results[neighbor][ip]  = mac
    results[nexthop][ip]   = nhid
    results[nexthopgroup][nhgid] = [nhids]
'''

EXAMPLES = '''
# Retrieve l3table and egress table
- name: Get ASIC l3table and egress table
  switch_tables: l3table=yes egress=yes asic=broadcom
'''

from collections import defaultdict
import json
import re
import socket



# MELLANOX SECTION #
####################

def general_parse_log(output, keyword):
    list = []
    for line in output.split('\n'):
        line += " "
        if line.split(" ")[0].strip() == keyword:
            list.append(line)
        else:
            line = line.replace(" ", "")
            if keyword != "neighbor":
                line = line.replace(":", "=", 1)
            line += " "
            if len(list) > 0:
                list[-1] = list[-1] + line
    return list


def convert_hex_to_ip(ip):
    ip = int(ip, 16)
    a = ip & 0x000000ff
    b = (ip & 0x0000ff00) >> 8
    c = (ip & 0x00ff0000) >> 16
    d = (ip & 0xff000000) >> 24
    str_to_ret = str(d) + "." + str(c) + "." + str(b) + "." + str(a)
    return str_to_ret


def parse_neighbors(output):
    table = {}
    neighbours = general_parse_log(output, "neighbor")
    for neigh in neighbours:
        mac = 0
        neigh_attributes = []
        neigh = neigh[12:-1]
        for word in neigh.split(" "):
            neigh_attributes.append(word.strip())
        for item in neigh_attributes:
            if item.split("=")[0].strip() == "mac_addr":
                mac = item.split("=")[1].strip()
        for item in neigh_attributes:
            if item.split("=")[0].strip() == "s_addr":
                table[convert_hex_to_ip(item.split("=")[1].strip())] = mac
    return table


def parse_ecmp_id(output):
    ecmp_nh = general_parse_log(output, "next")
    nh_list = []
    for ecmp in ecmp_nh:
        ecmp_attributes = []
        ecmp = ecmp[11:-1]
        for word in ecmp.split(" "):
            ecmp_attributes.append(word.strip())
        nh_list.append(convert_hex_to_ip(ecmp_attributes[2].split("=")[1].strip()))
    return nh_list


def main():
    module = AnsibleModule(
        argument_spec=dict(
            asic=dict(required=True, choices=['mellanox', 'broadcom']),
            route=dict(required=False, default=False, choices=BOOLEANS),
            neighbor=dict(required=False, default=False, choices=BOOLEANS),
            nexthop=dict(required=False, default=False, choices=BOOLEANS),
            nexthopgroup=dict(required=False, default=False, choices=BOOLEANS)),
        supports_check_mode=True)

    results = dict()

    if module.params['asic'] == 'broadcom':
        self.module.fail_json(msg="Broadcom support missing.")
        

    if module.params['asic'] == 'mellanox':

        rc, out, err = module.run_command("/usr/local/bin/sx_api_router_uc_routes_dump_all.py")
        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                      (rc, out, err))
        routes_table = {}
        nhg_table = {}
        ecmp_ids = []
        routes = general_parse_log(out, "route")
        for route_attr in routes:
            attributes = []
            is_prefix = None
            route_attr = route_attr[9:-1]
            for word in route_attr.split(" "):
                attributes.append(word)
            if attributes[6].split("=")[0].strip() == "nexthoplist" and attributes[7].split("=")[0].strip() == "hop0":
                attributes[6:10] = [''.join(attributes[6:10])]
            for word in route_attr.split(" "):
                if word.split("=")[0].strip() == "s_addr" and is_prefix is None:
                    route = convert_hex_to_ip(word.split("=")[1])
                    is_prefix = True
                elif word.split("=")[0].strip() == "type" and word.split("=")[1].strip() == "NEXT_HOP":
                    for attr in attributes:
                        if attr.split("=")[0].strip() == "nexthoplist" and attr.split("=")[1].strip() != "":
                            routes_table[route] = convert_hex_to_ip(attr.split("=")[4].strip())

                        elif attr.split("=")[0].strip() == "ecmp_id" and attr.split("=")[1].strip() != "0":
                            routes_table[route] = attr.split("=")[1].strip()
                            if attr.split("=")[1].strip() not in ecmp_ids:
                                ecmp_ids.append(attr.split("=")[1].strip())

        for id in ecmp_ids:
            path = "/usr/local/bin/sx_api_router_ecmp_dump.py " + str(id)
            rc, out, err = module.run_command(path)
            if rc != 0:
                module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                     (rc, out, err))
            nhg_table[id] = parse_ecmp_id(out)

        rc, out, err = module.run_command("/usr/local/bin/sx_api_router_neigh_dump.py")
        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                      (rc, out, err))
        neighbors_table = parse_neighbors(out)

        if module.params['neighbor']:
            results['neighbor'] = neighbors_table

        if module.params['nexthopgroup']:
            results['nexthopgroup'] = nhg_table

        if module.params['nexthop']:
            results['nexthop'] = dict()
            for ip in routes_table:
                if routes_table[ip] not in nhg_table:
                    results['nexthop'][ip] = routes_table[ip]
            for nh in nhg_table:
                for ip in nhg_table[nh]:
                    results['nexthop'][ip] = ip

        if module.params['route']:
            results['route'] = routes_table

    module.exit_json(ansible_facts=results)


from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
