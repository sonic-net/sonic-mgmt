#!/usr/bin/env python
# This ansible module is for gathering ACL related facts from SONiC device.
#
# The "sonic-cfggen" tool is used to output all the running config data from db in JSON format. ACL table information
# is extracted from the all config by key name 'ACL_TABLE'. ACL rule information is extracted by key name 'ACL_RULE'.
#
# Logically, ACL rules belong to a specific ACL table. The extracted information are aggregated into one dictionary.
# A dictionary with key name 'rules' under each ACL dictionary entry holds all ACL rules belong to it.
#
# Command "aclshow -a" can output counters of each ACL rule. The output is parsed and counter values are aggregated
# into the collected ACL table facts too.
#
# Example output of "aclshow -a":
#
# root@mtbc-sonic-03-2700:/home/admin# aclshow -a
# RULE NAME     TABLE NAME      PRIO    PACKETS COUNT    BYTES COUNT
# ------------  ------------  ------  ---------------  -------------
# RULE_1        DATAACL         9999                0              0
# RULE_2        DATAACL         9998                0              0
# DEFAULT_RULE  DATAACL            1             9216        1019489
#
# Example of module output:
# {
#     "ansible_facts": {
#         "ansible_acl_facts": {
#             "DATAACL": {
#                 "policy_desc": "DATAACL",
#                 "ports": [
#                     "PortChannel0001",
#                     "PortChannel0002",
#                     "PortChannel0003",
#                     "PortChannel0004"
#                 ],
#                 "rules": {
#                     "DEFAULT_RULE": {
#                         "ETHER_TYPE": "2048",
#                         "PACKET_ACTION": "DROP",
#                         "PRIORITY": "1",
#                         "bytes_count": "5686888",
#                         "packets_count": "51193"
#                     },
#                     "RULE_1": {
#                         "PACKET_ACTION": "FORWARD",
#                         "PRIORITY": "9999",
#                         "SRC_IP": "10.0.0.2/32",
#                         "bytes_count": "0",
#                         "packets_count": "0"
#                     },
#                     "RULE_2": {
#                         "DST_IP": "192.168.0.16/32",
#                         "PACKET_ACTION": "FORWARD",
#                         "PRIORITY": "9998",
#                         "bytes_count": "0",
#                         "packets_count": "0"
#                     }
#                 },
#                 "type": "L3"
#             },
#             "EVERFLOW": {
#                 "policy_desc": "EVERFLOW",
#                 "ports": [
#                     "PortChannel0001",
#                     "PortChannel0002",
#                     "PortChannel0003",
#                     "PortChannel0004",
#                     "Ethernet100",
#                     "Ethernet104",
#                     "Ethernet92",
#                     "Ethernet96",
#                     "Ethernet84",
#                     "Ethernet88",
#                     "Ethernet76",
#                     "Ethernet80",
#                     "Ethernet108",
#                     "Ethernet64",
#                     "Ethernet60",
#                     "Ethernet52",
#                     "Ethernet48",
#                     "Ethernet44",
#                     "Ethernet40",
#                     "Ethernet36",
#                     "Ethernet56",
#                     "Ethernet72",
#                     "Ethernet68",
#                     "Ethernet24",
#                     "Ethernet20",
#                     "Ethernet16",
#                     "Ethernet12",
#                     "Ethernet8",
#                     "Ethernet4",
#                     "Ethernet0",
#                     "Ethernet32",
#                     "Ethernet28"
#                 ],
#                 "rules": {},
#                 "type": "MIRROR"
#             },
#             "SNMP_ACL": {
#                 "policy_desc": "SNMP_ACL",
#                 "rules": {},
#                 "services": [
#                     "SNMP"
#                 ],
#                 "type": "CTRLPLANE"
#             },
#             "SSH_ONLY": {
#                 "policy_desc": "SSH_ONLY",
#                 "rules": {},
#                 "services": [
#                     "SSH"
#                 ],
#                 "type": "CTRLPLANE"
#             }
#         }
#     }
# }

from ansible.module_utils.basic import *
from collections import defaultdict
from sonic_py_common import multi_asic


DOCUMENTATION = '''
---
module: acl_facts
version_added: "2.0"
author: Xin Wang (xinw@mellanox.com)
short_description: Retrive ACL facts for a device.
description:
    - Retrieve ACL facts for a device, the facts will be
      inserted to the ansible_facts key.
options:
    N/A
'''

EXAMPLES = '''
# Gather ACL facts
- name: Gathering ACL facts about the device
  acl_facts:
'''


def get_all_config(module):
    """
    @summary:  all running configuration using CLI tool sonic-cfggen.
    @param module: The AnsibleModule object
    @return: Return parsed config in dict
    """
    rc, stdout, stderr = module.run_command('sonic-cfggen -d --print-data')
    if rc != 0:
        module.fail_json(msg='Failed to get DUT running config, rc=%s, stdout=%s, stderr=%s' % (rc, stdout, stderr))

    try:
        return module.from_json(stdout)
    except Exception as e:
        module.fail_json(msg='Failed to parse config from output of "sonic-cfggen -d --print-data", err=' + str(e))

    return None


def get_acl_rule_counters(module):
    """
    @summary: Parse the output of CLI 'aclshow -a' to get counters value of all ACL rules.
    @param module: The AnsibleModule object
    @return: Return ACL rule counters data in dict
    """
    counter_aggrgeate_map = defaultdict(list)
    counters = []

    namespace_list = multi_asic.get_namespace_list()
    for ns in namespace_list:
        cmd = 'sudo ip netns exec {} '.format(ns) if ns else ''
        rc, stdout, stderr = module.run_command(cmd + 'aclshow -a')
        if rc != 0:
            module.fail_json(msg='Failed to get acl counter data, rc=%s, stdout=%s, stderr=%s' % (rc, stdout, stderr))
        
        output_lines = stdout.splitlines()[2:]  # Skip the header lines in output
        for line in output_lines:
            line_expanded = line.split()
            if len(line_expanded) == 5:
                try:
                    packets_count = int(line_expanded[3])
                except ValueError:
                    packets_count = 0
                try:
                    bytes_count = int(line_expanded[4])
                except ValueError:
                    bytes_count = 0

                key = (line_expanded[0],line_expanded[1],line_expanded[2])
                if key in counter_aggrgeate_map:
                     counter_aggrgeate_map[key][0] = packets_count + counter_aggrgeate_map[key][0]
                     counter_aggrgeate_map[key][1] = bytes_count + counter_aggrgeate_map[key][1]
                else:
                     counter_aggrgeate_map[key].append(packets_count)
                     counter_aggrgeate_map[key].append(bytes_count)

    for k, v in counter_aggrgeate_map.items():
         counter = dict(rule_name=k[0],
                       table_name=k[1],
                       priority=k[2],
                       packets_count=v[0],
                       bytes_count=v[1])
         counters.append(counter)

    return counters


def merge_acl_table_and_rule(all_config):
    """
    @summary: Merge ACL_TABLE and ACL_RULE data from all config into one dictionary.

    Data of ACL_TABLE and ACL_RULE are under different keys in the all_config dict. Merge the ACL_RULE data into
    ACL_TABLE and return dictionary of ACL tables containing their own ACL rules.

    @param all_config: The dict containing all running config of DUT
    @return: Return a dict of ACL tables containing their own ACL rules.
    """
    acl_tables = all_config['ACL_TABLE']

    for table in acl_tables:
        acl_tables[table]['rules'] = {}

    for rule in all_config.get('ACL_RULE', {}):
        rule_expanded = rule.split('|')
        if len(rule_expanded) == 2:
            table_name = rule_expanded[0]
            rule_name = rule_expanded[1]
            if table_name in acl_tables:
                acl_tables[table_name]['rules'][rule_name] = all_config['ACL_RULE'][rule]

    return acl_tables


def merge_acl_table_and_counter(acl_tables, counters):
    """
    @summary: Merge the ACL counters data into the ACL tables dictionary.

    Counters of ACL rules are parsed from output of 'aclshow -a'. This function merges the counters of ACL rules
    into the ACL tables dict.

    @param acl_tables: The dict of ACL tables
    @param counters: The dict containing counters data of ACL rules
    @return: Return a dict of ACL tables containing ACL rules and counters
    """
    for counter in counters:
        table_name = counter['table_name']
        rule_name = counter['rule_name']
        if table_name in acl_tables:
            if rule_name in acl_tables[table_name]['rules']:
                acl_tables[table_name]['rules'][rule_name]['packets_count'] = counter['packets_count']
                acl_tables[table_name]['rules'][rule_name]['bytes_count'] = counter['bytes_count']

    return acl_tables


def main():

    module = AnsibleModule(argument_spec=dict())

    all_config = get_all_config(module)
    if not all_config:
        module.fail_json(msg='Empty DUT config')

    counters = get_acl_rule_counters(module)

    acl_tables = merge_acl_table_and_rule(all_config)
    acl_tables = merge_acl_table_and_counter(acl_tables, counters)

    module.exit_json(ansible_facts={'ansible_acl_facts': acl_tables})


if __name__ == '__main__':
    main()
