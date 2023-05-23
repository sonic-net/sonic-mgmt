#! /usr/bin/python3

import ipaddress
import json
import yaml

from functools import reduce

from port_utils import get_port_alias_to_name_map

ACL_ACTION_ACCEPT = "ACCEPT"
ACL_ACTION_DROP = "DROP"

ACL_TABLE_BMC_NORTHBOUND = "BMC_ACL_NORTHBOUND"
ACL_TABLE_BMC_NORTHBOUND_V6 = "BMC_ACL_NORTHBOUND_V6"
ACL_TABLE_BMC_SOUTHBOUND_V6 = "BMC_ACL_SOUTHBOUND_V6"

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

IP_PROTOCOL_TCP = "IP_TCP"
IP_PROTOCOL_UDP = "IP_UDP"

TCP_FLAG_ACK = "TCP_ACK"
TCP_FLAG_SYN = "TCP_SYN"


def minimum_supernet(ip_list):
    supernet = ipaddress.ip_network(ip_list[0])
    for ip in ip_list:
        while not supernet.supernet_of(ipaddress.ip_network(ip)):
            supernet = supernet.supernet()
    return supernet


def ip_merge(ip_list, exclude_list=None):
    result = [minimum_supernet(ip_list)]
    while exclude_list:
        exclude_net = ipaddress.ip_network(exclude_list[0])
        if any([exclude_net.overlaps(res) for res in result]):
            while all([not exclude_net.supernet().overlaps(ipaddress.ip_network(ip)) for ip in ip_list]):
                exclude_net = exclude_net.supernet()
            result = reduce(lambda x, y: x + y, [list(res.address_exclude(exclude_net)) if res.overlaps(exclude_net) else [res] for res in result])
        exclude_list = [ex for ex in exclude_list if not exclude_net.supernet_of(ipaddress.ip_network(ex))]
    return result


def acl_entry(seq_id, action=ACL_ACTION_DROP, ethertype=None, interfaces=None,
              src_ip=None, dst_ip=None, ip_protocol=None, tcp_flags=None):
    rule = {
        "config": {"sequence-id": seq_id},
        "actions": {"config": {"forwarding-action": action}},
    }
    if src_ip or dst_ip or ip_protocol:
        ip_cfg = {}
        if src_ip:
            ip_cfg["source-ip-address"] = src_ip
        if dst_ip:
            ip_cfg["destination-ip-address"] = dst_ip
        if ip_protocol:
            ip_cfg["protocol"] = ip_protocol
        rule["ip"] = {"config": ip_cfg}
    if interfaces:
        rule["input_interface"] = {"interface_ref": {"config": {"interface": ",".join(interfaces)}}}
    if ethertype:
        rule["l2"] = {"config": {"ethertype": ethertype}}
    if tcp_flags:
        rule["transport"] = {"config": {"tcp-flags": tcp_flags}}
    return rule


def gen_northbound_acl_entries_v4(rack_topo, hwsku):
    port_alias_to_name, _, _ = get_port_alias_to_name_map(hwsku)
    shelfs = rack_topo['shelfs']
    rms = [shelf['rm'] for shelf in shelfs]
    bmc_groups = reduce(lambda x, y: x + y, [shelf['bmc'] for shelf in shelfs])
    bmc_hosts = reduce(lambda x, y: x + y, [bmc_gp['hosts'] for bmc_gp in bmc_groups])
    rm_ips = [rm.get('ipv4_subnet', None) or rm['ipv4_addr'] for rm in rms]
    bmc_ips = [bg['config']['ipv4_subnet'] for bg in bmc_groups if bg['config'].get('ipv4_subnet', None) is not None] + \
              [bh['ipv4_addr'] for bh in bmc_hosts if bh.get('ipv4_addr', None) is not None]

    acl_entries = {}
    sequence_id = 1

    # IN_PORTS = BMC, DST_IP = BMC => DROP
    bmc_intfs = [port_alias_to_name[host['port_alias']] for host in bmc_hosts]
    bmc_nets = ip_merge(bmc_ips, rm_ips)
    sub_seq = 1
    for bmc_net in bmc_nets:
        acl_entries["{:04d}_IN_PORTS_BMC_DST_IP_BMC_{}".format(sequence_id, sub_seq)] = \
            acl_entry(sequence_id, dst_ip=format(bmc_net), interfaces=bmc_intfs)
        sequence_id += 5
        sub_seq += 1

    sequence_id = max(sequence_id, 101)
    # For same shelf:
    #   - SRC_IP = RM, DST_IP = BMC => ACCEPT
    #   - SRC_IP = BMC, DST_IP = RM => ACCEPT
    if len(shelfs) == 1:
        shelf = shelfs[0]
        rm = shelf['rm']
        rm_ip = ipaddress.ip_network(rm.get('ipv4_subnet', None) or rm['ipv4_addr'])
        acl_entries["{:04d}_SRC_IP_RM".format(sequence_id)] = \
            acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(rm_ip))
        sequence_id += 5
        acl_entries["{:04d}_DST_IP_RM".format(sequence_id)] = \
            acl_entry(sequence_id, ACL_ACTION_ACCEPT, dst_ip=format(rm_ip))
        sequence_id += 5
    else:
        for shelf in shelfs:
            sub_seq = 1
            rm = shelf['rm']
            rm_ip = ipaddress.ip_network(rm.get('ipv4_subnet', None) or rm['ipv4_addr'])
            for bmc_gp in shelf['bmc']:
                if bmc_gp.get('config', {}).get('ipv4_subnet', None):
                    bmc_ip = ipaddress.ip_network(bmc_gp['config']['ipv4_subnet'])
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(rm_ip), dst_ip=format(bmc_ip))
                    sequence_id += 5
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(bmc_ip), dst_ip=format(rm_ip))
                    sequence_id += 5
                    sub_seq += 1
                else:
                    gp_bmc_ips = [bh['ipv4_addr'] for bh in bmc_gp['hosts']]
                    gp_bmc_nets = ip_merge(gp_bmc_ips, list(set(bmc_ips) - set(gp_bmc_ips)) + rm_ips)
                    for gp_bmc_net in gp_bmc_nets:
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(rm_ip), dst_ip=format(gp_bmc_net))
                        sequence_id += 5
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(gp_bmc_net), dst_ip=format(rm_ip))
                        sequence_id += 5
                        sub_seq += 1

    # All other ipv4 packages => DROP
    sequence_id = 9990
    acl_entries["{:04d}_DROP_ALL".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV4)
    sequence_id += 5

    return {"acl-entries": {"acl-entry": acl_entries}}


def gen_northbound_acl_entries_v6(rack_topo, hwsku):
    port_alias_to_name, _, _ = get_port_alias_to_name_map(hwsku)
    shelfs = rack_topo['shelfs']
    rms = [shelf['rm'] for shelf in shelfs]
    rm_intfs = [port_alias_to_name[rm['port_alias']] for rm in rms]
    rm_support_ipv6 = any([rm.get('ipv6_subnet', None) or rm.get('ipv6_addr', None) for rm in rms])
    bmc_groups = reduce(lambda x, y: x + y, [shelf['bmc'] for shelf in shelfs])
    bmc_hosts = reduce(lambda x, y: x + y, [bmc_gp['hosts'] for bmc_gp in bmc_groups])
    bmc_intfs = [port_alias_to_name[host['port_alias']] for host in bmc_hosts]
    rm_ips = [rm.get('ipv6_subnet', None) or rm['ipv6_addr'] for rm in rms if rm.get('ipv6_subnet', None) or rm.get('ipv6_addr', None) is not None]
    rm_ips = [rm['ipv6_subnet'] for rm in rms if rm.get('ipv6_subnet', None) is not None] + \
             [rm['ipv6_addr'] for rm in rms if rm.get('ipv6_addr', None) is not None]
    bmc_ips = [bg['config']['ipv6_subnet'] for bg in bmc_groups if bg['config'].get('ipv6_subnet', None) is not None] + \
              [bh['ipv6_addr'] for bh in bmc_hosts if bh.get('ipv6_addr', None) is not None]

    acl_entries = {}

    sequence_id = 1  # 9900 <= priority < 10000

    # If IPv6 is supported on any RM
    if rm_support_ipv6:
        # IN_PORTS = BMC, DST_IP = BMC => DROP
        # (Avoid one BMC send package to another BMC)
        bmc_nets = ip_merge(bmc_ips, rm_ips)
        sub_seq = 1
        for bmc_net in bmc_nets:
            acl_entries["{:04d}_IN_PORTS_BMC_DST_IP_BMC_{}".format(sequence_id, sub_seq)] = \
                acl_entry(sequence_id, ACL_ACTION_DROP, dst_ip=format(bmc_net), interfaces=bmc_intfs)
            sequence_id += 5
            sub_seq += 1

        # IN_PORTS = RM, DST_IP = RM => DROP
        # (Avoid one RM send package to another RM)
        rm_nets = ip_merge(rm_ips, bmc_ips)
        sub_seq = 1
        for rm_net in rm_nets:
            acl_entries["{:04d}_IN_PORTS_RM_DST_IP_RM_{}".format(sequence_id, sub_seq)] = \
                acl_entry(sequence_id, ACL_ACTION_DROP, dst_ip=format(rm_net), interfaces=rm_intfs)
            sequence_id += 5
            sub_seq += 1

    sequence_id = 9001  # 900 <= priority < 1000

    if rm_support_ipv6:
        # For same shelf: (Only needed if IPv6 is supported on RM)
        #   - SRC_IP = RM, DST_IP = BMC => ACCEPT
        #   - SRC_IP = BMC, DST_IP = RM => ACCEPT
        for shelf in shelfs:
            rm = shelf['rm']
            rm_ip = ipaddress.ip_network(rm.get('ipv6_subnet', None) or rm['ipv6_addr'])
            sub_seq = 1
            for bmc_gp in shelf['bmc']:
                if bmc_gp.get('config', {}).get('ipv6_subnet', None):
                    bmc_ip = ipaddress.ip_network(bmc_gp['config']['ipv6_subnet'])
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(rm_ip), dst_ip=format(bmc_ip))
                    sequence_id += 5
                    acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                        acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(bmc_ip), dst_ip=format(rm_ip))
                    sequence_id += 5
                    sub_seq += 1
                else:
                    gp_bmc_ips = [bh['ipv6_addr'] for bh in bmc_gp['hosts']]
                    gp_bmc_nets = ip_merge(gp_bmc_ips, list(set(bmc_ips) - set(gp_bmc_ips)) + rm_ips)
                    for gp_bmc_net in gp_bmc_nets:
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_RM_DST_IP_BMC_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(rm_ip), dst_ip=format(gp_bmc_net))
                        sequence_id += 5
                        acl_entries["{:04d}_SHELF_{}_SRC_IP_BMC_DST_IP_RM_{}".format(sequence_id, shelf['id'], sub_seq)] = \
                            acl_entry(sequence_id, ACL_ACTION_ACCEPT, src_ip=format(gp_bmc_net), dst_ip=format(rm_ip))
                        sequence_id += 5
                        sub_seq += 1

    # All other ipv6 packets => DROP
    # (Prevent BMC send package to upstream)
    # (If RM doesn't support IPv6, this rule can also prevent one BMC send package to another BMC)
    sequence_id = 9990  # priority = 10
    acl_entries["{:04d}_DROP_ALL".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV6)
    sequence_id += 5

    return {"acl-entries": {"acl-entry": acl_entries}}


def gen_southbound_acl_entries_v6(rack_topo, hwsku):
    shelfs = rack_topo['shelfs']
    rms = [shelf['rm'] for shelf in shelfs]
    bmc_groups = reduce(lambda x, y: x + y, [shelf['bmc'] for shelf in shelfs])
    bmc_hosts = reduce(lambda x, y: x + y, [bmc_gp['hosts'] for bmc_gp in bmc_groups])

    acl_entries = {}

    # By default, drop all the southbound traffic:
    # MARCH_ALL => DROP
    sequence_id = 9990  # priority = 10
    acl_entries["{:04d}_DROP_ALL".format(sequence_id)] = acl_entry(sequence_id, ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV6)
    sequence_id += 5

    return {"acl-entries": {"acl-entry": acl_entries}}


def gen_acl_rules(topo_file, hwsku):
    with open(topo_file) as f:
        rack_topo = yaml.safe_load(f)

    acl_set = {}
    if ACL_TABLE_BMC_NORTHBOUND in rack_topo['config']['acl_tables']:
        acl_set[ACL_TABLE_BMC_NORTHBOUND] = gen_northbound_acl_entries_v4(rack_topo, hwsku)
    if ACL_TABLE_BMC_NORTHBOUND_V6 in rack_topo['config']['acl_tables']:
        acl_set[ACL_TABLE_BMC_NORTHBOUND_V6] = gen_northbound_acl_entries_v6(rack_topo, hwsku)
    if ACL_TABLE_BMC_SOUTHBOUND_V6 in rack_topo['config']['acl_tables']:
        acl_set[ACL_TABLE_BMC_SOUTHBOUND_V6] = gen_southbound_acl_entries_v6(rack_topo, hwsku)
    acl_rules = {"acl": {"acl-sets": {"acl-set": acl_set}}}

    acl_rule_file_name = rack_topo['config']['acl_rule_file_name']
    with open(acl_rule_file_name, 'w') as fout:
        json.dump(acl_rules, fout, sort_keys=True, indent=2)


def gen_bmc_otw_acl_rules():
    gen_acl_rules("bmc_otw_topo.yaml", "Nokia-7215")


def gen_bmc_ares_acl_rules():
    gen_acl_rules("bmc_ares_topo.yaml", "Nokia-7215")


def main():
    gen_bmc_otw_acl_rules()
    gen_bmc_ares_acl_rules()


if __name__ == '__main__':
    main()
