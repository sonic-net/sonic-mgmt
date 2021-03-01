#!/usr/bin/env python

import math
import os
import yaml
import re
import requests

from ansible.module_utils.basic import *

DOCUMENTATION = '''
module:  announce_routes
short_description: announce routes to exabgp processes running in PTF container
description: Announce routes to exabgp processes running in PTF container. This module must be executed on localhost
    which is the sonic-mgmt container.

Options:
    - option-name: topo_name
      description: topology name
      required: True

    - option-name: ptf_ip
      description: PTF container management IP address
      required: True
'''

EXAMPLES = '''
  - name: Announce routes
    announce_routes:
      topo_name: "t1-lag"
      ptf_ip: "192.168.1.10"
    delegate_to: localhost
'''

TOPO_FILE_FOLDER = 'vars/'
TOPO_FILENAME_TEMPLATE = 'topo_{}.yml'

PODSET_NUMBER = 200
TOR_NUMBER = 16
TOR_SUBNET_NUMBER = 2
MAX_TOR_SUBNET_NUMBER = 16
TOR_SUBNET_SIZE = 128
NHIPV4 = '10.10.246.254'
NHIPV6 = 'fc0a::ff'
SPINE_ASN = 65534
LEAF_ASN_START = 64600
TOR_ASN_START = 65500
IPV4_BASE_PORT = 5000
IPV6_BASE_PORT = 6000


def get_topo_type(topo_name):
    pattern = re.compile(r'^(t0|t1|ptf|fullmesh|dualtor)')
    match = pattern.match(topo_name)
    if not match:
        raise Exception("Unsupported testbed type - {}".format(topo_name))
    topo_type = match.group()
    if 'dualtor' in topo_type:
        # set dualtor topology type to 't0' to avoid adding it in each test script.
        topo_type = 't0'
    return topo_type


def read_topo(topo_name):
    topo_file_path = os.path.join(TOPO_FILE_FOLDER, TOPO_FILENAME_TEMPLATE.format(topo_name))
    try:
        with open(topo_file_path) as f:
            return yaml.safe_load(f)
    except IOError:
        return {}


def announce_routes(ptf_ip, port, routes):
    messages = []
    for prefix, nexthop, aspath in routes:
        if aspath:
            messages.append("announce route {} next-hop {} as-path [ {} ]".format(prefix, nexthop, aspath))
        else:
            messages.append("announce route {} next-hop {}".format(prefix, nexthop))

    url = "http://%s:%d" % (ptf_ip, port)
    data = { "commands": ";".join(messages) }
    r = requests.post(url, data=data)
    assert r.status_code == 200


def generate_routes(family, podset_number, tor_number, tor_subnet_number,
                    spine_asn, leaf_asn_start, tor_asn_start,
                    nexthop, nexthop_v6,
                    tor_subnet_size, max_tor_subnet_number,
                    router_type = "leaf", tor_index=None):
    routes = []

    default_route_as_path = "6666 6667"

    if router_type == "leaf":
        default_route_as_path = "{} {}".format(spine_asn, default_route_as_path)

    if router_type != 'tor':
        if family in ["v4", "both"]:
            routes.append(("0.0.0.0/0", nexthop, default_route_as_path))
        if family in ["v6", "both"]:
            routes.append(("::/0", nexthop_v6, default_route_as_path))

    # NOTE: Using large enough values (e.g., podset_number = 200,
    # us to overflow the 192.168.0.0/16 private address space here.
    # This should be fine for internal use, but may pose an issue if used otherwise
    for podset in range(0, podset_number):
        for tor in range(0, tor_number):
            for subnet in range(0, tor_subnet_number):
                if router_type == "spine":
                    # Skip podset 0 for T2
                    if podset == 0:
                        continue
                elif router_type == "leaf":
                    # Skip tor 0 podset 0 for T1
                    if podset == 0 and tor == 0:
                        continue
                elif router_type == "tor":
                    # Skip non podset 0 for T0
                    if podset != 0:
                        continue
                    elif tor != tor_index:
                        continue

                suffix = ( (podset * tor_number * max_tor_subnet_number * tor_subnet_size) + \
                      (tor * max_tor_subnet_number * tor_subnet_size) + \
                      (subnet * tor_subnet_size) )
                octet2 = (168 + (suffix / (256 ** 2)))
                octet1 = (192 + (octet2 / 256))
                octet2 = (octet2 % 256)
                octet3 = ((suffix / 256) % 256)
                octet4 = (suffix % 256)
                prefixlen_v4 = (32 - int(math.log(tor_subnet_size, 2)))

                prefix = "{}.{}.{}.{}/{}".format(octet1, octet2, octet3, octet4, prefixlen_v4)
                prefix_v6 = "20%02X:%02X%02X:0:%02X::/64" % (octet1, octet2, octet3, octet4)

                leaf_asn = leaf_asn_start + podset
                tor_asn  = tor_asn_start + tor

                aspath = None
                if router_type == "spine":
                    aspath = "{} {}".format(leaf_asn, tor_asn)
                elif router_type == "leaf":
                    if podset == 0:
                        aspath = "{}".format(tor_asn)
                    else:
                        aspath = "{} {} {}".format(spine_asn, leaf_asn, tor_asn)

                if family in ["v4", "both"]:
                    routes.append((prefix, nexthop, aspath))
                if family in ["v6", "both"]:
                    routes.append((prefix_v6, nexthop_v6, aspath))

    return routes


def fib_t0(topo, ptf_ip):

    common_config = topo['configuration_properties'].get('common', {})
    podset_number = common_config.get("podset_number", PODSET_NUMBER)
    tor_number = common_config.get("tor_number", TOR_NUMBER)
    tor_subnet_number = common_config.get("tor_subnet_number", TOR_SUBNET_NUMBER)
    max_tor_subnet_number = common_config.get("max_tor_subnet_number", MAX_TOR_SUBNET_NUMBER)
    tor_subnet_size = common_config.get("tor_subnet_size", TOR_SUBNET_SIZE)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    spine_asn = common_config.get("spine_asn", SPINE_ASN)
    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)

    vms = topo['topology']['VMs']
    for vm in vms.values():
        vm_offset = vm['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        routes_v4 = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                    spine_asn, leaf_asn_start, tor_asn_start,
                                    nhipv4, nhipv4, tor_subnet_size, max_tor_subnet_number)
        routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                    spine_asn, leaf_asn_start, tor_asn_start,
                                    nhipv6, nhipv6, tor_subnet_size, max_tor_subnet_number)

        announce_routes(ptf_ip, port, routes_v4)
        announce_routes(ptf_ip, port6, routes_v6)


def fib_t1_lag(topo, ptf_ip):

    common_config = topo['configuration_properties'].get('common', {})
    podset_number = common_config.get("podset_number", PODSET_NUMBER)
    tor_number = common_config.get("tor_number", TOR_NUMBER)
    tor_subnet_number = common_config.get("tor_subnet_number", TOR_SUBNET_NUMBER)
    max_tor_subnet_number = common_config.get("max_tor_subnet_number", MAX_TOR_SUBNET_NUMBER)
    tor_subnet_size = common_config.get("tor_subnet_size", TOR_SUBNET_SIZE)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)

    vms = topo['topology']['VMs']
    vms_config = topo['configuration']

    for k, v in vms_config.items():
        vm_offset = vms[k]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        router_type = None
        if 'spine' in v['properties']:
            router_type = 'spine'
        elif 'tor' in v['properties']:
            router_type = 'tor'
        tornum = v.get('tornum', None)
        tor_index = tornum - 1 if tornum is not None else None
        if router_type:
            routes_v4 = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                        None, leaf_asn_start, tor_asn_start,
                                        nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number,
                                        router_type=router_type, tor_index=tor_index)
            routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                        None, leaf_asn_start, tor_asn_start,
                                        nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number,
                                        router_type=router_type, tor_index=tor_index)
            announce_routes(ptf_ip, port, routes_v4)
            announce_routes(ptf_ip, port6, routes_v6)

        if 'vips' in v:
            routes_vips = []
            for prefix in v["vips"]["ipv4"]["prefixes"]:
                routes_vips.append((prefix, nhipv4, v["vips"]["ipv4"]["asn"]))
            announce_routes(ptf_ip, port, routes_vips)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            topo_name=dict(required=True, type='str'),
            ptf_ip=dict(required=True, type='str')
        ),
        supports_check_mode=False)

    topo_name = module.params['topo_name']
    ptf_ip = module.params['ptf_ip']

    topo = read_topo(topo_name)
    if not topo:
        module.fail_json(msg='Unable to load topology "{}"'.format(topo_name))

    topo_type = get_topo_type(topo_name)

    if topo_type == "t0":
        fib_t0(topo, ptf_ip)
        module.exit_json(changed=True)
    elif topo_type == "t1":
        fib_t1_lag(topo, ptf_ip)
        module.exit_json(changed=True)
    else:
        module.fail_json(msg='Unsupported topology "{}"'.format(topo_name))


if __name__ == '__main__':
    main()
