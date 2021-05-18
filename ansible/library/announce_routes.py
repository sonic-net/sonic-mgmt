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
    pattern = re.compile(r'^(t0|t1|ptf|fullmesh|dualtor|t2)')
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

# AS path from Leaf router for T0 topology
def get_leaf_uplink_as_path(spine_asn):
    default_route_as_path = "6666 6667"
    return "{} {}".format(spine_asn, default_route_as_path)

# AS path from Spine router for T1 topology
def get_spine_uplink_as_path():
    default_route_as_path = "6666 6667"
    return "{}".format(default_route_as_path)

# AS path from Core router for T2 topology
def get_core_uplink_as_path():
    default_route_as_path = "6666 6667"
    return "{}".format(default_route_as_path)

# Get AS path to append to uplink routers AS for routes being advertised by this uplink router.
def get_uplink_router_as_path(uplink_router_type, spine_asn):
    default_route_as_path = None
    # router type must be one of 'leaf', 'spine', 'core'. 'tor' routers are not uplink routers
    if uplink_router_type == "leaf":
        default_route_as_path = get_leaf_uplink_as_path(spine_asn)
    elif uplink_router_type == "spine":
        default_route_as_path = get_spine_uplink_as_path()
    elif uplink_router_type == "core":
        default_route_as_path = get_core_uplink_as_path()
    return default_route_as_path


def generate_routes(family, podset_number, tor_number, tor_subnet_number,
                    spine_asn, leaf_asn_start, tor_asn_start,
                    nexthop, nexthop_v6,
                    tor_subnet_size, max_tor_subnet_number, topo,
                    router_type = "leaf", tor_index=None, set_num=None):
    routes = []
    if router_type != "tor":
        default_route_as_path = get_uplink_router_as_path(router_type, spine_asn)

        if topo != "t2" or (topo == "t2" and router_type == "core"):
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
                if router_type == "core":
                    # Advertise podset 3+ to T2 DUT
                    if podset < 3:
                        continue

                    # First 3 pods are advertised from T1 - so remove 3 from the total pods being advertised by T3
                    first_third_podset_number = int(math.ceil((podset_number - 3) / 3.0))
                    second_third_podset_number = int(math.ceil(((podset_number - 3) * 2) / 3.0))

                    if set_num is not None:
                        # For T2, we have 3 sets - 1 set advertises first 1/3 podsets, second set advertises second 1/3 podsets, and all VM's advertises the last 1/3 podsets
                        if podset <= first_third_podset_number and set_num != 0:
                            continue
                        elif podset > first_third_podset_number and podset < second_third_podset_number and set_num != 1:
                            continue
                if router_type == "spine":
                    # Skip podset 0 for T2
                    if podset == 0:
                        continue
                elif router_type == "leaf":
                    if topo == 't2':
                        # Send routes for podset 0-2 (first 3 pods) to the T2 DUT
                        if podset > 2:
                            continue

                        if set_num is not None:
                            # For T2, we have 3 sets - 1 set advertises podset 1, second set advertises podset 2, and all VM's advertises podset3
                            if podset == 0 and set_num != 0:
                                continue
                            elif podset == 1 and set_num != 1:
                                continue
                    else:
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
                if router_type == "core":
                    aspath = "{} {}".format(leaf_asn, tor_asn)
                elif router_type == "spine":
                    aspath = "{} {}".format(leaf_asn, tor_asn)
                elif router_type == "leaf":
                    if topo == "t2":
                        aspath = "{}".format(tor_asn)
                    else:
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
                                    nhipv4, nhipv4, tor_subnet_size, max_tor_subnet_number, "t0")
        routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                    spine_asn, leaf_asn_start, tor_asn_start,
                                    nhipv6, nhipv6, tor_subnet_size, max_tor_subnet_number, "t0")

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
                                        nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t1",
                                        router_type=router_type, tor_index=tor_index)
            routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                        None, leaf_asn_start, tor_asn_start,
                                        nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t1",
                                        router_type=router_type, tor_index=tor_index)
            announce_routes(ptf_ip, port, routes_v4)
            announce_routes(ptf_ip, port6, routes_v6)

        if 'vips' in v:
            routes_vips = []
            for prefix in v["vips"]["ipv4"]["prefixes"]:
                routes_vips.append((prefix, nhipv4, v["vips"]["ipv4"]["asn"]))
            announce_routes(ptf_ip, port, routes_vips)


"""
For T2, we have 3 sets of routes that we are going to advertise
    - 1st set of 1/3 routes are advertised by the first 1/3 of the VMs
    - 2nd set of 1/3 routes are advertised by the remaining 2/3rd of the VMs
    - 3rd set of 1/3 routes are advertised by all the VMs
Also, T1 VM's are potentially distributed over 2 linecards (asics). The same set of routes should be sent by
the same set in both the linecards. So, if linecard1 and linecard2 have T1 VMs connected, then
    -  1st set of routes should be advertised by the first 1/3 of the VMs on linecard1 and also by the first
       1/3 of the VMs on linecard2.
    -  2nd set of routes should be advertised by the remaining 2/3 of the VMs on linecard1 and also by the remaining
        2/3 of the VMs on linecard2.
    -  3rd set of routes should be advertised by the all VMs on linecard1 and also by all VMs on linecard2
It is assumed that tne number of T1 VMs that on both the linecards is the same.
If we don't have 2 linecards for T1 VMs, then routes above would be advertised only by the first linecard that has T1 VMs

The total number of routes are controlled by the podset_number, tor_number, and tor_subnet_number from the topology file.
With the proposed T2 topology with 400 podsets, and 32 routes per podset we would have 12K routes.
In this topology, we have 24 VMs on each linecard (24 T3 VMs and 48 T1 VMs over 2 linecards).
We would have the following distribution:
- T1 Routes:
   - 192.168.xx.xx (32 routes) from the first 8 T1 VM's from linecard2 and linecard3 (VM25-VM32, and VM49-VM56)
   - 192.169.xx.xx (32 routes) from the remaining 16 T1 VM's on linecard2 and linecard3 (VM33-VM48, and VM64-VM72)
   - 192.170.xx.xx (32 routes) from all T1 VMs on linecard2 and linecard3 (VM25-VM48, and VM49-VM72)
- T3 Routes:
   - 192.171.xx.xx to 193.45.xx.xx (4K routes) from from first 8 T3 VM's on linecard1 (VM1-VM8)
   - 193.46.xx.xx to 193.176.xx.xx (4K routes) from the remaining 16 T3 VM's on linecard1 (VM9-VM24)
   - 193.177.xx.xx - 194.55.xx.xx (4K routes) from all 24 T3 VM's on linecard1 (VM1-VM24)
   - default route from all 24 T3 VM's on linecard1 (VM1-VM24)
"""
def fib_t2_lag(topo, ptf_ip):

    vms = topo['topology']['VMs']
    # T1 VMs per linecard(asic) - key is the dut index, and value is a list of T1 VMs
    t1_vms = {}
    # T3 VMs per linecard(asic) - key is the dut index, and value is a list of T3 VMs
    t3_vms = {}

    for key, value in vms.items():
        m = re.match("(\d+)\.(\d+)@(\d+)", value['vlans'][0])
        dut_index = int(m.group(1))
        if 'T1' in key:
            if dut_index not in t1_vms:
                t1_vms[dut_index] = list()
            t1_vms[dut_index].append(key)

        if 'T3' in key:
            if dut_index not in t3_vms:
                t3_vms[dut_index] = list()
            t3_vms[dut_index].append(key)
    generate_t2_routes(t1_vms, topo, ptf_ip)
    generate_t2_routes(t3_vms, topo, ptf_ip)

def generate_t2_routes(dut_vm_dict, topo, ptf_ip):
    common_config = topo['configuration_properties'].get('common', {})
    vms = topo['topology']['VMs']
    vms_config = topo['configuration']

    podset_number = common_config.get("podset_number", PODSET_NUMBER)
    tor_number = common_config.get("tor_number", TOR_NUMBER)
    tor_subnet_number = common_config.get("tor_subnet_number", TOR_SUBNET_NUMBER)
    max_tor_subnet_number = common_config.get("max_tor_subnet_number", MAX_TOR_SUBNET_NUMBER)
    tor_subnet_size = common_config.get("tor_subnet_size", TOR_SUBNET_SIZE)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)

    # generate routes for t1 vms
    for a_dut_index in dut_vm_dict:
        # sort the list of VMs
        all_vms = sorted(dut_vm_dict[a_dut_index])
        n_vms = len(all_vms)
        first_third_vm_index = int(math.ceil(n_vms / 3.0))

        for a_vm_index, a_vm in enumerate(all_vms):
            if len(all_vms) == 1:
                # Only 1 VM, have it advertise all sets of routes
                set_num = None
            elif a_vm_index < first_third_vm_index:
                set_num = 0
            else:
                set_num = 1
            vm_offset = vms[a_vm]['vm_offset']
            port = IPV4_BASE_PORT + vm_offset
            port6 = IPV6_BASE_PORT + vm_offset

            router_type = None
            if 'leaf' in vms_config[a_vm]['properties']:
                router_type = 'leaf'
            elif 'core' in vms_config[a_vm]['properties']:
                router_type = 'core'

            tor_index = None

            if router_type:
                routes_v4 = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                            common_config['dut_asn'], leaf_asn_start, tor_asn_start,
                                            nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t2",
                                            router_type=router_type, tor_index=tor_index, set_num=set_num)
                routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                            common_config['dut_asn'], leaf_asn_start, tor_asn_start,
                                            nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t2",
                                            router_type=router_type, tor_index=tor_index, set_num=set_num)
                announce_routes(ptf_ip, port, routes_v4)
                announce_routes(ptf_ip, port6, routes_v6)

                if 'vips' in vms_config[a_vm]:
                    routes_vips = []
                    for prefix in vms_config[a_vm]["vips"]["ipv4"]["prefixes"]:
                        routes_vips.append((prefix, nhipv4, vms_config[a_vm]["vips"]["ipv4"]["asn"]))
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
    elif topo_type == "t2":
        fib_t2_lag(topo, ptf_ip)
        module.exit_json(changed=True)
    else:
        module.exit_json(msg='Unsupported topology "{}" - skipping announcing routes'.format(topo_name))


if __name__ == '__main__':
    main()
