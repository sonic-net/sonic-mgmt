#!/usr/bin/env python

import math
import os
import yaml
import re
import requests
import ipaddress
import json
import sys
import socket
import random
import logging
import time
from multiprocessing.pool import ThreadPool
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.debug_utils import config_module_logging

if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode      # noqa F821

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

    - option-name: action
      description: announce or withdraw routes
      required: False

    - option-name: path
      description: to figure out the path of topo_{}.yml
      required: False
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
CORE_RA_ASN = 65900
LEAF_ASN_START = 64600
TOR_ASN_START = 65500
IPV4_BASE_PORT = 5000
IPV6_BASE_PORT = 6000

# Describe default number of COLOs
COLO_NUMBER = 30
# Describe default number of M0 devices in 1 colo
M0_NUMBER = 16
# Describe default number of subnet in a M0 device
M0_SUBNET_NUMBER = 2
# Describe default number of members in a M0 subnet
M0_SUBNET_SIZE = 64
# Describe default number of MX device connected to M0 device
MX_NUMBER = 2
# Describe default number of subnet in a MX device
MX_SUBNET_NUMBER = 2
# Describe default number of subnet members
MX_SUBNET_SIZE = 64
# Describe default start asn of MXs
MX_ASN_START = 68000
# Describe default start asn of M0s
M0_ASN_START = 64600
# Describe default IPv6 subnet prefix length of MX
MX_SUBNET_PREFIX_LEN_V6 = 64
# Describe default IPv6 subnet prefix length of M0
M0_SUBNET_PREFIX_LEN_V6 = 64
# Describe default start asn of M1s
M1_ASN_START = 65200


def wait_for_http(host_ip, http_port, timeout=10):
    """
    Waits for HTTP server to open.
    Tries until timeout is reached and returns whether localhost received HTTP response
    """
    started = False
    tries = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    while not started and tries < timeout:
        try:
            s.connect((host_ip, http_port))
            started = True
        except socket.error:
            tries += 1

    return started


def get_topo_type(topo_name):
    pattern = re.compile(
        r'^(t0-mclag|t0|t1|ptf|fullmesh|dualtor|t2|mgmttor|m0|mc0|mx|dpu)')
    match = pattern.match(topo_name)
    if not match:
        return "unsupported"
    topo_type = match.group()
    if topo_type in ['dualtor', 'mgmttor']:
        # set dualtor/mgmttor topology type to 't0' to avoid adding it in each test script.
        topo_type = 't0'
    if topo_type in ['mc0']:
        topo_type = 'm0'
    return topo_type


def read_topo(topo_name, path):
    topo_file_path = os.path.join(
        path, TOPO_FILE_FOLDER, TOPO_FILENAME_TEMPLATE.format(topo_name))
    try:
        with open(topo_file_path) as f:
            return yaml.safe_load(f)
    except IOError:
        return {}


def change_routes(action, ptf_ip, port, routes):
    messages = []
    for prefix, nexthop, aspath in routes:
        if aspath:
            messages.append(
                "{} route {} next-hop {} as-path [ {} ]".format(action, prefix, nexthop, aspath))
        else:
            messages.append(
                "{} route {} next-hop {}".format(action, prefix, nexthop))
    wait_for_http(ptf_ip, port, timeout=60)
    url = "http://%s:%d" % (ptf_ip, port)
    data = {"commands": ";".join(messages)}

    # nosemgrep-next-line
    # Flaky error `ConnectionResetError(104, 'Connection reset by peer')` may happen while using `requests.post`
    # To avoid this error, we add sleep time before sending request.
    # We use a "backoff" algorithm here, the maximum retry times is five.
    # If one retry fails, we increase the waiting time.
    for i in range(0, 5):
        try:
            r = requests.post(url, data=data, timeout=360, proxies={"http": None, "https": None})
            break
        except Exception as e:
            logging.debug("Got exception {}, will try to connect again".format(e))
            time.sleep(0.01 * (i+1))
            if i == 4:
                raise e

    if r.status_code != 200:
        raise Exception(
            "Change routes failed: url={}, data={}, r.status_code={}, r.reason={}, r.headers={}, r.text={}".format(
                url,
                json.dumps(data),
                r.status_code,
                r.reason,
                r.headers,
                r.text
            )
        )


def send_routes_for_each_set(args):
    routes, port, action, ptf_ip = args
    change_routes(action, ptf_ip, port, routes)


def send_routes_in_parallel(route_set):
    """
    Sends the given set of routes in parallel using a thread pool.

    Args:
        route_set (list): A list of route sets to send.

    Returns:
        None
    """
    # Create a pool of worker processes
    pool = ThreadPool(processes=len(route_set))

    # Use the ThreadPool.map function to apply the function to each set of routes
    results = pool.map(send_routes_for_each_set, route_set)

    # Optionally, process the results
    for result in results:
        # Process individual results here
        pass

    # Close the pool and wait for all processes to complete
    pool.close()
    pool.join()


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


# Generate prefixs of route
def generate_prefix(subnet_size, ip_base, offset):
    ip = get_new_ip(ip_base, offset)
    prefixlen = (ip_base.max_prefixlen - int(math.log(subnet_size, 2)))
    prefix = "{}/{}".format(ip, prefixlen)

    return prefix


def generate_m0_upstream_routes(nexthop, colo_number, m0_number, m0_subnet_number, m0_asn_start, mx_number,
                                mx_subnet_number, ip_base, m0_subnet_size, mx_subnet_size, mx_asn_start):
    routes = []

    # Generate default route
    routes.append(("0.0.0.0/0" if ip_base.version ==
                  4 else "::/0", nexthop, None))

    # Number of direct subnet members connected to a M0 device
    m0_direct_subnet_member_count = m0_subnet_number * m0_subnet_size
    # Number of MX subnet members connected to a M0 device
    m0_mx_subnet_member_count = mx_number * mx_subnet_number * mx_subnet_size
    # Total number of subnet members connected to a M0 device
    m0_subnet_member_count = m0_direct_subnet_member_count + m0_mx_subnet_member_count
    for colo in range(0, colo_number):
        # Number of subnet members of colo that has been calculated
        colo_subnet_member_offset = colo * m0_number * m0_subnet_member_count
        for m0_index in range(0, m0_number):
            # Skip M0 direct routes
            if colo == 0 and m0_index == 0:
                continue

            # Number of subnet members of M0 in current colo that has been caculated
            m0_subnet_member_offset = m0_index * m0_subnet_member_count
            # Total number of subnet members of M0 that has been caculated
            total_offset = colo_subnet_member_offset + m0_subnet_member_offset
            curr_m0_asn = m0_asn_start + m0_index
            m0_subnet_routes, prefix = generate_m0_subnet_routes(m0_subnet_number, m0_subnet_size, ip_base, nexthop,
                                                                 total_offset, curr_m0_asn)
            routes += m0_subnet_routes

            # Start ip of MX subnets
            ip_base_mx = ip_base if prefix is None else get_next_ip_by_net(
                prefix)
            m0_mx_routes, _ = generate_m0_mx_routes(
                mx_subnet_number, mx_subnet_size, mx_number, mx_asn_start, ip_base_mx, nexthop, curr_m0_asn)
            routes += m0_mx_routes

    return routes


def generate_m0_downstream_routes(nexthop, mx_subnet_number, mx_subnet_size, m0_subnet_number, m0_subnet_size, ip_base,
                                  mx_index):
    routes = []

    # Number of direct subnet members connected to a M0 device
    m0_direct_subnet_member_count = m0_subnet_number * m0_subnet_size
    # Number of subnet members connected to a MX device
    mx_subnet_member_count = mx_subnet_number * mx_subnet_size
    # Number of subnet members of MX that has been calculated
    mx_subnet_member_offset = mx_index * mx_subnet_member_count
    for subnet in range(0, mx_subnet_number):
        # Not need after asn path of MX
        # Number of subnet members of subnet in current MX that has been caculated
        subnet_member_offset = subnet * mx_subnet_size
        offset = m0_direct_subnet_member_count + \
            mx_subnet_member_offset + subnet_member_offset
        prefix = generate_prefix(mx_subnet_size, ip_base, offset)
        routes.append((prefix, nexthop, None))

    return routes


def generate_m0_routes(nexthop, colo_number, m0_number, m0_subnet_number, m0_asn_start, router_type, m0_subnet_size,
                       mx_number, mx_subnet_number, ip_base, mx_subnet_size, mx_asn_start, mx_index):
    if router_type == "m1":
        return generate_m0_upstream_routes(nexthop, colo_number, m0_number, m0_subnet_number, m0_asn_start, mx_number,
                                           mx_subnet_number, ip_base, m0_subnet_size, mx_subnet_size, mx_asn_start)

    if router_type == "mx":
        return generate_m0_downstream_routes(nexthop, mx_subnet_number, mx_subnet_size, m0_subnet_number,
                                             m0_subnet_size, ip_base, mx_index)

    return []


def generate_routes(family, podset_number, tor_number, tor_subnet_number,
                    spine_asn, leaf_asn_start, tor_asn_start, nexthop,
                    nexthop_v6, tor_subnet_size, max_tor_subnet_number, topo,
                    router_type="leaf", tor_index=None, set_num=None,
                    no_default_route=False, core_ra_asn=CORE_RA_ASN):
    routes = []
    if not no_default_route and router_type != "tor":
        default_route_as_path = get_uplink_router_as_path(
            router_type, spine_asn)

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
                    first_third_podset_number = int(
                        math.ceil((podset_number - 3) / 3.0))
                    second_third_podset_number = int(
                        math.ceil(((podset_number - 3) * 2) / 3.0))

                    if set_num is not None:
                        # For T2, we have 3 sets - 1 set advertises first 1/3 podsets,
                        # second set advertises second 1/3 podsets, and all VM's advertises the last 1/3 podsets
                        if podset <= first_third_podset_number and set_num != 0:
                            continue
                        elif podset > first_third_podset_number and \
                                podset < second_third_podset_number and set_num != 1:
                            continue
                if router_type == "spine" or router_type == "mgmtleaf":
                    # Skip podset 0 for T2
                    if podset == 0:
                        continue
                elif router_type == "leaf":
                    if topo == 't2':
                        # Send routes for podset 0-2 (first 3 pods) to the T2 DUT
                        if podset > 2:
                            continue

                        if set_num is not None:
                            # For T2, we have 3 sets - 1 set advertises podset 1,
                            # second set advertises podset 2, and all VM's advertises podset3
                            if podset == 0 and set_num != 0:
                                continue
                            elif podset == 1 and set_num != 1:
                                continue
                    elif topo == 't0-mclag':
                        if podset > 1:
                            continue
                        if set_num is not None:
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
                    # Skip subnet 0 (vlan ip) for M0
                    elif topo == "m0" and subnet == 0:
                        continue
                    elif tor != tor_index:
                        continue

                suffix = ((podset * tor_number * max_tor_subnet_number * tor_subnet_size) +
                          (tor * max_tor_subnet_number * tor_subnet_size) +
                          (subnet * tor_subnet_size))
                octet2 = (168 + int(suffix / (256 ** 2)))
                octet1 = (192 + int(octet2 / 256))
                octet2 = (octet2 % 256)
                octet3 = (int(suffix / 256) % 256)
                octet4 = (suffix % 256)
                prefixlen_v4 = (32 - int(math.log(tor_subnet_size, 2)))

                prefix = "{}.{}.{}.{}/{}".format(octet1,
                                                 octet2, octet3, octet4, prefixlen_v4)
                prefix_v6 = "20%02X:%02X%02X:0:%02X::/64" % (
                    octet1, octet2, octet3, octet4)

                leaf_asn = leaf_asn_start + podset
                tor_asn = tor_asn_start + tor

                aspath = None
                if router_type == "core":
                    aspath = "{} {}".format(leaf_asn, core_ra_asn)
                elif router_type == "spine" or router_type == "mgmtleaf":
                    aspath = "{} {}".format(leaf_asn, tor_asn)
                elif router_type == "leaf":
                    if topo == "t2":
                        aspath = "{}".format(tor_asn)
                    elif topo == "t0-mclag":
                        aspath = "{}".format(tor_asn)
                    else:
                        if podset == 0:
                            aspath = "{}".format(tor_asn)
                        else:
                            aspath = "{} {} {}".format(
                                spine_asn, leaf_asn, tor_asn)

                if family in ["v4", "both"]:
                    routes.append((prefix, nexthop, aspath))
                if family in ["v6", "both"]:
                    routes.append((prefix_v6, nexthop_v6, aspath))

    return routes


def fib_t0(topo, ptf_ip, no_default_route=False, action="announce"):
    common_config = topo['configuration_properties'].get('common', {})
    podset_number = common_config.get("podset_number", PODSET_NUMBER)
    tor_number = common_config.get("tor_number", TOR_NUMBER)
    tor_subnet_number = common_config.get(
        "tor_subnet_number", TOR_SUBNET_NUMBER)
    max_tor_subnet_number = common_config.get(
        "max_tor_subnet_number", MAX_TOR_SUBNET_NUMBER)
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
                                    nhipv4, nhipv4, tor_subnet_size, max_tor_subnet_number, "t0",
                                    no_default_route=no_default_route)
        routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                    spine_asn, leaf_asn_start, tor_asn_start,
                                    nhipv6, nhipv6, tor_subnet_size, max_tor_subnet_number, "t0",
                                    no_default_route=no_default_route)

        change_routes(action, ptf_ip, port, routes_v4)
        change_routes(action, ptf_ip, port6, routes_v6)


def fib_t1_lag(topo, ptf_ip, no_default_route=False, action="announce"):
    common_config = topo['configuration_properties'].get('common', {})
    podset_number = common_config.get("podset_number", PODSET_NUMBER)
    tor_number = common_config.get("tor_number", TOR_NUMBER)
    tor_subnet_number = common_config.get(
        "tor_subnet_number", TOR_SUBNET_NUMBER)
    max_tor_subnet_number = common_config.get(
        "max_tor_subnet_number", MAX_TOR_SUBNET_NUMBER)
    tor_subnet_size = common_config.get("tor_subnet_size", TOR_SUBNET_SIZE)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)

    vms = topo['topology']['VMs']
    vms_config = topo['configuration']

    dpus = None
    if 'DPUs' in topo['topology']:
        dpus = topo['topology']['DPUs']

    for k, v in vms_config.items():
        if dpus and k in dpus:
            continue

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
                                        router_type=router_type, tor_index=tor_index,
                                        no_default_route=no_default_route)
            routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                        None, leaf_asn_start, tor_asn_start,
                                        nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t1",
                                        router_type=router_type, tor_index=tor_index,
                                        no_default_route=no_default_route)
            change_routes(action, ptf_ip, port, routes_v4)
            change_routes(action, ptf_ip, port6, routes_v6)

        if 'vips' in v:
            routes_vips = []
            for prefix in v["vips"]["ipv4"]["prefixes"]:
                routes_vips.append((prefix, nhipv4, v["vips"]["ipv4"]["asn"]))
            change_routes(action, ptf_ip, port, routes_vips)


def get_new_ip(curr_ip, skip_count):
    """
    Get the [skip_count]th ip after curr_ip
    """
    new_ip = ipaddress.ip_address(int(curr_ip) + skip_count)
    return new_ip


def get_next_ip_by_net(net_str):
    """
    Get the nearest next non-overlapping ip address based on the net_str
    Sample input:
    str, "192.168.0.1/24"
    Sample output:
    <class 'ipaddress.ip_address'>, 192.168.3.0/32
    """
    net = ipaddress.ip_network(UNICODE_TYPE(net_str), strict=False)
    net_size = int(net.broadcast_address) + 1 - int(net.network_address)
    next_net = get_new_ip(net.network_address, net_size)
    return next_net


def get_next_ip(skip_nets):
    """
    Get minimum ip addresss which is bigger than any ip address in skip_nets.
    Sample input:
    [
        "192.168.0.1/24",
        "192.168.0.1/25",
        "192.168.0.128/25",
        "192.168.2.1/24",
    ]
    Sample output:
    <class 'ipaddress.ip_address'>, 192.168.3.0/32
    """
    max_next_ip = None
    for vlan in skip_nets:
        next_ip = get_next_ip_by_net(vlan)
        if max_next_ip is None:
            max_next_ip = next_ip
        elif next_ip > max_next_ip:
            max_next_ip = next_ip
    return max_next_ip


def get_ip_base_by_vlan_config(vlan_configs):
    """
    To avoid overlaping of ip, skip all vlan ips.
    """
    vlan_prefixs = []
    for _, vlans in vlan_configs.items():
        for _, config in vlans.items():
            vlan_prefixs.append(config["prefix"])

    ip_base = get_next_ip(vlan_prefixs)
    return ip_base


"""
For M0, we have 2 sets of routes that we are going to advertised
    - 1st set routes are advertised by the upstream VMs (M1 devices)
    - 2nd set routes are advertised by the downstream VMs (MX devices)

The total number of routes are controlled by the colo_number, m0_number, mx_subnet_number, m0_subnet_number and number
of MX devices from the topology file.
We would have the following distribution:
- M1 Routes:
   - 1 default route, prefix: 0.0.0.0/0
   - Subnet routes of M0 devices connected to M1 devices other than DUT,
     count: (colo_number * m0_number - 1) * m0_subnet_number
   - Subnet routes of MX devices connected to M0 devices connected M1 devices,
     count: (colo_number * m0_number - 1) * mx_number * mx_subnet_number
- MX Routes:
   - Subunet routes of MX, count: mx_subnet_number
"""


def fib_m0(topo, ptf_ip, action="announce"):
    common_config = topo['configuration_properties'].get('common', {})
    colo_number = common_config.get("colo_number", COLO_NUMBER)
    m0_number = common_config.get("m0_number", M0_NUMBER)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    m0_asn_start = common_config.get("m0_asn_start", M0_ASN_START)
    m0_subnet_number = common_config.get("m0_subnet_number", M0_SUBNET_NUMBER)
    m0_subnet_size = common_config.get("m0_subnet_size", M0_SUBNET_SIZE)
    mx_subnet_size = common_config.get("mx_subnet_size", MX_SUBNET_SIZE)
    mx_subnet_number = common_config.get("mx_subnet_number", MX_SUBNET_NUMBER)
    mx_asn_start = common_config.get("mx_asn_start", MX_ASN_START)
    # In general, IPv6 prefix length should be less then 64
    m0_subnet_prefix_len_v6 = common_config.get(
        "m0_subnet_prefix_len_v6", M0_SUBNET_PREFIX_LEN_V6)
    mx_subnet_prefix_len_v6 = common_config.get(
        "mx_subnet_prefix_len_v6", MX_SUBNET_PREFIX_LEN_V6)

    vms = topo['topology']['VMs']
    vms_config = topo['configuration']
    mx_list = list(filter(lambda x: "MX" in x, vms_config.keys()))
    mx_number = len(mx_list)

    # In order to avoid overlapping the routes announced and the vlan of m0, get ip_start
    vlan_configs = dict(
        filter(lambda x: "default" not in x[0], topo["topology"]["DUT"]["vlan_configs"].items()))

    ip_base = get_ip_base_by_vlan_config(vlan_configs)
    ip_base_v6 = ipaddress.IPv6Address(UNICODE_TYPE("20c0:a800::0"))

    m1_routes_v4 = None
    m1_routes_v6 = None
    mx_index = -1
    for k, v in vms_config.items():
        vm_offset = vms[k]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        router_type = None
        # Upstream
        if "m1" in v["properties"]:
            router_type = "m1"
        # Downstream
        elif "mx" in v["properties"]:
            router_type = "mx"
            mx_index += 1

        # Routes announced by different M1s are the same, can reuse generated routes
        if router_type == "m1" and m1_routes_v4 is not None:
            routes_v4 = m1_routes_v4
            routes_v6 = m1_routes_v6
        else:
            m0_subnet_size_v6 = 2 ** (128 - m0_subnet_prefix_len_v6)
            mx_subnet_size_v6 = 2 ** (128 - mx_subnet_prefix_len_v6)
            routes_v4 = generate_m0_routes(nhipv4, colo_number, m0_number, m0_subnet_number, m0_asn_start, router_type,
                                           m0_subnet_size, mx_number, mx_subnet_number, ip_base, mx_subnet_size,
                                           mx_asn_start, mx_index)
            routes_v6 = generate_m0_routes(nhipv6, colo_number, m0_number, m0_subnet_number, m0_asn_start, router_type,
                                           m0_subnet_size_v6, mx_number, mx_subnet_number, ip_base_v6,
                                           mx_subnet_size_v6, mx_asn_start, mx_index)

            if router_type == "m1":
                m1_routes_v4 = routes_v4
                m1_routes_v6 = routes_v6

        change_routes(action, ptf_ip, port, routes_v4)
        change_routes(action, ptf_ip, port6, routes_v6)


def generate_m0_subnet_routes(m0_subnet_number, m0_subnet_size, ip_base, nexthop, base_offset=0, m0_asn=None):
    """
    Generate subnet routes of M0 device
    """
    routes = []
    prefix = None
    for m0_subnet in range(0, m0_subnet_number):
        # Number of subnet members of subnet in current M0 that has been caculated
        subnet_member_offset = m0_subnet * m0_subnet_size
        offset = base_offset + subnet_member_offset

        prefix = generate_prefix(m0_subnet_size, ip_base, offset)

        # For mx topo, current m0 is neighbor of DUT, which will announce this route. Not need after asn path of M0
        # For m0 topo, need after path of M0
        aspath = None if m0_asn is None else "{}".format(m0_asn)
        routes.append((prefix, nexthop, aspath))

    return routes, prefix


def generate_m0_mx_routes(mx_subnet_number, mx_subnet_size, mx_number, mx_asn_start, ip_base_mx, nexthop, m0_asn=None):
    """
    Generate MX routes of M0 device
    """
    routes = []
    prefix = None
    # Number of subnet members connected to a MX device
    mx_subnet_member_count = mx_subnet_number * mx_subnet_size
    for mx in range(mx_number):
        # Number of subnet members of MX that has been calculated
        mx_subnet_member_offset = mx * mx_subnet_member_count
        curr_mx_asn = mx_asn_start + mx
        for mx_subnet in range(mx_subnet_number):
            # Number of subnet members of subnet in current MX that has been calculated
            subnet_member_offset = mx_subnet * mx_subnet_size
            offset = mx_subnet_member_offset + subnet_member_offset

            prefix = generate_prefix(mx_subnet_size, ip_base_mx, offset)
            # For mx topo, current m0 is neighbor of DUT, which will announce this route. Not need M0 asn
            # For m0 topo, need M0 asn
            aspath = "{}".format(curr_mx_asn) if m0_asn is None else "{} {}".format(
                m0_asn, curr_mx_asn)

            routes.append((prefix, nexthop, aspath))

    return routes, prefix


def generate_mx_routes(nexthop, colo_number, m0_number, m0_subnet_number, m0_asn_start, m0_subnet_size, mx_number,
                       mx_subnet_number, ip_base, mx_subnet_size, mx_asn_start, m1_asn):
    routes = []

    # Generate default route
    routes.append(("0.0.0.0/0" if ip_base.version ==
                  4 else "::/0", nexthop, None))

    # Direct routes of connected M0: m0_subnet_number
    m0_subnet_routes, prefix = generate_m0_subnet_routes(
        m0_subnet_number, m0_subnet_size, ip_base, nexthop)
    routes += m0_subnet_routes

    # Downstream routes of connected M0: (mx_number - 1) * mx_subnet_number
    # Start ip of MX subnets
    ip_base_mx = ip_base if prefix is None else get_next_ip_by_net(prefix)
    # Number of subnet members connected to a MX device
    m0_mx_routes, prefix = generate_m0_mx_routes(mx_subnet_number, mx_subnet_size, mx_number-1, mx_asn_start,
                                                 ip_base_mx, nexthop)
    routes += m0_mx_routes

    # Upstream routes of connected M0:
    #     (colo_number * m0_number - 1) * (m0_subnet_number + mx_number * mx_subnet_number)
    # Start ip of M0 upstream routes
    ip_base_m0_upstream = ip_base_mx if prefix is None else get_next_ip_by_net(
        prefix)
    m0_upstream_routes = generate_m0_upstream_routes(
        nexthop, colo_number, m0_number, m0_subnet_number, m0_asn_start+1,
        mx_number, mx_subnet_number, ip_base_m0_upstream, m0_subnet_size,
        mx_subnet_size, mx_asn_start)
    for route in m0_upstream_routes:
        routes.append((route[0], route[1], "{} {}".format(m1_asn, route[2])))

    return routes


"""
For MX, we have 1 set of routes that we are going to advertised
    - Routes are advertised by the upstream VMs (M0 devices).

The total number of routes are controlled by the colo_number, m0_number,
    mx_subnet_number, m0_subnet_number and mx_number.
Routes announced by M0 can be broken down to 5 sets:
   - 1 default route, prefix: 0.0.0.0/0.
   - 1 loopback route.
   - Direct subnet routes of M0 connected to DUT,
     count: m0_subnet_number
   - Subnet routes of MX connected to M0 connected to DUT,
     count: (mx_number - 1) * mx_subnet_number.
   - Upstream routes of M0 connected to DUT,
     count: (colo_number * m0_number - 1) * (mx_number * mx_subnet_number + m0_subnet_number).
"""


def fib_mx(topo, ptf_ip, action="announce"):
    common_config = topo['configuration_properties'].get('common', {})
    colo_number = common_config.get("colo_number", COLO_NUMBER)
    m0_number = common_config.get("m0_number", M0_NUMBER)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    m0_asn_start = common_config.get("m0_asn_start", M0_ASN_START)
    m0_subnet_number = common_config.get("m0_subnet_number", M0_SUBNET_NUMBER)
    m0_subnet_size = common_config.get("m0_subnet_size", M0_SUBNET_SIZE)
    mx_subnet_size = common_config.get("mx_subnet_size", MX_SUBNET_SIZE)
    mx_subnet_number = common_config.get("mx_subnet_number", MX_SUBNET_NUMBER)
    mx_asn_start = common_config.get("mx_asn_start", MX_ASN_START)
    # In general, IPv6 prefix length should be less then 64
    m0_subnet_prefix_len_v6 = common_config.get(
        "m0_subnet_prefix_len_v6", M0_SUBNET_PREFIX_LEN_V6)
    mx_subnet_prefix_len_v6 = common_config.get(
        "mx_subnet_prefix_len_v6", MX_SUBNET_PREFIX_LEN_V6)
    mx_number = common_config.get("mx_number", MX_NUMBER)
    m1_asn_start = common_config.get("m1_asn_start", M1_ASN_START)

    vms = topo['topology']['VMs']
    vms_config = topo['configuration']

    # In order to avoid overlapping the routes announced and the vlan of mx, get ip_start
    vlan_configs = dict(
        filter(lambda x: "default" not in x[0], topo["topology"]["DUT"]["vlan_configs"].items()))

    ip_base = get_ip_base_by_vlan_config(vlan_configs)
    ip_base_v6 = ipaddress.IPv6Address(UNICODE_TYPE("20c0:a800::0"))

    m0_routes_v4 = None
    m0_routes_v6 = None
    for k, v in vms_config.items():
        vm_offset = vms[k]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        # Routes announced by different M0s are the same, can reuse generated routes
        if m0_routes_v4 is not None:
            routes_v4 = m0_routes_v4
            routes_v6 = m0_routes_v6
        else:
            m0_subnet_size_v6 = 2 ** (128 - m0_subnet_prefix_len_v6)
            mx_subnet_size_v6 = 2 ** (128 - mx_subnet_prefix_len_v6)
            routes_v4 = generate_mx_routes(nhipv4, colo_number, m0_number, m0_subnet_number, m0_asn_start,
                                           m0_subnet_size, mx_number, mx_subnet_number, ip_base, mx_subnet_size,
                                           mx_asn_start, m1_asn_start)
            routes_v6 = generate_mx_routes(nhipv6, colo_number, m0_number, m0_subnet_number, m0_asn_start,
                                           m0_subnet_size_v6, mx_number, mx_subnet_number, ip_base_v6,
                                           mx_subnet_size_v6, mx_asn_start, m1_asn_start)

            m0_routes_v4 = routes_v4
            m0_routes_v6 = routes_v6

        change_routes(action, ptf_ip, port, routes_v4)
        change_routes(action, ptf_ip, port6, routes_v6)


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
If we don't have 2 linecards for T1 VMs,
    then routes above would be advertised only by the first linecard that has T1 VMs

The total number of routes are controlled by the podset_number, tor_number,
    and tor_subnet_number from the topology file.
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


def fib_t2_lag(topo, ptf_ip, action="announce"):
    route_set = []
    vms = topo['topology']['VMs']
    # T1 VMs per linecard(asic) - key is the dut index, and value is a list of T1 VMs
    t1_vms = {}
    # T3 VMs per linecard(asic) - key is the dut index, and value is a list of T3 VMs
    t3_vms = {}

    for key, value in vms.items():
        m = re.match(r"(\d+)\.(\d+)@(\d+)", value['vlans'][0])
        dut_index = int(m.group(1))
        if 'T1' in key:
            if dut_index not in t1_vms:
                t1_vms[dut_index] = list()
            t1_vms[dut_index].append(key)

        if 'T3' in key:
            if dut_index not in t3_vms:
                t3_vms[dut_index] = list()
            t3_vms[dut_index].append(key)
    route_set += generate_t2_routes(t1_vms, topo, ptf_ip, action)
    route_set += generate_t2_routes(t3_vms, topo, ptf_ip, action)
    send_routes_in_parallel(route_set)


def generate_t2_routes(dut_vm_dict, topo, ptf_ip, action="announce"):
    common_config = topo['configuration_properties'].get('common', {})
    vms = topo['topology']['VMs']
    vms_config = topo['configuration']
    r_set = []

    podset_number = common_config.get("podset_number", PODSET_NUMBER)
    tor_number = common_config.get("tor_number", TOR_NUMBER)
    tor_subnet_number = common_config.get(
        "tor_subnet_number", TOR_SUBNET_NUMBER)
    max_tor_subnet_number = common_config.get(
        "max_tor_subnet_number", MAX_TOR_SUBNET_NUMBER)
    tor_subnet_size = common_config.get("tor_subnet_size", TOR_SUBNET_SIZE)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)
    core_ra_asn = common_config.get("core_ra_asn", CORE_RA_ASN)

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
                                            router_type=router_type, tor_index=tor_index, set_num=set_num,
                                            core_ra_asn=core_ra_asn)
                routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                            common_config['dut_asn'], leaf_asn_start, tor_asn_start,
                                            nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t2",
                                            router_type=router_type, tor_index=tor_index, set_num=set_num,
                                            core_ra_asn=core_ra_asn)
                random.shuffle(routes_v4)
                random.shuffle(routes_v6)
                r_set.append((routes_v4, port, action, ptf_ip))
                r_set.append((routes_v6, port6, action, ptf_ip))

                if 'vips' in vms_config[a_vm]:
                    routes_vips = []
                    for prefix in vms_config[a_vm]["vips"]["ipv4"]["prefixes"]:
                        routes_vips.append(
                            (prefix, nhipv4, vms_config[a_vm]["vips"]["ipv4"]["asn"]))
                    change_routes(action, ptf_ip, port, routes_vips)
    return r_set


def fib_t0_mclag(topo, ptf_ip, action="announce"):
    common_config = topo['configuration_properties'].get('common', {})
    podset_number = common_config.get("podset_number", PODSET_NUMBER)
    tor_number = common_config.get("tor_number", TOR_NUMBER)
    tor_subnet_number = common_config.get(
        "tor_subnet_number", TOR_SUBNET_NUMBER)
    max_tor_subnet_number = common_config.get(
        "max_tor_subnet_number", MAX_TOR_SUBNET_NUMBER)
    tor_subnet_size = common_config.get("tor_subnet_size", TOR_SUBNET_SIZE)
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    spine_asn = common_config.get("spine_asn", SPINE_ASN)
    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)
    vms = topo['topology']['VMs']
    all_vms = sorted(vms.keys())

    for vm_indx, vm in enumerate(all_vms):
        if len(all_vms) == 1:
            set_num = None
        elif vm_indx < 1:
            set_num = 0
        else:
            set_num = 1
        vm_offset = vms[vm]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        routes_v4 = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                    spine_asn, leaf_asn_start, tor_asn_start,
                                    nhipv4, nhipv4, tor_subnet_size, max_tor_subnet_number,
                                    "t0-mclag", set_num=set_num)
        routes_v6 = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                    spine_asn, leaf_asn_start, tor_asn_start,
                                    nhipv6, nhipv6, tor_subnet_size, max_tor_subnet_number,
                                    "t0-mclag", set_num=set_num)

        change_routes(action, ptf_ip, port, routes_v4)
        change_routes(action, ptf_ip, port6, routes_v6)


def fib_dpu(topo, ptf_ip, action="announce"):
    common_config = topo['configuration_properties'].get('common', {})
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)

    routes_v4 = []
    routes_v6 = []
    routes_v4.append(("0.0.0.0/0", nhipv4, None))
    routes_v6.append(("::/0", nhipv6, None))
    vms = topo['topology']['VMs']
    all_vms = sorted(vms.keys())

    for vm in all_vms:
        vm_offset = vms[vm]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        change_routes(action, ptf_ip, port, routes_v4)
        change_routes(action, ptf_ip, port6, routes_v6)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            topo_name=dict(required=True, type='str'),
            ptf_ip=dict(required=True, type='str'),
            action=dict(required=False, type='str',
                        default='announce', choices=["announce", "withdraw"]),
            path=dict(required=False, type='str', default=''),
            log_path=dict(required=False, type='str', default='')
        ),
        supports_check_mode=False)

    if module.params['log_path']:
        config_module_logging("announce_routes", log_path=module.params['log_path'])

    topo_name = module.params['topo_name']
    ptf_ip = module.params['ptf_ip']
    action = module.params['action']
    path = module.params['path']

    topo = read_topo(topo_name, path)
    if not topo:
        module.fail_json(msg='Unable to load topology "{}"'.format(topo_name))

    is_storage_backend = "backend" in topo_name

    topo_type = get_topo_type(topo_name)

    try:
        if topo_type == "t0":
            fib_t0(topo, ptf_ip, no_default_route=is_storage_backend, action=action)
            module.exit_json(changed=True)
        elif topo_type == "t1":
            fib_t1_lag(
                topo, ptf_ip, no_default_route=is_storage_backend, action=action)
            module.exit_json(changed=True)
        elif topo_type == "t2":
            fib_t2_lag(topo, ptf_ip, action=action)
            module.exit_json(changed=True)
        elif topo_type == "t0-mclag":
            fib_t0_mclag(topo, ptf_ip, action=action)
            module.exit_json(changed=True)
        elif topo_type == "m0":
            fib_m0(topo, ptf_ip, action=action)
            module.exit_json(changed=True)
        elif topo_type == "mx":
            fib_mx(topo, ptf_ip, action=action)
            module.exit_json(changed=True)
        elif topo_type == "dpu":
            fib_dpu(topo, ptf_ip, action=action)
            module.exit_json(change=True)
        else:
            module.exit_json(
                msg='Unsupported topology "{}" - skipping announcing routes'.format(topo_name))
    except Exception as e:
        module.fail_json(msg='Announcing routes failed, topo_name={}, topo_type={}, exception={}'
                         .format(topo_name, topo_type, repr(e)))


if __name__ == '__main__':
    main()
