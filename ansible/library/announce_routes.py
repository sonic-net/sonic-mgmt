#!/usr/bin/python

import itertools
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
from ansible.module_utils.multi_servers_utils import MultiServersUtils

if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode      # noqa: F821

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
DEFAULT_NEIGHBOR_GROUPS = 1
AGGREGATE_ROUTES_DEFAULT_VALUE = []
IPV6_ADDRESS_PATTERN_DEFAULT_VALUE = '20%02X:%02X%02X:0:%02X::/64'
ENABLE_IPV4_ROUTES_GENERATION_DEFAULT_VALUE = True
ENABLE_IPV6_ROUTES_GENERATION_DEFAULT_VALUE = True
GENERATE_WITHOUT_APPLY = 'generate'
IPV4 = 'ipv4'
IPV6 = 'ipv6'
BGP_SCALE_T1S = [
    't1-isolated-d254u2', 't1-isolated-d254u2s1', 't1-isolated-d254u2s2',
    't1-isolated-d510u2', 't1-isolated-d510u2s2'
]

# Describe default number of COLOs
COLO_NUMBER = 30
# Describe default number of M1 devices connected to MA device
M1_NUMBER = 4
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
# Describe default number of C0 devices connected to M1 device
C0_NUMBER = 20
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
# Describe default leaf number
LEAF_NUMBER = 256


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
        r'^(t0-mclag|t0|t1|ptf|fullmesh|dualtor|t2|mgmttor|m0|mc0|mx|m1|dpu|smartswitch-t1|lt2|ft2)')
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
    logging.debug("action = {}, ptf_ip = {}, port = {}, routes = {}".format(action, ptf_ip, port, routes))
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


# AS path from LT2 to UT2
def get_ut2_uplink_as_path():
    default_route_as_path = "6666 6667"
    return "{}".format(default_route_as_path)


# AS path from lower T2 to FT2
def get_ft2_uplink_as_path():
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
    elif uplink_router_type == "lowerspine":
        default_route_as_path = get_ft2_uplink_as_path()
    elif uplink_router_type == "upperspine":
        default_route_as_path = get_ut2_uplink_as_path()
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
                    no_default_route=False, core_ra_asn=CORE_RA_ASN,
                    ipv6_address_pattern=IPV6_ADDRESS_PATTERN_DEFAULT_VALUE,
                    tor_default_route=False, offset=0):
    routes = []
    if not no_default_route and (router_type != "tor" or tor_default_route):
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
    suffix = 0
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
                          (subnet * tor_subnet_size) + offset)
                octet2 = (168 + int(suffix / (256 ** 2)))
                octet1 = (192 + int(octet2 / 256))
                octet2 = (octet2 % 256)
                octet3 = (int(suffix / 256) % 256)
                octet4 = (suffix % 256)
                prefixlen_v4 = (32 - int(math.log(tor_subnet_size, 2)))

                prefix = "{}.{}.{}.{}/{}".format(octet1,
                                                 octet2, octet3, octet4, prefixlen_v4)
                prefix_v6 = ipv6_address_pattern % (
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

    return routes, suffix


def generate_t1_to_t0_routes(family, offset, leaf_number, subnet_size, tor_asn, leaf_asn_start, nexthop, nexthop_v6,
                             podset_num=1, ipv6_address_pattern=IPV6_ADDRESS_PATTERN_DEFAULT_VALUE):
    routes = []
    for podset in range(0, podset_num):
        for leaf in range(0, leaf_number):
            suffix = offset + leaf
            octet2 = (168 + int(suffix / (256 ** 2)))
            octet1 = (192 + int(octet2 / 256))
            octet2 = (octet2 % 256)
            octet3 = (int(suffix / 256) % 256)
            octet4 = (suffix % 256)
            prefixlen_v4 = (32 - int(math.log(subnet_size, 2)))
            prefix = "{}.{}.{}.{}/{}".format(octet1, octet2, octet3, octet4, prefixlen_v4)
            prefix_v6 = ipv6_address_pattern % (
                octet1, octet2, octet3, octet4)
            leaf_asn = leaf_asn_start + podset
            aspath = "{} {}".format(leaf_asn, tor_asn)
            if family in ["v4", "both"]:
                routes.append((prefix, nexthop, aspath))
            if family in ["v6", "both"]:
                routes.append((prefix_v6, nexthop_v6, aspath))
    return routes, suffix


def fib_t0(topo, ptf_ip, no_default_route=False, action="announce", upstream_neighbor_groups=0, routes={}):
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
    ipv6_address_pattern = common_config.get("ipv6_address_pattern", IPV6_ADDRESS_PATTERN_DEFAULT_VALUE)
    enable_ipv6_routes_generation = common_config.get("enable_ipv6_routes_generation",
                                                      ENABLE_IPV6_ROUTES_GENERATION_DEFAULT_VALUE)
    enable_ipv4_routes_generation = common_config.get("enable_ipv4_routes_generation",
                                                      ENABLE_IPV4_ROUTES_GENERATION_DEFAULT_VALUE)
    if upstream_neighbor_groups == 0:
        upstream_neighbor_groups = common_config.get("upstream_neighbor_groups", DEFAULT_NEIGHBOR_GROUPS)

    vms = topo['topology']['VMs']
    vms_len = len(vms)
    current_routes_offset = 0
    last_suffix = 0
    for index, vm_name in enumerate(sorted(vms.keys())):
        vm = vms[vm_name]
        router_type = "leaf"
        if 'tor' in topo['configuration'][vm_name]['properties']:
            router_type = 'tor'
        vm_offset = vm['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset
        aggregate_prefixes = topo['configuration'][vm_name].get("aggregate_routes", AGGREGATE_ROUTES_DEFAULT_VALUE)
        aggregate_routes = [(prefix, nhipv4 if "." in prefix else nhipv6, "") for prefix in aggregate_prefixes]
        aggregate_routes_v4 = get_ipv4_routes(aggregate_routes)
        aggregate_routes_v6 = get_ipv6_routes(aggregate_routes)
        routes[vm_name] = {}

        if enable_ipv4_routes_generation:
            routes_v4, last_suffix = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                                     spine_asn, leaf_asn_start, tor_asn_start,
                                                     nhipv4, nhipv4, tor_subnet_size, max_tor_subnet_number, "t0",
                                                     router_type=router_type,
                                                     no_default_route=no_default_route, offset=current_routes_offset)
            if aggregate_routes_v4:
                filterout_subnet_ipv4(aggregate_routes, routes_v4)
                routes_v4.extend(aggregate_routes_v4)
            routes[vm_name][IPV4] = routes_v4
            if action != GENERATE_WITHOUT_APPLY:
                change_routes(action, ptf_ip, port, routes_v4)
        if enable_ipv6_routes_generation:
            routes_v6, last_suffix = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                                     spine_asn, leaf_asn_start, tor_asn_start,
                                                     nhipv6, nhipv6, tor_subnet_size, max_tor_subnet_number, "t0",
                                                     router_type=router_type,
                                                     no_default_route=no_default_route,
                                                     ipv6_address_pattern=ipv6_address_pattern,
                                                     offset=current_routes_offset)
            if aggregate_routes_v6:
                filterout_subnet_ipv6(aggregate_routes, routes_v6)
                routes_v6.extend(aggregate_routes_v6)
            routes[vm_name][IPV6] = routes_v6
            if action != GENERATE_WITHOUT_APPLY:
                change_routes(action, ptf_ip, port6, routes_v6)
        group_index = index * upstream_neighbor_groups // vms_len
        next_group_index = (index + 1) * upstream_neighbor_groups // vms_len
        if group_index != next_group_index:
            current_routes_offset += last_suffix


def fib_t1_lag(topo, ptf_ip, topo_name, no_default_route=False, action="announce", tor_default_route=False,
               downstream_neighbor_groups=0, routes={}):
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
    ipv6_address_pattern = common_config.get("ipv6_address_pattern", IPV6_ADDRESS_PATTERN_DEFAULT_VALUE)
    enable_ipv6_routes_generation = common_config.get("enable_ipv6_routes_generation",
                                                      ENABLE_IPV6_ROUTES_GENERATION_DEFAULT_VALUE)
    enable_ipv4_routes_generation = common_config.get("enable_ipv4_routes_generation",
                                                      ENABLE_IPV4_ROUTES_GENERATION_DEFAULT_VALUE)

    vms = topo['topology']['VMs']
    vms_config = topo['configuration']

    dpus = None
    if 'DPUs' in topo['topology']:
        dpus = topo['topology']['DPUs']

    last_suffix = 0

    routes_to_change = {}
    if topo_name in BGP_SCALE_T1S:
        if downstream_neighbor_groups == 0:
            downstream_neighbor_groups = common_config.get("downstream_neighbor_groups", DEFAULT_NEIGHBOR_GROUPS)

        # Announce T1 loopback received in T0
        downstream_vm_config = {key: value for key, value in vms_config.items() if 'tor' in value['properties']}
        leaf_number = common_config.get("leaf_number", LEAF_NUMBER)
        downstream_tor_number = len(downstream_vm_config)
        lov6_address_pattern = ipv6_address_pattern.split("/")[0] + "/128"
        current_routes_offset = last_suffix
        routes[k] = {}
        for index, k in enumerate(sorted(downstream_vm_config.keys())):
            v = downstream_vm_config[k]
            if dpus and k in dpus:
                continue
            vm_offset = vms[k]['vm_offset']
            port = IPV4_BASE_PORT + vm_offset
            port6 = IPV6_BASE_PORT + vm_offset
            routes_to_change[port] = []
            routes_to_change[port6] = []
            aggregate_prefixes = v.get("aggregate_routes", AGGREGATE_ROUTES_DEFAULT_VALUE)
            aggregate_routes = [(prefix, nhipv4 if "." in prefix else nhipv6, "") for prefix in aggregate_prefixes]
            aggregate_routes_v4 = get_ipv4_routes(aggregate_routes)
            aggregate_routes_v6 = get_ipv6_routes(aggregate_routes)
            tor_asn = tor_asn_start + index
            if enable_ipv4_routes_generation:
                routes_v4, last_suffix = generate_t1_to_t0_routes("v4", current_routes_offset, leaf_number, 1, tor_asn,
                                                                  leaf_asn_start, nhipv4, nhipv6,
                                                                  ipv6_address_pattern=lov6_address_pattern)
                if aggregate_routes_v4:
                    filterout_subnet_ipv4(aggregate_routes, routes_v4)
                    routes_v4.extend(aggregate_routes_v4)
                routes[k][IPV4] = routes_v4
                routes_to_change[port] += routes_v4
            if enable_ipv6_routes_generation:
                routes_v6, last_suffix = generate_t1_to_t0_routes("v6", current_routes_offset, leaf_number, 1, tor_asn,
                                                                  leaf_asn_start, nhipv6, nhipv6,
                                                                  ipv6_address_pattern=lov6_address_pattern)
                if aggregate_routes_v6:
                    filterout_subnet_ipv6(aggregate_routes, routes_v6)
                    routes_v6.extend(aggregate_routes_v6)
                routes[k][IPV6] = routes_v6
                routes_to_change[port6] += routes_v6
            group_index = index * downstream_neighbor_groups // downstream_tor_number
            next_group_index = (index + 1) * downstream_neighbor_groups // downstream_tor_number
            if group_index != next_group_index:
                current_routes_offset += last_suffix
    if topo_name in BGP_SCALE_T1S:
        tor_default_route = True

    if last_suffix % 256 != 0:
        last_suffix += (256 - last_suffix % 256)

    for k in sorted(vms_config.keys()):
        v = vms_config[k]
        curr_no_default_route = no_default_route
        if topo_name in BGP_SCALE_T1S and 'spine' in v['properties']:
            curr_no_default_route = True
        if dpus and k in dpus:
            continue

        vm_offset = vms[k]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset
        # ports for T0 is already in routes_to_change, but ports for T1 is not, hence need setdefault
        routes_to_change.setdefault(port, [])
        routes_to_change.setdefault(port6, [])
        aggregate_prefixes = v.get("aggregate_routes", AGGREGATE_ROUTES_DEFAULT_VALUE)
        aggregate_routes = [(prefix, nhipv4 if "." in prefix else nhipv6, "") for prefix in aggregate_prefixes]
        aggregate_routes_v4 = get_ipv4_routes(aggregate_routes)
        aggregate_routes_v6 = get_ipv6_routes(aggregate_routes)
        if k not in routes:
            routes[k] = {}
        router_type = None
        if 'spine' in v['properties']:
            router_type = 'spine'
        elif 'tor' in v['properties']:
            router_type = 'tor'
        tornum = v.get('tornum', None)
        tor_index = tornum - 1 if tornum is not None else None
        if router_type:
            if enable_ipv4_routes_generation:
                routes_v4, _ = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                               None, leaf_asn_start, tor_asn_start,
                                               nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t1",
                                               router_type=router_type, tor_index=tor_index,
                                               no_default_route=curr_no_default_route,
                                               tor_default_route=tor_default_route, offset=last_suffix)
                if aggregate_routes_v4:
                    filterout_subnet_ipv4(aggregate_routes, routes_v4)
                    routes_v4.extend(aggregate_routes_v4)
                routes[k][IPV4] = routes_v4
                routes_to_change[port] += routes_v4
            if enable_ipv6_routes_generation:
                routes_v6, _ = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                               None, leaf_asn_start, tor_asn_start,
                                               nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t1",
                                               router_type=router_type, tor_index=tor_index,
                                               no_default_route=curr_no_default_route,
                                               ipv6_address_pattern=ipv6_address_pattern,
                                               tor_default_route=tor_default_route, offset=last_suffix)
                if aggregate_routes_v6:
                    filterout_subnet_ipv6(aggregate_routes, routes_v6)
                    routes_v6.extend(aggregate_routes_v6)
                routes[k][IPV6] = routes_v6
                routes_to_change[port6] += routes_v6

        if 'vips' in v:
            routes_vips = []
            for prefix in v["vips"]["ipv4"]["prefixes"]:
                routes_vips.append((prefix, nhipv4, v["vips"]["ipv4"]["asn"]))
            routes_to_change[port] += routes_vips

    if action != GENERATE_WITHOUT_APPLY:
        for port, routes in routes_to_change.items():
            if len(routes) <= 0:
                continue
            change_routes(action, ptf_ip, port, routes)


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


def fib_m0(topo, ptf_ip, action="announce", routes={}):
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

        routes[k] = {}
        routes[k][IPV4] = routes_v4
        routes[k][IPv6] = routes_v6
        if action != GENERATE_WITHOUT_APPLY:
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
        # For m0/m1 topo, need after path of M0
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
            # For m0/m1 topo, need M0 asn
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


def fib_mx(topo, ptf_ip, action="announce", routes={}):
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

        routes[k] = {}
        routes[k][IPV4] = routes_v4
        routes[k][IPv6] = routes_v6
        if action != GENERATE_WITHOUT_APPLY:
            change_routes(action, ptf_ip, port, routes_v4)
            change_routes(action, ptf_ip, port6, routes_v6)


"""
For M1, we have 4 sets of routes:
    - MA routes - advertised by the upstream MA VMs
    - MB routes - advertised by the upstream MB VMs
    - M0 routes - advertised by the downstream M0 VMs
    - C0 routes - advertised by the downstream C0 VMs

The total number of routes is controlled by parameters:
    - m1_number: number of M1 devices (including the DUT itself)
    - m0_number: number of M0 devices connected to each M1
    - m0_subnet_number: number of subnets on each M0
    - mx_number, mx_subnet_number, c0_number, and the number of MA/MB/M0/C0 devices from topology definition.

- MA routes:
    - Default route, prefix: 0.0.0.0/0
- MB routes:
    - Default route, prefix: 0.0.0.0/0
- Routes advertised by each M0:
    - Loopback IP of M0,   count: 1
    - Subnet routes of M0, count: m0_subnet_number
    - Loopback IP of Mx,   count: mx_number
    - Subnet routes of Mx, count: mx_number * mx_subnet_number
- Routes advertised by each C0:
    - Loopback IP of C0,   count: 1
"""


def generate_m1_ma_routes(nexthop, ip_base):
    """
    Generate subnet routes for MA devices in M1 topo
    """
    routes = [("0.0.0.0/0" if ip_base.version == 4 else "::/0", nexthop, None)]
    return routes


def generate_m1_mb_routes(nexthop, ip_base):
    routes = [("0.0.0.0/0" if ip_base.version == 4 else "::/0", nexthop, None)]
    return routes


def generate_m1_m0_routes(nexthop, ip_base, m0_subnet_number, m0_subnet_size, m0_asn,
                          mx_number, mx_subnet_number, mx_subnet_size, mx_lo_ip, mx_asn):
    """
    Generate subnet routes for M0 devices in M1 topo
    """
    routes = []

    # Generate M0 subnet routes
    m0_subnets, prefix = generate_m0_subnet_routes(m0_subnet_number, m0_subnet_size, ip_base, nexthop)
    routes += m0_subnets
    ip_base = get_next_ip_by_net(prefix)

    # Generate Mx subnet routes
    mx_subnets, prefix = generate_m0_mx_routes(mx_subnet_number, mx_subnet_size, mx_number, mx_asn, ip_base, nexthop)
    routes += mx_subnets
    ip_base = get_next_ip_by_net(prefix)

    # Generate Mx loopback routes
    for i in range(mx_number):
        routes.append((mx_lo_ip, nexthop, str(mx_asn)))
        mx_lo_ip = ipaddress.ip_network(get_next_ip_by_net(mx_lo_ip))

    return routes, ip_base, mx_lo_ip


def fib_m1(topo, ptf_ip, action="announce", routes={}):
    common_config = topo['configuration_properties'].get('common', {})
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    m0_subnet_number = common_config.get("m0_subnet_number", M0_SUBNET_NUMBER)
    m0_subnet_size = common_config.get("m0_subnet_size", M0_SUBNET_SIZE)
    m0_subnet_size_v6 = 2 ** (128 - common_config.get("m0_subnet_prefix_len_v6", M0_SUBNET_PREFIX_LEN_V6))
    m0_asn = common_config.get("m0_asn")
    mx_number = common_config.get("mx_number", MX_NUMBER)
    mx_subnet_number = common_config.get("mx_subnet_number", MX_SUBNET_NUMBER)
    mx_subnet_size = common_config.get("mx_subnet_size", MX_SUBNET_SIZE)
    mx_subnet_size_v6 = 2 ** (128 - common_config.get("mx_subnet_prefix_len_v6", MX_SUBNET_PREFIX_LEN_V6))
    mx_asn = common_config.get("mx_asn")
    mx_lo_v4_start = ipaddress.ip_network(UNICODE_TYPE(common_config.get("mx_loopback_v4_start")))
    mx_lo_v6_start = ipaddress.ip_network(UNICODE_TYPE(common_config.get("mx_loopback_v6_start")))

    vms = topo['topology']['VMs']
    vms_config = topo['configuration']

    ipv4_base = ipaddress.IPv4Address(UNICODE_TYPE("192.168.0.0"))
    ipv6_base = ipaddress.IPv6Address(UNICODE_TYPE("20c0:a800::0"))

    for k, v in vms_config.items():
        vm_offset = vms[k]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        router_type = None
        if "ma" in v["properties"]:
            router_type = "ma"
        if "mb" in v["properties"]:
            router_type = "mb"
        elif "m0" in v["properties"]:
            router_type = "m0"
        elif "c0" in v["properties"]:
            router_type = "c0"

        routes_v4, routes_v6 = [], []
        if router_type == "ma":
            routes_v4 = generate_m1_ma_routes(nhipv4, ipv4_base)
            routes_v6 = generate_m1_ma_routes(nhipv6, ipv6_base)
        elif router_type == "mb":
            routes_v4 = generate_m1_mb_routes(nhipv4, ipv4_base)
            routes_v6 = generate_m1_mb_routes(nhipv6, ipv6_base)
        elif router_type == "m0":
            routes_v4, ipv4_base, mx_lo_v4_start = \
                generate_m1_m0_routes(nhipv4, ipv4_base, m0_subnet_number, m0_subnet_size, m0_asn,
                                      mx_number, mx_subnet_number, mx_subnet_size, mx_lo_v4_start, mx_asn)
            routes_v6, ipv6_base, mx_lo_v6_start = \
                generate_m1_m0_routes(nhipv6, ipv6_base, m0_subnet_number, m0_subnet_size_v6, m0_asn,
                                      mx_number, mx_subnet_number, mx_subnet_size_v6, mx_lo_v6_start, mx_asn)
        elif router_type == "c0":
            # C0 announce nothing but it's loopback IP.
            pass

        routes[k] = {}
        routes[k][IPV4] = routes_v4
        routes[k][IPv6] = routes_v6
        if action != GENERATE_WITHOUT_APPLY:
            # routes_v4 = generate_m1_routes(nhipv4)
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


def fib_t2_lag(topo, ptf_ip, action="announce", routes={}):
    route_set = []
    vms = topo['topology']['VMs']
    # T1 VMs per linecard(asic) - key is the dut index, and value is a list of T1 VMs
    t1_vms = {}
    # T3 VMs per linecard(asic) - key is the dut index, and value is a list of T3 VMs
    t3_vms = {}
    for key, value in vms.items():
        if type(value['vlans'][0]) == int:
            dut_index = 0
        else:
            m = re.match(r"(\d+)\.(\d+)@(\d+)", value['vlans'][0])
            dut_index = int(m.group(1))
        if 'T1' in key or 'LT2' in key:
            if dut_index not in t1_vms:
                t1_vms[dut_index] = list()
            t1_vms[dut_index].append(key)

        if 'T3' in key:
            if dut_index not in t3_vms:
                t3_vms[dut_index] = list()
            t3_vms[dut_index].append(key)

    route_set += generate_t2_routes(t1_vms, topo, ptf_ip, action, routes={})
    route_set += generate_t2_routes(t3_vms, topo, ptf_ip, action, routes={})
    if action != GENERATE_WITHOUT_APPLY:
        send_routes_in_parallel(route_set)


def fib_ft2_routes(topo, ptf_ip, action="announce", routes={}):
    """
    Generate routes from LT2 to FT2 in the FT2 topology.
    """
    GROUP_SIZE = 4  # Number if LT2s per group
    PREFIX_LEN_V6 = 124  # Prefix length for IPv6
    PREFIX_LEN_V4 = 24  # Prefix length for IPv4
    ROUTE_NUMBER = 16384  # Number of routes to be generated for one single address family
    BASE_NETWORK_V4 = "192.0.0.0/8"
    BASE_NETWORK_V6 = "2001:db8::0:0/108"

    common_config = topo['configuration_properties'].get('common', {})
    nhipv4 = common_config.get("nhipv4", NHIPV4)
    nhipv6 = common_config.get("nhipv6", NHIPV6)
    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)

    default_route_as_path = get_uplink_router_as_path("lowerspine", None)

    vms = sorted(topo['topology']['VMs'])

    group_number = int(math.ceil(float(len(vms)) / GROUP_SIZE))
    routes_per_group = ROUTE_NUMBER // group_number  # Number of routes per group
    subnets_ipv4 = list(ipaddress.ip_network(UNICODE_TYPE(BASE_NETWORK_V4)).subnets(new_prefix=PREFIX_LEN_V4))
    subnets_ipv6 = list(ipaddress.ip_network(UNICODE_TYPE(BASE_NETWORK_V6)).subnets(new_prefix=PREFIX_LEN_V6))
    route_offset = 0
    # Generate routes for each group
    for group_index in range(group_number):
        group_subnets_ipv4 = subnets_ipv4[route_offset:route_offset + routes_per_group]
        group_subnets_ipv6 = subnets_ipv6[route_offset:route_offset + routes_per_group]
        route_offset += routes_per_group
        as_path = "{} {}".format(leaf_asn_start + group_index, tor_asn_start + group_index)
        # Get the index of the VM in the group
        for lt2_index in range(GROUP_SIZE):
            vm_index = group_index * GROUP_SIZE + lt2_index
            if vm_index >= len(vms):
                break
            vm_name = vms[vm_index]
            vm_offset = topo['topology']['VMs'][vm_name]['vm_offset']
            port = IPV4_BASE_PORT + vm_offset
            port6 = IPV6_BASE_PORT + vm_offset
            ipv4_routes = []
            for subnet in group_subnets_ipv4:
                # Generate IPv4 routes
                ipv4_routes.append((str(subnet), nhipv4, as_path))
            ipv6_routes = []
            for subnet in group_subnets_ipv6:
                # Generate IPv6 routes
                ipv6_routes.append((str(subnet), nhipv6, as_path))
            # Generate default routes for both IPv4 and IPv6
            ipv4_routes.append(("0.0.0.0/0", nhipv4, default_route_as_path))
            ipv6_routes.append(("::/0", nhipv6, default_route_as_path))
            routes[vm_name] = {}
            routes[vm_name][IPV4] = ipv4_routes
            routes[vm_name][IPv6] = ipv6_routes
            if action != GENERATE_WITHOUT_APPLY:
                # Send the routes to the PTF
                change_routes(action, ptf_ip, port, ipv4_routes)
                change_routes(action, ptf_ip, port6, ipv6_routes)


def generate_t2_routes(dut_vm_dict, topo, ptf_ip, action="announce", routes={}):
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
    ipv6_address_pattern = common_config.get("ipv6_address_pattern", IPV6_ADDRESS_PATTERN_DEFAULT_VALUE)
    enable_ipv6_routes_generation = common_config.get("enable_ipv6_routes_generation",
                                                      ENABLE_IPV6_ROUTES_GENERATION_DEFAULT_VALUE)
    enable_ipv4_routes_generation = common_config.get("enable_ipv4_routes_generation",
                                                      ENABLE_IPV4_ROUTES_GENERATION_DEFAULT_VALUE)

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
            aggregate_prefixes = vms_config[a_vm].get("aggregate_routes", AGGREGATE_ROUTES_DEFAULT_VALUE)
            aggregate_routes = [(prefix, nhipv4 if "." in prefix else nhipv6, "") for prefix in aggregate_prefixes]
            aggregate_routes_v4 = get_ipv4_routes(aggregate_routes)
            aggregate_routes_v6 = get_ipv6_routes(aggregate_routes)
            routes[a_vm] = {}

            router_type = None
            if 'leaf' in vms_config[a_vm]['properties']:
                router_type = 'leaf'
            elif 'core' in vms_config[a_vm]['properties']:
                router_type = 'core'

            tor_index = None

            if router_type:
                if enable_ipv4_routes_generation:
                    routes_v4, _ = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                                   common_config['dut_asn'], leaf_asn_start, tor_asn_start,
                                                   nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t2",
                                                   router_type=router_type, tor_index=tor_index, set_num=set_num,
                                                   core_ra_asn=core_ra_asn)
                    if aggregate_routes_v4:
                        filterout_subnet_ipv4(aggregate_routes, routes_v4)
                        routes_v4.extend(aggregate_routes_v4)
                    random.shuffle(routes_v4)
                    routes[a_vm][IPV4] = routes_v4
                    r_set.append((routes_v4, port, action, ptf_ip))
                if enable_ipv6_routes_generation:
                    routes_v6, _ = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                                   common_config['dut_asn'], leaf_asn_start, tor_asn_start,
                                                   nhipv4, nhipv6, tor_subnet_size, max_tor_subnet_number, "t2",
                                                   router_type=router_type, tor_index=tor_index, set_num=set_num,
                                                   core_ra_asn=core_ra_asn, ipv6_address_pattern=ipv6_address_pattern)
                    if aggregate_routes_v6:
                        filterout_subnet_ipv6(aggregate_routes, routes_v6)
                        routes_v6.extend(aggregate_routes_v6)
                    random.shuffle(routes_v6)
                    routes[a_vm][IPv6] = routes_v6
                    r_set.append((routes_v6, port6, action, ptf_ip))

                if 'vips' in vms_config[a_vm] and action != GENERATE_WITHOUT_APPLY:
                    routes_vips = []
                    for prefix in vms_config[a_vm]["vips"]["ipv4"]["prefixes"]:
                        routes_vips.append(
                            (prefix, nhipv4, vms_config[a_vm]["vips"]["ipv4"]["asn"]))
                    change_routes(action, ptf_ip, port, routes_vips)
    return r_set


def fib_t0_mclag(topo, ptf_ip, action="announce", routes={}):
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
    ipv6_address_pattern = common_config.get("ipv6_address_pattern", IPV6_ADDRESS_PATTERN_DEFAULT_VALUE)
    enable_ipv6_routes_generation = common_config.get("enable_ipv6_routes_generation",
                                                      ENABLE_IPV6_ROUTES_GENERATION_DEFAULT_VALUE)
    enable_ipv4_routes_generation = common_config.get("enable_ipv4_routes_generation",
                                                      ENABLE_IPV4_ROUTES_GENERATION_DEFAULT_VALUE)
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
        aggregate_prefixes = topo['configuration'][vm].get("aggregate_routes", AGGREGATE_ROUTES_DEFAULT_VALUE)
        aggregate_routes = [(prefix, nhipv4 if "." in prefix else nhipv6, "") for prefix in aggregate_prefixes]
        aggregate_routes_v4 = get_ipv4_routes(aggregate_routes)
        aggregate_routes_v6 = get_ipv6_routes(aggregate_routes)
        routes[vm] = {}

        if enable_ipv4_routes_generation:
            routes_v4, _ = generate_routes("v4", podset_number, tor_number, tor_subnet_number,
                                           spine_asn, leaf_asn_start, tor_asn_start,
                                           nhipv4, nhipv4, tor_subnet_size, max_tor_subnet_number,
                                           "t0-mclag", set_num=set_num)
            if aggregate_routes_v4:
                filterout_subnet_ipv4(aggregate_routes, routes_v4)
                routes_v4.extend(aggregate_routes_v4)
            routes[vm][IPV4] = routes_v4
            if action != GENERATE_WITHOUT_APPLY:
                change_routes(action, ptf_ip, port, routes_v4)
        if enable_ipv6_routes_generation:
            routes_v6, _ = generate_routes("v6", podset_number, tor_number, tor_subnet_number,
                                           spine_asn, leaf_asn_start, tor_asn_start,
                                           nhipv6, nhipv6, tor_subnet_size, max_tor_subnet_number,
                                           "t0-mclag", set_num=set_num,
                                           ipv6_address_pattern=ipv6_address_pattern)
            if aggregate_routes_v6:
                filterout_subnet_ipv6(aggregate_routes, routes_v6)
                routes_v6.extend(aggregate_routes_v6)
            routes[vm][IPv6] = routes_v6
            if action != GENERATE_WITHOUT_APPLY:
                change_routes(action, ptf_ip, port6, routes_v6)


def fib_lt2_routes(topo, ptf_ip, action="annouce", routes={}):
    T1_GROUP_SIZE = 2
    BASE_ADDR_V4 = "192.128.0.0/9"
    BASE_ADDR_V6 = "20c0:a800::0:0/108"
    ROUTE_NUMBER_T1 = 16000 * 2  # x2 for unique route

    common_config = topo['configuration_properties'].get('common', {})
    nhipv4 = common_config.get('nhipv4', NHIPV4)
    nhipv6 = common_config.get('nhipv6', NHIPV6)

    leaf_asn_start = common_config.get("leaf_asn_start", LEAF_ASN_START)
    tor_asn_start = common_config.get("tor_asn_start", TOR_ASN_START)

    vms = sorted(topo['topology']['VMs'])
    t1_vms = list(filter(lambda vm: "T1" in vm, vms))
    ut2_vms = list(filter(lambda vm: "UT2" in vm, vms))

    default_route_as_path = get_uplink_router_as_path("upperspine", None)

    all_subnetv4 = list(ipaddress.ip_network(UNICODE_TYPE(BASE_ADDR_V4)).subnets(new_prefix=24))
    all_subnetv6 = list(ipaddress.ip_network(UNICODE_TYPE(BASE_ADDR_V6)).subnets(new_prefix=124))

    group_nums = int(math.ceil(float(len(t1_vms)) / T1_GROUP_SIZE))
    t1_route_per_group = int(math.ceil(ROUTE_NUMBER_T1 / T1_GROUP_SIZE / group_nums))

    # 32 route each x 4 to match 110 T1
    extra_ipv4_t1 = itertools.chain(
        ipaddress.ip_network("192.168.0.0/27"),
        ipaddress.ip_network("192.169.0.0/27"),
        ipaddress.ip_network("192.170.0.0/27"),
        ipaddress.ip_network("192.171.0.0/27"),
    )

    for group in range(group_nums):
        selected_v4_subnets = all_subnetv4[group * t1_route_per_group: group * t1_route_per_group + t1_route_per_group]
        selected_v6_subnets = all_subnetv6[group * t1_route_per_group: group * t1_route_per_group + t1_route_per_group]

        as_path = "{} {}".format(leaf_asn_start + group, tor_asn_start + group)

        for vm_index in range(T1_GROUP_SIZE):
            if group * T1_GROUP_SIZE + vm_index >= len(t1_vms):
                break
            vm_name = t1_vms[group * T1_GROUP_SIZE + vm_index]
            vm_offset = topo['topology']['VMs'][vm_name]['vm_offset']

            ipv4_routes = []
            ipv6_routes = []

            for subnetv4, subnetv6 in zip(selected_v4_subnets, selected_v6_subnets):
                ipv4_routes.append((str(subnetv4), nhipv4, as_path))
                ipv6_routes.append((str(subnetv6), nhipv6, as_path))

            ipv4_routes.append((str(next(extra_ipv4_t1)), nhipv4, as_path))

            routes[vm_name] = {}
            routes[vm_name][IPV4] = ipv4_routes
            routes[vm_name][IPv6] = ipv6_routes
            if action != GENERATE_WITHOUT_APPLY:
                change_routes(action, ptf_ip, IPV4_BASE_PORT + vm_offset, ipv4_routes)
                change_routes(action, ptf_ip, IPV6_BASE_PORT + vm_offset, ipv6_routes)

    for device in range(len(ut2_vms)):
        ipv4_routes = [
            ("0.0.0.0/0", nhipv4, default_route_as_path),
        ]

        ipv6_routes = [
            ("::/0", nhipv6, default_route_as_path),
        ]

        group += 1
        as_path = "{} {}".format(leaf_asn_start + group, tor_asn_start + group)

        vm_name = ut2_vms[device]
        vm_offset = topo['topology']['VMs'][vm_name]['vm_offset']

        ipv4_routes.append((topo['configuration'][vm_name]['interfaces']['Loopback0']['ipv4'], nhipv4, as_path))
        ipv6_routes.append((topo['configuration'][vm_name]['interfaces']['Loopback0']['ipv6'], nhipv6, as_path))

        if vm_name not in routes:
            routes[vm_name] = {}
        routes[vm_name][IPV4] = ipv4_routes
        routes[vm_name][IPv6] = ipv6_routes
        if action != GENERATE_WITHOUT_APPLY:
            change_routes(action, ptf_ip, IPV4_BASE_PORT + vm_offset, ipv4_routes)
            change_routes(action, ptf_ip, IPV6_BASE_PORT + vm_offset, ipv6_routes)


def fib_dpu(topo, ptf_ip, action="announce", routes={}):
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

        routes[vm] = {}
        routes[vm][IPV4] = routes_v4
        routes[vm][IPv6] = routes_v6
        if action != GENERATE_WITHOUT_APPLY:
            change_routes(action, ptf_ip, port, routes_v4)
            change_routes(action, ptf_ip, port6, routes_v6)


def adhoc_routes(topo, ptf_ip, peers_routes_to_change, action):
    vms = topo['topology']['VMs']

    for hostname, routes in peers_routes_to_change.items():
        if hostname not in vms:
            continue
        vm_offset = vms[hostname]['vm_offset']
        port = IPV4_BASE_PORT + vm_offset
        port6 = IPV6_BASE_PORT + vm_offset

        routes[hostname] = {}
        routes[hostname][IPV4] = ipv4_routes
        routes[hostname][IPv6] = ipv6_routes
        ipv4_routes = [r for r in routes if '.' in r[0]]
        if ipv4_routes and action != GENERATE_WITHOUT_APPLY:
            change_routes(action, ptf_ip, port, ipv4_routes)

        ipv6_routes = [r for r in routes if ':' in r[0]]
        if ipv6_routes and action != GENERATE_WITHOUT_APPLY:
            change_routes(action, ptf_ip, port6, ipv6_routes)


def get_ipv4_routes(routes):
    return [r for r in routes if ipaddress.ip_network(UNICODE_TYPE(r[0])).version == 4]


def get_ipv6_routes(routes):
    return [r for r in routes if ipaddress.ip_network(UNICODE_TYPE(r[0])).version == 6]


def filterout_subnet_ipv4(aggregate_routes, candidate_routes):
    ars_ipv4 = get_ipv4_routes(aggregate_routes)
    return filterout_subnet(ars_ipv4, candidate_routes)


def filterout_subnet_ipv6(aggregate_routes, candidate_routes):
    ars_ipv6 = get_ipv6_routes(aggregate_routes)
    return filterout_subnet(ars_ipv6, candidate_routes)


def filterout_subnet(aggregate_routes, candidate_routes):
    subnets = []
    for ar in aggregate_routes:
        ar_net = ipaddress.ip_network(UNICODE_TYPE(ar[0]))
        for cr in candidate_routes:
            if ipaddress.ip_network(UNICODE_TYPE(cr[0])).subnet_of(ar_net):
                subnets.append(cr)
    return list(set(candidate_routes) - set(subnets))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            topo_name=dict(required=True, type='str'),
            ptf_ip=dict(required=True, type='str'),
            action=dict(required=False, type='str',
                        default='announce', choices=["announce", "withdraw", GENERATE_WITHOUT_APPLY]),
            path=dict(required=False, type='str', default=''),
            dut_interfaces=dict(required=False, type='str', default=''),
            adhoc=dict(required=False, type='bool', default=False),
            peers_routes_to_change=dict(required=False, type='dict', default={}),
            log_path=dict(required=False, type='str', default='/tmp'),
            upstream_neighbor_groups=dict(required=False, type='int', default=0),
            downstream_neighbor_groups=dict(required=False, type='int', default=0)
        ),
        supports_check_mode=False)

    if module.params['log_path']:
        config_module_logging("announce_routes", log_path=module.params['log_path'])

    topo_name = module.params['topo_name']
    ptf_ip = module.params['ptf_ip']
    action = module.params['action']
    dut_interfaces = module.params['dut_interfaces']
    path = module.params['path']
    adhoc = module.params['adhoc']
    peers_routes_to_change = module.params['peers_routes_to_change']
    upstream_neighbor_groups = module.params['upstream_neighbor_groups']
    downstream_neighbor_groups = module.params['downstream_neighbor_groups']

    topo = read_topo(topo_name, path)
    if not topo:
        module.fail_json(msg='Unable to load topology "{}"'.format(topo_name))
    if dut_interfaces:
        topo['topology']['VMs'] = MultiServersUtils.get_vms_by_dut_interfaces(topo['topology']['VMs'], dut_interfaces)
        for vm_name in list(topo['configuration'].keys()):
            if vm_name not in topo['topology']['VMs']:
                topo['configuration'].pop(vm_name)

    is_storage_backend = "backend" in topo_name
    tor_default_route = topo_name in ["t1-isolated-d128", "t1-isolated-d32"]

    topo_type = get_topo_type(topo_name)
    routes = {}
    try:
        if adhoc:
            adhoc_routes(topo, ptf_ip, peers_routes_to_change, action)
            module.exit_json(change=True)
        elif topo_type == "t0":
            fib_t0(topo, ptf_ip, no_default_route=is_storage_backend, action=action,
                   upstream_neighbor_groups=upstream_neighbor_groups, routes=routes)
            module.exit_json(changed=True, routes=routes)
        elif topo_type == "t1" or topo_type == "smartswitch-t1":
            fib_t1_lag(
                topo, ptf_ip, topo_name, no_default_route=is_storage_backend, action=action,
                tor_default_route=tor_default_route, downstream_neighbor_groups=downstream_neighbor_groups,
                routes=routes)
            module.exit_json(changed=True, routes=routes)
        elif topo_type == "t2":
            fib_t2_lag(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(changed=True, routes=routes)
        elif topo_type == "t0-mclag":
            fib_t0_mclag(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(changed=True, routes=routes)
        elif topo_type == "m1":
            fib_m1(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(changed=True, routes=routes)
        elif topo_type == "m0":
            fib_m0(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(changed=True, routes=routes)
        elif topo_type == "mx":
            fib_mx(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(changed=True, routes=routes)
        elif topo_type == "dpu":
            fib_dpu(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(change=True, routes=routes)
        elif topo_type == "lt2":
            fib_lt2_routes(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(change=True, routes=routes)
        elif topo_type == "ft2":
            fib_ft2_routes(topo, ptf_ip, action=action, routes=routes)
            module.exit_json(change=True, routes=routes)
        else:
            module.exit_json(
                msg='Unsupported topology "{}" - skipping announcing routes'.format(topo_name))
    except Exception as e:
        module.fail_json(msg='Announcing routes failed, topo_name={}, topo_type={}, exception={}'
                         .format(topo_name, topo_type, repr(e)))


if __name__ == '__main__':
    main()
