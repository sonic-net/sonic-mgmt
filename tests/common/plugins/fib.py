import sys
import time
import math
import requests
import pytest
import logging
import ipaddr as ipaddress
logger = logging.getLogger(__name__)

def announce_routes(ptfip, port, family, podset_number, tor_number, tor_subnet_number,
                    spine_asn, leaf_asn_start, tor_asn_start,
                    nexthop, nexthop_v6,
                    tor_subnet_size = 128, max_tor_subnet_number = 16,
                    router_type = "leaf"):
    messages = []

    default_route_as_path = "6666 6667"

    if router_type == "leaf":
        default_route_as_path = "{} {}".format(spine_asn, default_route_as_path)

    if router_type != 'tor':
        if family in ["v4", "both"]:
            messages.append("announce route 0.0.0.0/0 next-hop {} as-path [ {} ]".format(nexthop, default_route_as_path))
        if family in ["v6", "both"]:
            messages.append("announce route ::/0 next-hop {} as-path [ {} ]".format(nexthop_v6, default_route_as_path))

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

                if aspath:
                    if family in ["v4", "both"]:
                        messages.append("announce route {} next-hop {} as-path [ {} ]".format(prefix, nexthop, aspath))
                    if family in ["v6", "both"]:
                        messages.append("announce route {} next-hop {} as-path [ {} ]".format(prefix_v6, nexthop_v6, aspath))
                else:
                    if family in ["v4", "both"]:
                        messages.append("announce route {} next-hop {}".format(prefix, nexthop))
                    if family in ["v6", "both"]:
                        messages.append("announce route {} next-hop {}".format(prefix_v6, nexthop_v6))


    url = "http://%s:%d" % (ptfip, port)
    data = { "commands": ";".join(messages) }
    r = requests.post(url, data=data)
    print r
    assert r.status_code == 200

def fib_t0(ptfhost, testbed):
    logger.info("use fib_t0 to setup routes for topo {}".format(testbed['topo']['name']))

    podset_number = 200
    tor_number = 16
    tor_subnet_number = 2
    max_tor_subnet_number = 16
    tor_subnet_size = 128

    spine_asn       = 65534
    leaf_asn_start  = 64600
    tor_asn_start   = 65500

    topo = testbed['topo']['properties']
    ptf_hostname = testbed['ptf']
    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptf_hostname).vars['ansible_host']

    local_ip = ipaddress.IPAddress("10.10.246.254")
    local_ipv6 = ipaddress.IPAddress("fc0a::ff")
    for k, v in testbed['topo']['properties']['configuration'].items():
        vm_offset = testbed['topo']['properties']['topology']['VMs'][k]['vm_offset']
        peer_ip = ipaddress.IPNetwork(v['bp_interface']['ipv4'])
        peer_ipv6 = ipaddress.IPNetwork(v['bp_interface']['ipv6'])
        asn = int(v['bgp']['asn'])
        port = 5000 + vm_offset
        port6 = 6000 + vm_offset

        ptfhost.exabgp(name=k,
                       state="started", \
                       router_id = str(local_ip), \
                       local_ip  = str(local_ip), \
                       peer_ip   = str(peer_ip.ip), \
                       local_asn = asn, \
                       peer_asn  = asn, \
                       port = port)

        ptfhost.exabgp(name="%s-v6" % k,
                       state="started", \
                       router_id = str(local_ip), \
                       local_ip  = str(local_ipv6), \
                       peer_ip   = str(peer_ipv6.ip), \
                       local_asn = asn, \
                       peer_asn  = asn, \
                       port = port6)

    for k, v in testbed['topo']['properties']['configuration'].items():
        vm_offset = testbed['topo']['properties']['topology']['VMs'][k]['vm_offset']
        port = 5000 + vm_offset
        port6 = 6000 + vm_offset

        announce_routes(ptfip, port, "v4", podset_number, tor_number, tor_subnet_number,
                        spine_asn, leaf_asn_start, tor_asn_start,
                        local_ip, local_ipv6)

        announce_routes(ptfip, port6, "v6", podset_number, tor_number, tor_subnet_number,
                        spine_asn, leaf_asn_start, tor_asn_start,
                        local_ip, local_ipv6)

def fib_t1_lag(ptfhost, testbed):
    logger.info("use fib_t1_lag to setup routes for topo {}".format(testbed['topo']['name']))

    podset_number = 200
    tor_number = 16
    tor_subnet_number = 2
    max_tor_subnet_number = 16
    tor_subnet_size = 128

    leaf_asn_start  = 64600
    tor_asn_start   = 65500

    topo = testbed['topo']['properties']
    ptf_hostname = testbed['ptf']
    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptf_hostname).vars['ansible_host']

    local_ip = ipaddress.IPAddress("10.10.246.254")
    local_ipv6 = ipaddress.IPAddress("fc0a::ff")

    for k, v in testbed['topo']['properties']['configuration'].items():
        vm_offset = testbed['topo']['properties']['topology']['VMs'][k]['vm_offset']
        peer_ip = ipaddress.IPNetwork(v['bp_interface']['ipv4'])
        peer_ipv6 = ipaddress.IPNetwork(v['bp_interface']['ipv6'])
        asn = int(v['bgp']['asn'])
        port = 5000 + vm_offset
        port6 = 6000 + vm_offset

        ptfhost.exabgp(name=k,
                       state="started", \
                       router_id = str(local_ip), \
                       local_ip  = str(local_ip), \
                       peer_ip   = str(peer_ip.ip), \
                       local_asn = asn, \
                       peer_asn  = asn, \
                       port = port)

        ptfhost.exabgp(name="%s-v6" % k,
                       state="started", \
                       router_id = str(local_ip), \
                       local_ip  = str(local_ipv6), \
                       peer_ip   = str(peer_ipv6.ip), \
                       local_asn = asn, \
                       peer_asn  = asn, \
                       port = port6)

    for k, v in testbed['topo']['properties']['configuration'].items():

        vm_offset = testbed['topo']['properties']['topology']['VMs'][k]['vm_offset']
        port = 5000 + vm_offset
        port6 = 6000 + vm_offset

        if 'spine' in v['properties']:
            announce_routes(ptfip, port, "v4", podset_number, tor_number, tor_subnet_number,
                            None, leaf_asn_start, tor_asn_start,
                            local_ip, local_ipv6, router_type="spine")

            announce_routes(ptfip, port6, "v6", podset_number, tor_number, tor_subnet_number,
                            None, leaf_asn_start, tor_asn_start,
                            local_ip, local_ipv6, router_type="spine")

        elif 'tor' in v['properties']:
            announce_routes(ptfip, port, "v4", podset_number, tor_number, tor_subnet_number,
                            None, leaf_asn_start, tor_asn_start,
                            local_ip, local_ipv6, router_type="tor")

@pytest.fixture(scope='module')
def fib(ptfhost, testbed):
    logger.info("setup fib to topo {}".format(testbed['topo']['name']))
    if testbed['topo']['name'] == "t0":
        fib_t0(ptfhost, testbed)
    elif testbed['topo']['name'] == "t1-lag":
        fib_t1_lag(ptfhost, testbed)
    else:
        logger.error("unknonw topology {}".format(testbed['topo']['name']))
