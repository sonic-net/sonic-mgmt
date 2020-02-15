import sys
import time
import math
import requests
import pytest
import ipaddr as ipaddress

def announce_routes(ptfip, port, family, podset_number, tor_number, tor_subnet_number, 
                    spine_asn, leaf_asn_start, tor_asn_start, 
                    nexthop, nexthop_v6,
                    tor_subnet_size = 128, max_tor_subnet_number = 16):
    messages = []

    # default route
    if family in ["v4", "both"]:
        messages.append("announce route 0.0.0.0/0 next-hop {} as-path [ {} ]".format(nexthop, spine_asn))
    if family in ["v6", "both"]:
        messages.append("announce route ::/0 next-hop {} as-path [ {} ]".format(nexthop_v6, spine_asn))

    # NOTE: Using large enough values (e.g., podset_number = 200,
    # us to overflow the 192.168.0.0/16 private address space here.
    # This should be fine for internal use, but may pose an issue if used otherwise
    for podset in range(0, podset_number):
        for tor in range(0, tor_number):
            for subnet in range(0, tor_subnet_number):
                # Skip tor 0 podset 0
                if podset == 0 and tor == 0:
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
                if podset == 0:
                    aspath = "{}".format(tor_asn)
                else:
                    aspath = "{} {} {}".format(spine_asn, leaf_asn, tor_asn)

                if family in ["v4", "both"]:
                    messages.append("announce route {} next-hop {} as-path [ {} ]".format(prefix, nexthop, aspath))
                if family in ["v6", "both"]:
                    messages.append("announce route {} next-hop {} as-path [ {} ]".format(prefix_v6, nexthop_v6, aspath))

    url = "http://%s:%d" % (ptfip, port)
    data = { "commands": ";".join(messages) }
    r = requests.post(url, data=data)
    print r
    assert r.status_code == 200

@pytest.fixture(scope='module')
def fib_t0(ptfhost, testbed):

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
