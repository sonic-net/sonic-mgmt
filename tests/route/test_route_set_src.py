from netaddr import IPAddress, IPNetwork
import re
import pytest
import logging

logger = logging.getLogger(__name__)

def test_default_route_set_src(duthost):
    """check if ipv4 and ipv6 default src address match Loopback0 address

admin@vlab-01:~$ ip route list match 0.0.0.0
default proto bgp src 10.1.0.32 metric 20
        nexthop via 10.0.0.57 dev PortChannel0001 weight 1
        nexthop via 10.0.0.59 dev PortChannel0002 weight 1
        nexthop via 10.0.0.61 dev PortChannel0003 weight 1
        nexthop via 10.0.0.63 dev PortChannel0004 weight 1

admin@vlab-01:~$ ip -6 route list match ::
default proto bgp src fc00:1::32 metric 20
        nexthop via fe80::831:6cff:fea5:d8eb dev PortChannel0004 weight 1
        nexthop via fe80::10b5:4aff:fef2:6e37 dev PortChannel0002 weight 1
        nexthop via fe80::1419:9ff:fe52:2db dev PortChannel0003 weight 1
        nexthop via fe80::5cb4:7bff:fec8:148b dev PortChannel0001 weight 1 pref medium
    """

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    lo_ipv4 = None
    lo_ipv6 = None
    los = config_facts.get("LOOPBACK_INTERFACE", {})
    logger.info("Loopback IPs: {}".format(los))
    for k, v in los.items():
        if k == "Loopback0":
            for ipstr in v.keys():
                ip = IPNetwork(ipstr)
                if ip.version == 4:
                    lo_ipv4 = ip
                elif ip.version == 6:
                    lo_ipv6 = ip

    if lo_ipv4 is None:
        pytest.fail("cannot find ipv4 Loopback0 address")
    if lo_ipv6 is None:
        pytest.fail("cannot find ipv6 Loopback0 address")

    rt = duthost.command("ip route list match 0.0.0.0")['stdout_lines']
    m = re.match(r"^default proto bgp src (\S+)", rt[0])
    if m:
        if IPAddress(m.group(1)) != lo_ipv4.ip:
            pytest.fail("default route set src to wrong IP {} != {}".format(m.group(1), lo_ipv4.ip))
    else:
        pytest.fail("default route do not have set src. {}".format(rt))

    rt = duthost.command("ip -6 route list match ::")['stdout_lines']
    m = re.match(r"^default proto bgp src (\S+)", rt[0])
    if m:
        if IPAddress(m.group(1)) != lo_ipv6.ip:
            pytest.fail("default route set src to wrong IP {} != {}".format(m.group(1), lo_ipv6.ip))
    else:
        pytest.fail("default route do not have set src. {}".format(rt))
