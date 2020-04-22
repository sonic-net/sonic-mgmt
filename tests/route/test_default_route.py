import ipaddress
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
        nexthop via fc00::72 dev PortChannel0001 weight 1
        nexthop via fc00::76 dev PortChannel0002 weight 1
        nexthop via fc00::7a dev PortChannel0003 weight 1
        nexthop via fc00::7e dev PortChannel0004 weight 1 pref medium
    """

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    lo_ipv4 = None
    lo_ipv6 = None
    los = config_facts.get("LOOPBACK_INTERFACE", {})
    logger.info("Loopback IPs: {}".format(los))
    for k, v in los.items():
        if k == "Loopback0":
            for ipstr in v.keys():
                ip = ipaddress.ip_interface(ipstr)
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
        if ipaddress.ip_address(m.group(1)) != lo_ipv4.ip:
            pytest.fail("default route set src to wrong IP {} != {}".format(m.group(1), lo_ipv4.ip))
    else:
        pytest.fail("default route do not have set src. {}".format(rt))

    rt = duthost.command("ip -6 route list match ::")['stdout_lines']
    m = re.match(r"^default proto bgp src (\S+)", rt[0])
    if m:
        if ipaddress.ip_address(m.group(1)) != lo_ipv6.ip:
            pytest.fail("default route set src to wrong IP {} != {}".format(m.group(1), lo_ipv6.ip))
    else:
        pytest.fail("default route do not have set src. {}".format(rt))

def test_default_ipv6_route_next_hop_global_address(duthost):
    """check if ipv6 default route nexthop address uses global address

admin@vlab-01:~$ ip -6 route list match ::
default proto bgp src fc00:1::32 metric 20
        nexthop via fc00::72 dev PortChannel0001 weight 1
        nexthop via fc00::76 dev PortChannel0002 weight 1
        nexthop via fc00::7a dev PortChannel0003 weight 1
        nexthop via fc00::7e dev PortChannel0004 weight 1 pref medium
    """

    rt = duthost.command("ip -6 route list match ::")['stdout_lines']
    logger.info("default ipv6 route {}".format(rt))
    for l in rt[1:]:
        m = re.search(r"nexthop via (\S+)", l)
        if m:
            if ipaddress.ip_address(m.group(1)).is_link_local:
                pytest.fail("use link local address {} for nexthop".format(m.group(1)))
        else:
            pytest.fail("cannot find ipv6 nexthop for default route {}".format(rt))
