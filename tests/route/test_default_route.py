import pytest
import ipaddress
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

def test_default_route_set_src(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index):
    """
    check if ipv4 and ipv6 default src address match Loopback0 address

    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_asic_index)

    config_facts = asichost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

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

    pytest_assert(lo_ipv4, "cannot find ipv4 Loopback0 address")
    pytest_assert(lo_ipv6, "cannot find ipv6 Loopback0 address")

    rtinfo = asichost.get_ip_route_info(ipaddress.ip_network(u"0.0.0.0/0"))
    pytest_assert(rtinfo['set_src'], "default route do not have set src. {}".format(rtinfo))
    pytest_assert(rtinfo['set_src'] == lo_ipv4.ip, \
            "default route set src to wrong IP {} != {}".format(rtinfo['set_src'], lo_ipv4.ip))

    rtinfo = asichost.get_ip_route_info(ipaddress.ip_network(u"::/0"))
    pytest_assert(rtinfo['set_src'], "default v6 route do not have set src. {}".format(rtinfo))
    pytest_assert(rtinfo['set_src'] == lo_ipv6.ip, \
            "default v6 route set src to wrong IP {} != {}".format(rtinfo['set_src'], lo_ipv6.ip))

def test_default_ipv6_route_next_hop_global_address(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index):
    """
    check if ipv6 default route nexthop address uses global address

    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_asic_index)

    rtinfo = asichost.get_ip_route_info(ipaddress.ip_network(u"::/0"))
    pytest_assert(len(rtinfo['nexthops']) > 0, "cannot find ipv6 nexthop for default route")
    for nh in rtinfo['nexthops']:
        pytest_assert(not nh[0].is_link_local, \
                "use link local address {} for nexthop".format(nh[0]))
