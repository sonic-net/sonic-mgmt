import json
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('m1'),
]


def get_default_route_nexthop(duthost, ip_version):
    if ip_version == 4:
        cmd = "vtysh -c 'show ip route 0.0.0.0/0 json'"
    elif ip_version == 6:
        cmd = "vtysh -c 'show ipv6 route ::/0 json'"
    output = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, "Failed to read default route")
    route_info = json.loads(output['stdout'])
    prefix = '0.0.0.0/0' if ip_version == 4 else '::/0'
    return [v['ip'] for v in route_info[prefix][0]['nexthops']]


@pytest.mark.parametrize("ip_version", [4, 6])
def test_bgp_aspath_prepend(duthost, ip_version):
    """
    According to M1/M2/M3/MA BGP policy design, traffic to upstream never go to MB unless all the MA paths are down.
    This test is to verify the BGP AS path prepend policy works as expected.
    """
    neighs = duthost.get_bgp_neighbors()
    ma_neighs = [k for k, v in neighs.items() if v['ip_version'] == ip_version and 'ma' in v['description'].lower()]
    mb_neigh = [k for k, v in neighs.items() if v['ip_version'] == ip_version and 'mb' in v['description'].lower()][0]

    try:
        # Verify MB does NOT appear in default route nexthop before all MA paths are down
        for ma_ip in ma_neighs:
            nexthops = get_default_route_nexthop(duthost, ip_version)
            pytest_assert(mb_neigh not in nexthops, "MB appears in default route nexthop before all MA paths are down")
            output = duthost.shell(f"sudo config bgp shut neigh {ma_ip}", module_ignore_errors=True)
            pytest_assert(output['rc'] == 0, f"Failed to shutdown MA neighbor {ma_ip}")
        # Now all the MA paths has been shutdown, verify MB appears in default route nexthop
        nexthops = get_default_route_nexthop(duthost, ip_version)
        pytest_assert(mb_neigh in nexthops, "MB does NOT appear in default route nexthop after all MA paths are down")
    finally:
        # Restore MA BGP sessions
        for ma_ip in ma_neighs:
            output = duthost.shell(f"sudo config bgp startup neigh {ma_ip}", module_ignore_errors=True)
            pytest_assert(output['rc'] == 0, f"Failed to startup MA neighbor {ma_ip}")
