import json
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP

pytestmark = [
    pytest.mark.topology('m1', 'uma'),
]

# Suffix of the backup upstream path. MB is the CoreTs / out-of-band peer across
# the M series, and is also what minigraph_png.j2 keys on to set device_type
# CoreTs, which in turn selects the *.oob bgp templates and peer-group MB_PATH_*.
MB_SUFFIX = 'MB'


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


def get_neighbors_by_suffix(neighs, ip_version, suffix):
    """Neighbors whose description ends with the given role suffix.

    Match on the suffix rather than a substring. The roles overlap as
    substrings - "LMA" contains "ma" - so a substring match picks up the wrong
    neighbors. On a UMA testbed 'ma' in description matches the four downstream
    VM0xLMA neighbors instead of the RWA upstream.
    """
    suffix = suffix.upper()
    return [k for k, v in neighs.items()
            if v['ip_version'] == ip_version and v['description'].upper().endswith(suffix)]


@pytest.mark.parametrize("ip_version", [4, 6])
def test_bgp_aspath_prepend(duthost, tbinfo, ip_version):
    """
    According to M1/M2/M3/MA BGP policy design, traffic to upstream never go to MB unless all the MA paths are down.
    This test is to verify the BGP AS path prepend policy works as expected.
    """
    # The primary upstream role differs per topology: MA on m1, RWA on uma.
    topo_type = tbinfo['topo']['type']
    upstream_suffix = UPSTREAM_NEIGHBOR_MAP.get(topo_type)
    if upstream_suffix is None:
        pytest.skip("No upstream neighbor type defined for topology '{}'".format(topo_type))

    neighs = duthost.get_bgp_neighbors()
    ma_neighs = get_neighbors_by_suffix(neighs, ip_version, upstream_suffix)
    mb_neighs = get_neighbors_by_suffix(neighs, ip_version, MB_SUFFIX)

    if not mb_neighs:
        pytest.skip("Topology '{}' has no {} (out-of-band) neighbor, there is no backup path to fail over to"
                    .format(topo_type, MB_SUFFIX))
    pytest_assert(ma_neighs, "No {} upstream neighbors found for topology '{}'"
                             .format(upstream_suffix.upper(), topo_type))
    mb_neigh = mb_neighs[0]

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
