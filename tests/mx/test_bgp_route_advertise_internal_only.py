import ipaddress
import json
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('mx'),
]


def get_loopback_addr_v6(duthost):
    ipv6_intfs = duthost.show_ipv6_interfaces()
    pytest_assert('Loopback0' in ipv6_intfs, "Loopback0 interface doesn't have IPv6 address configured")
    return ipv6_intfs['Loopback0']['ipv6 address/mask']


def add_vlan(duthost, vlan_id):
    output = duthost.shell(f"sudo config vlan add {vlan_id}", module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, f"Failed to add vlan {vlan_id}")


def generate_vlan_prefix_v6(lo_addr_v6):
    """
    Generate a /96 IPv6 prefix which is in same /64 subnet as lo_addr_v6
    """
    lo_addr_v6 = ipaddress.IPv6Interface(lo_addr_v6)
    lo_net_v6 = lo_addr_v6.network.supernet(new_prefix=64)
    for i in range(0, 1 << 32):
        pfx = ipaddress.IPv6Network((int(lo_net_v6.network_address) + (i << 32), 96))
        if lo_addr_v6 not in pfx:
            return str(pfx)


def verify_bgp_session_established(duthost):
    bgp_facts = duthost.get_bgp_neighbors()
    for neigh_ip in bgp_facts:
        if bgp_facts[neigh_ip]['state'] != 'established':
            return False
    return True


@pytest.fixture
def setup_teardown(duthost):
    # Setup new VLAN for testing
    lo_addr_v6 = ipaddress.IPv6Interface(get_loopback_addr_v6(duthost))
    lo_prefix_64 = str(ipaddress.IPv6Network((lo_addr_v6.ip, 64), strict=False).network_address) + "/64"
    vlan_id = 4001
    vlan_prefix_v6 = generate_vlan_prefix_v6(lo_addr_v6)
    add_vlan(duthost, vlan_id)
    duthost.add_ip_addr_to_vlan(f"Vlan{vlan_id}", vlan_prefix_v6)
    # Restart BGP service to update FRR config
    output = duthost.shell("sudo systemctl restart bgp", module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, "Failed to restart bgp service")
    pytest_assert(wait_until(180, 10, 20, verify_bgp_session_established, duthost),
                  "Not all BGP sessions are established")

    yield lo_prefix_64, vlan_prefix_v6

    # Remove the VLAN for testing
    duthost.remove_ip_addr_from_vlan(f"Vlan{vlan_id}", vlan_prefix_v6)
    duthost.remove_vlan(vlan_id)
    # Restart BGP service to restore FRR config
    output = duthost.shell("sudo systemctl restart bgp", module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, "Failed to restart bgp service")
    pytest_assert(wait_until(180, 10, 20, verify_bgp_session_established, duthost),
                  "Not all BGP sessions are established")


def test_vlan_prefix_advertise_v6(duthost, setup_teardown):
    """
    In the 4 VLAN production scenario, each VLAN has a /96 IPv6 prefix. These /96 prefixes are in the same subnet as
    IPv6 Loopback address.
    This testcase is to verify Mx never advertises these /96 prefixes to upstream M0. (Otherwise it may cause TCAM
    usage issue on M1 layer)
    In this testcase, we setup a new vlans with /96 IPv6 prefixes, then verify it is not advertised to M0
    """
    lo_prefix_64, vlan_prefix_v6 = setup_teardown
    bgp_neighs = duthost.bgp_facts()["ansible_facts"]["bgp_neighbors"]
    m0_p2p_addr_v6 = None
    for neigh_addr, neigh_info in bgp_neighs.items():
        if neigh_info['ip_version'] == 6 and neigh_info['description'].lower().endswith('m0'):
            m0_p2p_addr_v6 = neigh_addr
            break
    pytest_assert(m0_p2p_addr_v6 is not None, "Cannot find IPv6 M0 BGP neighbor on DUT")
    output = duthost.shell(f"vtysh -c 'show bgp neighbors {m0_p2p_addr_v6} advertised-routes json'",
                           module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, "Failed to get advertised routes to M0")
    route_info = json.loads(output['stdout'])
    pytest_assert(lo_prefix_64 in route_info['advertisedRoutes'].keys(),
                  f"/64 Loopback prefix {lo_prefix_64} is not advertised to M0")
    pytest_assert(vlan_prefix_v6 not in route_info['advertisedRoutes'].keys(),
                  f"/96 VLAN prefix {vlan_prefix_v6} is advertised to M0")
