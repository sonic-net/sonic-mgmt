import ipaddress
import pytest

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('m1'),
]


@pytest.fixture(scope="module", autouse=True)
def teardown(duthost):
    yield
    config_reload(duthost, safe_reload=True)


def modify_dut_type(duthost, dut_type):
    output = duthost.shell(f"sonic-db-cli CONFIG_DB HSET 'DEVICE_METADATA|localhost' 'type' '{dut_type}'",
                           module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, "Failed to set DUT type")


def modify_bgp_neigh(duthost, bgp_facts, neigh_ip, neigh_name, neigh_type):
    origin_neigh_name = bgp_facts[neigh_ip]['description']
    output = duthost.shell(
        f"sonic-db-cli CONFIG_DB HSET 'BGP_NEIGHBOR|{neigh_ip}' 'name' '{neigh_name}'",
        module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, f"Failed to update BGP neigh name to {neigh_name}")
    output = duthost.shell(
        f"sonic-db-cli CONFIG_DB RENAME 'DEVICE_NEIGHBOR_METADATA|{origin_neigh_name}'"
        f" 'DEVICE_NEIGHBOR_METADATA|{neigh_name}'", module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, f"Failed to rename {origin_neigh_name} to {neigh_name}")
    output = duthost.shell(
        f"sonic-db-cli CONFIG_DB HSET 'DEVICE_NEIGHBOR_METADATA|{neigh_name}' 'type' '{neigh_type}'",
        module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, f"Failed to set BGP neigh type to {neigh_type}")


def verify_bgp_session_established(duthost, neighbors):
    bgp_facts = duthost.get_bgp_neighbors()
    for neigh_ip in neighbors:
        if neigh_ip not in bgp_facts or bgp_facts[neigh_ip]['state'] != 'established':
            return False
    return True


@pytest.mark.parametrize("ip_version", [4, 6])
@pytest.mark.parametrize("combo", [
    # entry: [DUT type, [BGP neighbor types]]
    ["MgmtSpineRouter", ['MgmtAggregator', 'CoreTs', 'MgmtToRRouter', 'SpineTs']],
    ["MgmtAccessRouter", ['MgmtAggregator', 'CoreTs', 'MgmtToRRouter', 'SpineTs']],
    ["LowerMgmtAggregator", ["CoreTs", "MgmtToRRouter", "UpperMgmtAggregator", "CoreRouter"]],
    ["UpperMgmtAggregator", ["CoreTs", "MgmtToRRouter", "LowerMgmtAggregator", "CoreRouter"]],
])
def test_bgp_establish_combo(duthost, ip_version, combo):
    target_dut_type, target_neigh_types = combo
    bgp_facts = {ip: fact for ip, fact in duthost.get_bgp_neighbors().items()
                 if ipaddress.ip_address(ip).version == ip_version}
    bgp_neigh_ips = list(bgp_facts.keys())
    mock_bgp_neighbors = []
    # Modify DUT type and BGP neighbor types
    modify_dut_type(duthost, target_dut_type)
    for i in range(len(target_neigh_types)):
        neigh_ip = bgp_neigh_ips[i]
        neigh_type = target_neigh_types[i]
        modify_bgp_neigh(duthost, bgp_facts, neigh_ip, f"mock-{target_dut_type}-{neigh_type}-v{ip_version}", neigh_type)
        mock_bgp_neighbors.append(neigh_ip)
    # This testcase restart bgp.service multiple times, reset-failed first to avoid below failure
    # >> Job for bgp.service failed because start of the service was attempted too often.
    output = duthost.shell("systemctl reset-failed bgp", module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, "Failed to reset-failed bgp service")
    # Restart BGP service and verify all BGP sessions under test can be established
    output = duthost.shell("sudo systemctl restart bgp", module_ignore_errors=True)
    pytest_assert(output['rc'] == 0, "Failed to restart bgp service")
    pytest_assert(wait_until(120, 10, 20, verify_bgp_session_established, duthost, mock_bgp_neighbors),
                  "Not all BGP sessions are established")
