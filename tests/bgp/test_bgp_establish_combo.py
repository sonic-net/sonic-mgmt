import ipaddress
import pytest

from tests.common.gcu_utils import apply_patch, expect_op_success
from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.gcu_utils import generate_tmpfile, delete_tmpfile
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('m1'),
]


def gcu_apply_patch_helper(duthost, json_patch):
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.fixture(scope="function", autouse=True)
def setup_teardown(duthost):
    # This testcase will use GCU to modify several entries in running-config.
    # Restore the config via config_reload may cost too much time.
    # So we leverage GCU for the config update. Setup checkpoint before the test
    # and rollback to it after the test.
    create_checkpoint(duthost)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


def modify_dut_type(duthost, dut_type):
    json_patch = [
        {
            "op": "replace",
            "path": "/DEVICE_METADATA/localhost/type",
            "value": dut_type
        }
    ]
    gcu_apply_patch_helper(duthost, json_patch)


def modify_bgp_neigh(duthost, bgp_facts, neigh_ip, neigh_name, neigh_type):
    # Modify neighbor name in BGP_NEIGHBOR table
    json_patch = [
        {
            "op": "replace",
            "path": f"/BGP_NEIGHBOR/{neigh_ip}/name",
            "value": neigh_name
        }
    ]
    gcu_apply_patch_helper(duthost, json_patch)

    # Modify neighbor name in DEVICE_NEIGHBOR_METADATA
    origin_neigh_name = bgp_facts[neigh_ip]['description']
    json_patch = [
        {
            "op": "move",
            "from": f"/DEVICE_NEIGHBOR_METADATA/{origin_neigh_name}",
            "path": f"/DEVICE_NEIGHBOR_METADATA/{neigh_name}"
        }
    ]
    gcu_apply_patch_helper(duthost, json_patch)

    # Modify neighbor type in DEVICE_NEIGHBOR_METADATA
    origin_neigh_name = bgp_facts[neigh_ip]['description']
    json_patch = [
        {
            "op": "replace",
            "path": f"/DEVICE_NEIGHBOR_METADATA/{neigh_name}/type",
            "value": neigh_type
        }
    ]
    gcu_apply_patch_helper(duthost, json_patch)


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
