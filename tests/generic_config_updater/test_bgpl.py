import logging
import pytest

from netaddr import IPNetwork
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.generators import generate_ip_through_default_route
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)

@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for bgpmon config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)

@pytest.fixture(scope="module")
def bgpmon_setup_info(duthost):
    """ Get initial setup info for BGPMONITOR
    """
    peer_addr = generate_ip_through_default_route(duthost)
    pytest_assert(peer_addr, "Failed to generate ip address for test")
    peer_addr = str(IPNetwork(peer_addr).ip)

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    local_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']

    return peer_addr, local_addr, str(mg_facts['minigraph_bgp_asn'])

def bgpmon_cleanup_config(duthost):
    """ Clean up BGPMONITOR config to make sure t0 is not broken by other tests
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "BGP_MONITORS|*" | xargs -r sonic-db-cli CONFIG_DB del'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "bgpmon cleanup config failed"
    )

def check_bgpmon_with_addr(duthost, addr):
    """ Check BGP MONITOR config change is taken into effect
    """
    cmds = "show ip bgp summary | grep -w {}".format(addr)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "BGPMonitor with addr {} is not being setup.".format(addr)
    )

def bgpmon_tc1_add_init(duthost, bgpmon_setup_info):
    """ Test to add initial bgpmon config

    Make sure bgpmon is cleaned up for current topo.
    Then test to add initial setup for bgpmon.
    """
    bgpmon_cleanup_config(duthost)

    peer_addr, local_addr, bgp_asn = bgpmon_setup_info
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_MONITORS",
            "value": {
                peer_addr: {
                    "admin_status": "up",
                    "asn": bgp_asn,
                    "holdtime": "180",
                    "keepalive": "60",
                    "local_addr": local_addr,
                    "name": "BGPMonitor",
                    "nhopself": "0",
                    "rrclient": "0"
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_bgpmon_with_addr(duthost, peer_addr)
    finally:
        delete_tmpfile(duthost, tmpfile)

def bgpmon_tc1_add_duplicate(duthost, bgpmon_setup_info):
    """ Test to add duplicate config to bgpmon
    """
    peer_addr, local_addr, bgp_asn = bgpmon_setup_info
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_MONITORS/{}".format(peer_addr),
            "value": {
                "admin_status": "up",
                "asn": bgp_asn,
                "holdtime": "180",
                "keepalive": "60",
                "local_addr": local_addr,
                "name": "BGPMonitor",
                "nhopself": "0",
                "rrclient": "0"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_bgpmon_with_addr(duthost, peer_addr)
    finally:
        delete_tmpfile(duthost, tmpfile)

def bgpmon_tc1_admin_change(duthost, bgpmon_setup_info):
    """ Test to admin down bgpmon config
    """
    peer_addr, _, _ = bgpmon_setup_info
    json_patch = [
        {
            "op": "replace",
            "path": "/BGP_MONITORS/{}/admin_status".format(peer_addr),
            "value": "down"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        cmds = "show ip bgp summary | grep -w {}".format(peer_addr)
        output = duthost.shell(cmds)
        pytest_assert(not output['rc'] and "Idle (Admin)" in output['stdout'],
            "BGPMonitor with addr {} failed to admin down.".format(peer_addr)
        )
    finally:
        delete_tmpfile(duthost, tmpfile)

def bgpmon_tc1_ip_change(duthost, bgpmon_setup_info):
    """ Test to replace bgpmon ip address
    """
    peer_addr, local_addr, bgp_asn = bgpmon_setup_info
    peer_addr_replaced = generate_ip_through_default_route(duthost, [IPNetwork(peer_addr).ip])
    peer_addr_replaced = str(IPNetwork(peer_addr_replaced).ip)
    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_MONITORS/{}".format(peer_addr)
        },
        {
            "op": "add",
            "path": "/BGP_MONITORS/{}".format(peer_addr_replaced),
            "value": {
                "admin_status": "up",
                "asn": bgp_asn,
                "holdtime": "180",
                "keepalive": "60",
                "local_addr": local_addr,
                "name": "BGPMonitor",
                "nhopself": "0",
                "rrclient": "0"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_bgpmon_with_addr(duthost, peer_addr_replaced)
    finally:
        delete_tmpfile(duthost, tmpfile)

def bgpmon_tc1_remove(duthost):
    """ Test to remove bgpmon config
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_MONITORS"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        output = duthost.shell("show ip bgp summary")
        pytest_assert(not output['rc'],
            "Failed to get info from BGP summary"
        )
        pytest_assert("BGPMonitor" not in output['stdout'],
            "Failed to remove BGPMonitor"
        )
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_bgpmon_tc1_add_and_remove(duthost, bgpmon_setup_info):
    """ Test to verify bgpmon config addition and deletion
    """
    bgpmon_tc1_add_init(duthost, bgpmon_setup_info)
    bgpmon_tc1_add_duplicate(duthost, bgpmon_setup_info)
    bgpmon_tc1_admin_change(duthost, bgpmon_setup_info)
    bgpmon_tc1_ip_change(duthost, bgpmon_setup_info)
    bgpmon_tc1_remove(duthost)
