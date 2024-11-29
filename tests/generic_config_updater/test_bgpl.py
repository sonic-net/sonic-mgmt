import logging
import pytest
import re

from netaddr import IPNetwork
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.generators import generate_ip_through_default_route
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx', 't2'),
]

logger = logging.getLogger(__name__)


def get_bgp_monitor_runningconfig(duthost, namespace=None):
    """ Get bgp listener config
    """
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    cmds = "show runningconfiguration bgp {}".format(namespace_prefix)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # Sample:
    # neighbor 11.0.0.1 description BGPMonitor
    bgp_listener_pattern = r"\s+neighbor.*description BGPMonitor"
    bgp_listener_config = re.findall(bgp_listener_pattern, output['stdout'])
    return bgp_listener_config


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_front_end_hostname, rand_front_end_asic_namespace):
    """
    Setup/teardown fixture for bgpmon config
    Args:
        duthosts: list of DUTs.
        rand_selected_front_end_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, _asic_id = rand_front_end_asic_namespace
    original_bgp_listener_config = get_bgp_monitor_runningconfig(duthost, namespace=asic_namespace)
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
        current_bgp_listener_config = get_bgp_monitor_runningconfig(duthost)
        pytest_assert(
            set(original_bgp_listener_config) == set(current_bgp_listener_config),
            "bgp listener config are not suppose to change after test"
        )
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def bgpmon_setup_info(rand_selected_front_end_dut):
    """ Get initial setup info for BGPMONITOR
    """
    peer_addr = generate_ip_through_default_route(rand_selected_front_end_dut)
    pytest_assert(peer_addr, "Failed to generate ip address for test")
    peer_addr = str(IPNetwork(peer_addr).ip)

    mg_facts = rand_selected_front_end_dut.minigraph_facts(host=rand_selected_front_end_dut.hostname)['ansible_facts']
    local_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']

    return peer_addr, local_addr, str(mg_facts['minigraph_bgp_asn'])


def bgpmon_cleanup_config(duthost, namespace=None):
    """ Clean up BGPMONITOR config to make sure t0 is not broken by other tests
    """
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    cmds = 'sonic-db-cli {} CONFIG_DB keys "BGP_MONITORS|*" | xargs -r sonic-db-cli CONFIG_DB del'.format(
        namespace_prefix)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "bgpmon cleanup config failed")


def check_bgpmon_with_addr(duthost, addr, namespace=None):
    """ Check BGP MONITOR config change is taken into effect
    """
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    cmds = "show ip bgp summary {} | grep -w {}".format(namespace_prefix, addr)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "BGPMonitor with addr {} is not being setup.".format(addr))


def bgpmon_tc1_add_init(duthost, bgpmon_setup_info, namespace=None):
    """ Test to add initial bgpmon config

    Make sure bgpmon is cleaned up for current topo.
    Then test to add initial setup for bgpmon.
    """
    bgpmon_cleanup_config(duthost, namespace)

    peer_addr, local_addr, bgp_asn = bgpmon_setup_info
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/BGP_MONITORS".format(json_namespace),
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
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_bgpmon_with_addr(duthost, peer_addr, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def bgpmon_tc1_add_duplicate(duthost, bgpmon_setup_info, namespace=None):
    """ Test to add duplicate config to bgpmon
    """
    peer_addr, local_addr, bgp_asn = bgpmon_setup_info
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/BGP_MONITORS/{}".format(json_namespace, peer_addr),
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
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_bgpmon_with_addr(duthost, peer_addr, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def bgpmon_tc1_admin_change(duthost, bgpmon_setup_info, namespace=None):
    """ Test to admin down bgpmon config
    """
    peer_addr, _, _ = bgpmon_setup_info
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "replace",
            "path": "{}/BGP_MONITORS/{}/admin_status".format(json_namespace, peer_addr),
            "value": "down"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        cmds = "show ip bgp summary {} | grep -w {}".format(namespace_prefix, peer_addr)
        output = duthost.shell(cmds)
        pytest_assert(not output['rc'] and "Idle (Admin)" in output['stdout'],
                      "BGPMonitor with addr {} failed to admin down.".format(peer_addr))
    finally:
        delete_tmpfile(duthost, tmpfile)


def bgpmon_tc1_ip_change(duthost, bgpmon_setup_info, namespace=None):
    """ Test to replace bgpmon ip address
    """
    peer_addr, local_addr, bgp_asn = bgpmon_setup_info
    peer_addr_replaced = generate_ip_through_default_route(duthost, [IPNetwork(peer_addr).ip])
    peer_addr_replaced = str(IPNetwork(peer_addr_replaced).ip)
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/BGP_MONITORS/{}".format(json_namespace, peer_addr)
        },
        {
            "op": "add",
            "path": "{}/BGP_MONITORS/{}".format(json_namespace, peer_addr_replaced),
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
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_bgpmon_with_addr(duthost, peer_addr_replaced, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def bgpmon_tc1_remove(duthost, namespace=None):
    """ Test to remove bgpmon config
    """
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/BGP_MONITORS".format(json_namespace)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        output = duthost.shell("show ip bgp summary {}".format(namespace_prefix))
        pytest_assert(not output['rc'], "Failed to get info from BGP summary")
        pytest_assert("BGPMonitor" not in output['stdout'], "Failed to remove BGPMonitor")
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_bgpmon_tc1_add_and_remove(rand_selected_front_end_dut, bgpmon_setup_info, rand_front_end_asic_namespace):
    """ Test to verify bgpmon config addition and deletion
    """
    asic_namespace, _asic_id = rand_front_end_asic_namespace
    bgpmon_tc1_add_init(rand_selected_front_end_dut, bgpmon_setup_info, asic_namespace)
    bgpmon_tc1_add_duplicate(rand_selected_front_end_dut, bgpmon_setup_info, asic_namespace)
    bgpmon_tc1_admin_change(rand_selected_front_end_dut, bgpmon_setup_info, asic_namespace)
    bgpmon_tc1_ip_change(rand_selected_front_end_dut, bgpmon_setup_info, asic_namespace)
    bgpmon_tc1_remove(rand_selected_front_end_dut, asic_namespace)
