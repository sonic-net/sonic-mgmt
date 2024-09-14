import logging
import pytest
import re
import ipaddress

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload


pytestmark = [
    pytest.mark.topology('t1'),     # BGP Sentinel is limited to t1 only
]

logger = logging.getLogger(__name__)

BGPSENTINEL_V4 = "BGPSentinel"
BGPSENTINEL_V6 = "BGPSentinelV6"
BGPSENTINEL_SRC_ADDR_RE = "neighbor {} update-source {}"
BGPSENTINEL_IP_RANGE_RE = "bgp listen range {} peer-group {}"
DUMMY_IP_RANGE_V4 = "10.255.0.0/25"
DUMMY_IP_RANGE_V6 = "cc98:2008:2012:2022::/64"
DUMMY_SRC_ADDRESS_V4 = "10.1.0.33"
DUMMY_SRC_ADDRESS_V6 = "fc00:1::33"
IP_RANGE_V4 = "10.10.20.0/24"
IP_RANGE_V6 = "2603:10a1:30a:8000::/59"


@pytest.fixture(scope="module")
def lo_intf_ips(rand_selected_dut, tbinfo):
    """ Get loopback interface ip. This will be used as src_address in sentinel
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    ip, ipv6 = "", ""
    for lo_interface in mg_facts['minigraph_lo_interfaces']:
        if ipaddress.ip_address(lo_interface['addr']).version == 4:
            ip = lo_interface['addr']
        elif ipaddress.ip_address(lo_interface['addr']).version == 6:
            ipv6 = lo_interface['addr']
        if ip and ipv6:
            return ip, ipv6
    pytest_assert(True, "Required ipv4 and ipv6 to start the test")


def get_bgp_sentinel_runningconfig(duthost):
    """ Get bgp sentinel config that contains src_address and ip_range

    Sample output in t0:
    ['\n neighbor BGPSentinel update-source 10.1.0.32',
     '\n bgp listen range 10.255.0.0/25 peer-group BGPSentinel']
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # Sample:
    # neighbor BGPSentinel update-source 10.1.0.32
    # bgp listen range 192.168.0.0/21 peer-group BGPSentinel
    bgp_sentinel_pattern = r"\s+neighbor.*update-source.*|\s+bgp listen range.*"
    bgp_sentinel_config = re.findall(bgp_sentinel_pattern, output['stdout'])
    return bgp_sentinel_config


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for bgp sentinel config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    original_bgp_sentinel_config = get_bgp_sentinel_runningconfig(duthost)
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
        current_bgp_sentinel_config = get_bgp_sentinel_runningconfig(duthost)
        pytest_assert(
            set(original_bgp_sentinel_config) == set(current_bgp_sentinel_config),
            "bgp sentinel config are not suppose to change after test org: {}, cur: {}"
            .format(original_bgp_sentinel_config, current_bgp_sentinel_config)
        )
    finally:
        delete_checkpoint(duthost)


def bgp_sentinel_config_cleanup(duthost):
    """ Clean up bgp sentinel config to avoid ip range conflict
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "BGP_SENTINELS|*" | xargs -r sonic-db-cli CONFIG_DB del'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "bgp sentinel config cleanup failed.")


def show_bgp_running_config(duthost):
    return duthost.shell("show runningconfiguration bgp")['stdout']


def bgp_sentinel_tc1_add_config(duthost, lo_intf_ips):
    """ Test to add desired v4&v6 bgp sentinel config
    """
    lo_ip, lo_ipv6 = lo_intf_ips
    ip_range, ip_rangev6 = IP_RANGE_V4, IP_RANGE_V6

    json_patch = [
        {
            "op": "add",
            "path": "/BGP_SENTINELS",
            "value": {
                "{}".format(BGPSENTINEL_V4): {
                    "ip_range": [
                        "{}".format(ip_range)
                    ],
                    "name": "{}".format(BGPSENTINEL_V4),
                    "src_address": "{}".format(lo_ip)
                },
                "{}".format(BGPSENTINEL_V6): {
                    "ip_range": [
                        "{}".format(ip_rangev6)
                    ],
                    "name": "{}".format(BGPSENTINEL_V6),
                    "src_address": "{}".format(lo_ipv6)
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(
            re.search(BGPSENTINEL_SRC_ADDR_RE.format(BGPSENTINEL_V4, lo_ip), bgp_config) and
            re.search(BGPSENTINEL_SRC_ADDR_RE.format(BGPSENTINEL_V6, lo_ipv6), bgp_config),
            "Failed to update bgp sentinel src address."
        )
        pytest_assert(
            re.search(BGPSENTINEL_IP_RANGE_RE.format(ip_range, BGPSENTINEL_V4), bgp_config) and
            re.search(BGPSENTINEL_IP_RANGE_RE.format(ip_rangev6, BGPSENTINEL_V6), bgp_config),
            "Failed to add bgp sentinel ip range."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def bgp_sentinel_tc1_add_dummy_ip_range(duthost):
    """ Test to add dummy ip range to existed config
    """
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_SENTINELS/{}/ip_range/1".format(BGPSENTINEL_V4),
            "value": "{}".format(DUMMY_IP_RANGE_V4)
        },
        {
            "op": "add",
            "path": "/BGP_SENTINELS/{}/ip_range/1".format(BGPSENTINEL_V6),
            "value": "{}".format(DUMMY_IP_RANGE_V6)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)

        pytest_assert(
            re.search(BGPSENTINEL_IP_RANGE_RE.format(DUMMY_IP_RANGE_V4, BGPSENTINEL_V4), bgp_config) and
            re.search(BGPSENTINEL_IP_RANGE_RE.format(DUMMY_IP_RANGE_V6, BGPSENTINEL_V6), bgp_config),
            "Failed to add bgp sentinel dummy ip range."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def bgp_sentinel_tc1_rm_dummy_ip_range(duthost):
    """ Test to remove dummy ip range to existed config
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_SENTINELS/{}/ip_range/1".format(BGPSENTINEL_V4)
        },
        {
            "op": "remove",
            "path": "/BGP_SENTINELS/{}/ip_range/1".format(BGPSENTINEL_V6)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(
            not re.search(BGPSENTINEL_IP_RANGE_RE.format(DUMMY_IP_RANGE_V4, BGPSENTINEL_V4), bgp_config) and
            not re.search(BGPSENTINEL_IP_RANGE_RE.format(DUMMY_IP_RANGE_V6, BGPSENTINEL_V6), bgp_config),
            "Failed to remove bgp sentinel dummy ip range."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def bgp_sentinel_tc1_replace_src_address(duthost):
    """ Test to replace dummy src_address to existed config
    """
    json_patch = [
        {
            "op": "replace",
            "path": "/BGP_SENTINELS/{}/src_address".format(BGPSENTINEL_V4),
            "value": "{}".format(DUMMY_SRC_ADDRESS_V4)
        },
        {
            "op": "replace",
            "path": "/BGP_SENTINELS/{}/src_address".format(BGPSENTINEL_V6),
            "value": "{}".format(DUMMY_SRC_ADDRESS_V6)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(
            re.search(BGPSENTINEL_SRC_ADDR_RE.format(BGPSENTINEL_V4, DUMMY_SRC_ADDRESS_V4), bgp_config) and
            re.search(BGPSENTINEL_SRC_ADDR_RE.format(BGPSENTINEL_V6, DUMMY_SRC_ADDRESS_V6), bgp_config),
            "Failed to replace bgp sentinel src address."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def test_bgp_sentinel_tc1_test_config(rand_selected_dut, lo_intf_ips):
    """ Test suite for bgp sentinel config for v4 and v6
    """
    bgp_sentinel_config_cleanup(rand_selected_dut)
    bgp_sentinel_tc1_add_config(rand_selected_dut, lo_intf_ips)
    bgp_sentinel_tc1_add_dummy_ip_range(rand_selected_dut)
    bgp_sentinel_tc1_rm_dummy_ip_range(rand_selected_dut)
    bgp_sentinel_tc1_replace_src_address(rand_selected_dut)
