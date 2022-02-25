import logging
import pytest
import re
import ipaddress

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t0'), # BGP Speaker is limited to t0 only
]

logger = logging.getLogger(__name__)

BGPSPEAKER_V4          = "BGPSLBPassive"
BGPSPEAKER_V6          = "BGPSLBPassiveV6"
BGPSPEAKER_SRC_ADDR_RE = "neighbor {} update-source {}"
BGPSPEAKER_IP_RANGE_RE = "bgp listen range {} peer-group {}"
DUMMY_IP_RANGE_V4      = "10.255.0.0/25"
DUMMY_IP_RANGE_V6      = "cc98:2008:2012:2022::/64"

@pytest.fixture(scope="module")
def vlan_intf_ip_ranges(duthost, tbinfo):
    """ Get vlan subnet. This will be used as bgp speaker ip range
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ip_range, ip_rangev6 = "", ""
    for vlan_interface in mg_facts['minigraph_vlan_interfaces']:
        if ipaddress.ip_address(vlan_interface['addr']).version == 4:
            ip_range = vlan_interface['subnet']
        elif ipaddress.ip_address(vlan_interface['addr']).version == 6:
            ip_rangev6 = vlan_interface['subnet']
        if ip_range and ip_rangev6:
            return ip_range, ip_rangev6
    pytest_assert(True, "Required ip_range and ip_rangev6 to start the test")

@pytest.fixture(scope="module")
def lo_intf_ips(duthost, tbinfo):
    """ Get loopback interface ip. This will be used as src_address in speaker
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ip, ipv6 = "", ""
    for lo_interface in mg_facts['minigraph_lo_interfaces']:
        if ipaddress.ip_address(lo_interface['addr']).version == 4:
            ip = lo_interface['addr']
        elif ipaddress.ip_address(lo_interface['addr']).version == 6:
            ipv6 = lo_interface['addr']
        if ip and ipv6:
            return ip, ipv6
    pytest_assert(True, "Required ipv4 and ipv6 to start the test")


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for bgp speaker config
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

def bgp_speaker_config_cleanup(duthost):
    """ Clean up bgp speaker config to avoid ip range conflict
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "BGP_PEER_RANGE|*" | xargs -r sonic-db-cli CONFIG_DB del'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "bgp speaker config cleanup failed."
    )

def show_bgp_running_config(duthost):
    return duthost.shell("show runningconfiguration bgp")['stdout']

def bgp_speaker_tc1_add_config(duthost, lo_intf_ip, vlan_intf_ip_range, bgp_speaker):
    """ Test to add desired v4/v6 bgp speaker config
    """
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_PEER_RANGE",
            "value": {
                "{}".format(bgp_speaker): {
                    "ip_range": [
                        "{}".format(vlan_intf_ip_range)
                    ],
                    "name": "{}".format(bgp_speaker),
                    "src_address": "{}".format(lo_intf_ip)
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
        pytest_assert(re.search(BGPSPEAKER_SRC_ADDR_RE.format(bgp_speaker, lo_intf_ip), bgp_config),
            "Failed to update bgp speaker src address."
        )
        pytest_assert(re.search(BGPSPEAKER_IP_RANGE_RE.format(bgp_speaker, vlan_intf_ip_range), bgp_config),
            "Failed to add bgp speaker ip range."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)

def bgp_speaker_tc1_add_dummy_ip_range(duthost, bgp_speaker, dummy_ip_range):
    """ Test to add dummy ip range to existed config
    """
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_PEER_RANGE/{}/ip_range/1".format(bgp_speaker),
            "value": "{}".format(dummy_ip_range)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(re.search(BGPSPEAKER_IP_RANGE_RE.format(bgp_speaker, dummy_ip_range), bgp_config),
            "Failed to add bgp speaker dummy ip range."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)

def bgp_speaker_tc1_rm_dummy_ip_range(duthost, bgp_speaker, dummy_ip_range):
    """ Test to remove dummy ip range to existed config
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_PEER_RANGE/{}/ip_range/1".format(bgp_speaker)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = show_bgp_running_config(duthost)
        pytest_assert(not re.search(BGPSPEAKER_IP_RANGE_RE.format(bgp_speaker, dummy_ip_range), bgp_config),
            "Failed to remove bgp speaker dummy ip range."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("ip_version", ["v4", "v6"])
def test_bgp_speaker_tc1_test_config(duthost, lo_intf_ips, vlan_intf_ip_ranges):
    """ Test suite for bgp speaker config for v4 and v6
    """
    lo_ip, lo_ipv6 = lo_intf_ips
    ip_range, ip_rangev6 = vlan_intf_ip_ranges

    if "ip_version" == "v4":
        lo_intf_ip = lo_ip
        vlan_intf_ip_range = ip_range
        bgp_speaker = BGPSPEAKER_V4
        dummy_ip_range = DUMMY_IP_RANGE_V4
    elif "ip_version" == "v6":
        lo_intf_ip = lo_ipv6
        vlan_intf_ip_range = ip_rangev6
        bgp_speaker = BGPSPEAKER_V6
        dummy_ip_range = DUMMY_IP_RANGE_V6
    else:
        pytest.fail("Invalid ip version!")

    bgp_speaker_config_cleanup(duthost)
    bgp_speaker_tc1_add_config(duthost, lo_intf_ip, vlan_intf_ip_range, bgp_speaker)
    bgp_speaker_tc1_add_dummy_ip_range(duthost, bgp_speaker, dummy_ip_range)
    bgp_speaker_tc1_rm_dummy_ip_range(duthost, bgp_speaker, dummy_ip_range)
