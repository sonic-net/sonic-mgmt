import json
import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

LINK_CRC_MITIGATION_ADD_TEMPLATE = '[{{"op": "add", "path": "/asic0/PORTCHANNEL_MEMBER/{}|{}", "value": {}}}]'
LINK_CRC_MITIGATION_REMOVE_TEMPLATE = '[{{"op": "remove", "path": "/asic0/PORTCHANNEL_MEMBER/{}|{}"}}]'


def extract_up_interface(output):
    """Extract portchannel and port from interface output.
    Example:
    admin@str2-7250-lc1-1:~$ show interfaces portchannel -n asic0
    Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
        S - selected, D - deselected, * - not synced
    No.  Team Dev        Protocol     Ports
    -----  --------------  -----------  ---------------------------
    102  PortChannel102  LACP(A)(Up)  Ethernet40(S) Ethernet32(S)

    Then we will use the regex to extract PortChannel102 and Ethernet40.
    """
    pattern = re.compile(
        r"^\s*(\d+)\s+(PortChannel\d+)\s+LACP\(\w+\)\(Up\)\s+(Ethernet\d+)\([US]\)",
        re.MULTILINE
    )
    match = pattern.search(output)
    if match:
        return match.group(2), match.group(3)
    return None, None


def apply_patch_and_verify(duthost, json_patch, tmpfile):
    """Apply patch and verify success."""
    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    if output['rc'] or "Patch applied successfully" not in output['stdout']:
        err_msg = f"Patching failed: {output['stdout']}"
        logger.info(err_msg)
        pytest_assert(False, err_msg)
    return output


def verify_portchannel_member(duthost, portchannel, port, member_exists):
    """Verify portchannel member state in CONFIG_DB.

    Args:
        duthost: DUT host object
        portchannel: Name of the portchannel
        port: Name of the member port
        member_exists: Boolean indicating if member should exist
    """
    cmds = f'sonic-db-cli -n asic0 CONFIG_DB keys "PORTCHANNEL_MEMBER|{portchannel}|{port}"'
    redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout'].strip()
    expected_value = f"PORTCHANNEL_MEMBER|{portchannel}|{port}" if member_exists else ""
    pytest_assert(redis_value == expected_value,
                  f"Config Link CRC Mitigation action failed. Expected: {expected_value}, Got: {redis_value}")


def show_current_config(duthost):
    """Show current running config."""
    logger.info("The current running config is:")
    logger.info(duthost.shell("show run all", module_ignore_errors=False)['stdout'])


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """Setup/teardown fixture for each multi asic test."""
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)
    yield
    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def test_check_empty_apply_patch(duthost):
    """Test applying empty patch."""
    json_patch = []
    tmpfile = generate_tmpfile(duthost)

    try:
        apply_patch_and_verify(duthost, json_patch, tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_check_link_crc_mitigation_remove_and_add_apply_patch(duthost):
    """Test removing and adding link CRC mitigation."""
    tmpfile = generate_tmpfile(duthost)
    try:
        show_current_config(duthost)

        result = duthost.shell("show interfaces portchannel -n asic0", module_ignore_errors=False)['stdout']
        portchannel, port = extract_up_interface(result)

        # Verify initial state
        verify_portchannel_member(duthost, portchannel, port, True)

        # Remove member
        json_patch = LINK_CRC_MITIGATION_REMOVE_TEMPLATE.format(portchannel, port)
        apply_patch_and_verify(duthost, json.loads(json_patch), tmpfile)
        verify_portchannel_member(duthost, portchannel, port, False)

        # Add member back
        json_patch = LINK_CRC_MITIGATION_ADD_TEMPLATE.format(portchannel, port, "{}")
        apply_patch_and_verify(duthost, json.loads(json_patch), tmpfile)
        verify_portchannel_member(duthost, portchannel, port, True)

    finally:
        delete_tmpfile(duthost, tmpfile)


def test_check_apply_patch_negative_case(duthost):
    """Test patch failure case."""
    json_patch = '[{"op": "replace", "path": "/x"}]'
    tmpfile = generate_tmpfile(duthost)

    try:
        show_current_config(duthost)
        output = apply_patch(duthost, json_data=json.loads(json_patch), dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    pytest_assert(
        output["rc"] != 0 and "Failed to apply patch" in output["stderr"],
        f"Expected failure did not occur as expected. Output: {output['stderr']}"
    )
