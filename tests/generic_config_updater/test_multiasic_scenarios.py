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

IDF_ISOLATION = [
    {
        "op": "add",
        "path": "/asic0/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
        "value": "isolated_no_export"
    },
    {
        "op": "add",
        "path": "/asic1/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
        "value": "isolated_withdraw_all"
    },
]

IDF_UNISOLATION = [
    {
        "op": "add",
        "path": "/asic0/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
        "value": "unisolated"
    },
    {
        "op": "add",
        "path": "/asic1/BGP_DEVICE_GLOBAL/STATE/idf_isolation_state",
        "value": "unisolated"
    },
]

LINK_CRC_MITIGATION_REMOVE_TEMPLATE = '[{{"op": "remove", "path": "/asic0/PORTCHANNEL_MEMBER/{}|{}"}}]'
LINK_CRC_MITIGATION_ADD_TEMPLATE = '[{{"op": "add", "path": "/asic0/PORTCHANNEL_MEMBER/{}|{}", "value": {}}}]'


def extract_up_interface(output):
    # Updated regex pattern to match both (U) and (S) status
    pattern = re.compile(r"^\s*(\d+)\s+(PortChannel\d+)\s+LACP\(\w+\)\(Up\)\s+(Ethernet\d+)\([US]\)", re.MULTILINE)
    match = pattern.search(output)
    if match:
        return match.group(2), match.group(3)
    else:
        return None, None


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for each multi asic test.
    rollback to check if it goes back to starting config
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


def test_check_empty_apply_patch(duthost):
    json_patch = []
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    if output['rc'] or "Patch applied successfully" not in output['stdout']:
        logger.info("Patching process broken, the error output is {}").format(output['stdout'])
        pytest_assert(False, "Patching process broken, the error output is {}").format(output['stdout'])


def test_check_idf_isolation_apply_patch(duthost):
    json_patch = IDF_ISOLATION
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile, ignore_tables="-i /PORT")

        if output['rc'] or "Patch applied successfully" not in output['stdout']:
            logger.info("Patching process broken, the error output is {}".format(output['stdout']))
            pytest_assert(False, "Patching process broken, the error output is {}").format(output['stdout'])

        cmds = 'sonic-db-cli -n asic0 CONFIG_DB hget "BGP_DEVICE_GLOBAL|STATE" idf_isolation_state'
        expected_value = "isolated_no_export"
        redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
        pytest_assert(redis_value == expected_value, "Config IDF ISOLATION failed")

        cmds = 'sonic-db-cli -n asic1 CONFIG_DB hget "BGP_DEVICE_GLOBAL|STATE" "idf_isolation_state"'
        expected_value = "isolated_withdraw_all"
        redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
        pytest_assert(redis_value == expected_value, "Config IDF ISOLATION failed")
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_check_idf_unisolation_apply_patch(duthost):
    json_patch = IDF_UNISOLATION
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile, ignore_tables="-i /PORT")

        if output['rc'] or "Patch applied successfully" not in output['stdout']:
            logger.info("Patching process broken, the error output is {}".format(output['stdout']))
            pytest_assert(False, "Patching process broken, the error output is {}").format(output['stdout'])
        
        cmds = 'sonic-db-cli -n asic0 CONFIG_DB hget "BGP_DEVICE_GLOBAL|STATE" idf_isolation_state'
        expected_value = "unisolated"
        redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
        pytest_assert(redis_value == expected_value, "Config IDF ISOLATION failed")

        cmds = 'sonic-db-cli -n asic1 CONFIG_DB hget "BGP_DEVICE_GLOBAL|STATE" idf_isolation_state'
        expected_value = "unisolated"
        redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
        pytest_assert(redis_value == expected_value, "Config IDF ISOLATION failed")
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_check_link_crc_mitigation_remove_and_add_apply_patch(duthost):
    tmpfile = generate_tmpfile(duthost)

    try:
        result = duthost.shell("show interfaces portchannel -n asic0", module_ignore_errors=False)['stdout']
        portchannel, port = extract_up_interface(result)

        # Precheck keys existing
        cmds = 'sonic-db-cli -n asic0 CONFIG_DB keys "PORTCHANNEL_MEMBER|{}|{}"'.format(portchannel, port)
        expected_value = "PORTCHANNEL_MEMBER|{}|{}".format(portchannel, port)
        redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
        pytest_assert(redis_value == expected_value, "Config Link CRC Mitigation add action failed.")

        json_patch = LINK_CRC_MITIGATION_REMOVE_TEMPLATE.format(portchannel, port)
        output = apply_patch(duthost, json_data=json.loads(json_patch), dest_file=tmpfile, ignore_tables="-i /PORT")

        if output['rc'] or "Patch applied successfully" not in output['stdout']:
            logger.info("Patching process broken, the error output is {}".format(output['stdout']))
            pytest_assert(False, "Patching process broken, the error output is {}").format(output['stdout'])

        cmds = 'sonic-db-cli -n asic0 CONFIG_DB keys "PORTCHANNEL_MEMBER|{}|{}"'.format(portchannel, port)
        expected_value = ""
        redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
        pytest_assert(redis_value.strip() == expected_value, "Config Link CRC Mitigation remove action failed.")

        json_patch = LINK_CRC_MITIGATION_ADD_TEMPLATE.format(portchannel, port, "{}")
        output = apply_patch(duthost, json_data=json.loads(json_patch), dest_file=tmpfile)

        if output['rc'] or "Patch applied successfully" not in output['stdout']:
            logger.info("Patching process broken, the error output is {}".format(output['stdout']))
            pytest_assert(False, "Patching process broken, the error output is {}").format(output['stdout'])

        cmds = 'sonic-db-cli -n asic0 CONFIG_DB keys "PORTCHANNEL_MEMBER|{}|{}"'.format(portchannel, port)
        expected_value = "PORTCHANNEL_MEMBER|{}|{}".format(portchannel, port)
        redis_value = duthost.shell(cmds, module_ignore_errors=False)['stdout']
        pytest_assert(redis_value == expected_value, "Config Link CRC Mitigation add action failed.")
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_check_apply_patch_negative_case(duthost):
    json_patch = '[{"op": "replace", "path": "/x"}]'
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(
            duthost, json_data=json.loads(json_patch), dest_file=tmpfile
        )
    finally:
        delete_tmpfile(duthost, tmpfile)

    pytest_assert(
        output["rc"] != 0 and "Failed to apply patch" in output["stderr"],
        "Expected failure did not occur as expected. Output: {}".format(
            output["stderr"]
        ),
    )