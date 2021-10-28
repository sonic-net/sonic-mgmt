import json
import time
import logging
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

def apply_patch(duthost, json_data, dest_file):
    duthost.copy(content=json.dumps(json_data, indent=4), dest=dest_file)

    cmds = 'config apply-patch {}'.format(dest_file)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)
    # output = duthost.shell(cmds)

    return output

def expect_op_success(duthost, output):
    pytest_assert(not output['rc'], "Command is not running successfully")
    pytest_assert("Patch applied successfully" in output['stdout'], "Please check if json file is validate")
    time.sleep(5)
    pytest_assert(duthost.is_service_fully_started('dhcp_relay'), "dhcp_relay service is not running")

def expect_res_success(duthost, expected_server_list, unexpected_server_list):
    output = duthost.shell('docker exec dhcp_relay ps aux')
    for expected_server in expected_server_list:
        pytest_assert(expected_server not in output['stdout'], "dhcp server {} is not deleted successfully".format(expected_server))
    for unexpected_server in unexpected_server_list:
        pytest_assert(unexpected_server in output['stdout'], "dhcp server {} is not added successfully".format(unexpected_server))

def expect_op_failure(output):
    logger.info("return code {}".format(output['rc']))
    pytest_assert(output['rc'], "The command should fail with non zero return code")
