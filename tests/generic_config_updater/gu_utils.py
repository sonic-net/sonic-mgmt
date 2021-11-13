import json
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

def generate_tmpfile(duthost):
    return duthost.shell('mktemp')['stdout']

def delete_tmpfile(duthost, tmpfile):
    duthost.file(path=tmpfile, state='absent')

def apply_patch(duthost, json_data, dest_file):
    duthost.copy(content=json.dumps(json_data, indent=4), dest=dest_file)

    cmds = 'config apply-patch {}'.format(dest_file)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    return output

def expect_op_success(duthost, output):
    pytest_assert(not output['rc'], "Command is not running successfully")
    pytest_assert(
        "Patch applied successfully" in output['stdout'],
        "Please check if json file is validate"
    )

def expect_op_success_and_reset_check(duthost, output, container_name, threshold, interval, delay):
    '''Add contianer reset check after op success
    '''
    expect_op_success(duthost, output)
    if start_limit_hit(duthost, container_name):
        reset_start_limit_hit(duthost, container_name, threshold, interval, delay)

def expect_res_success(duthost, output, expected_content_list, unexpected_content_list):
    for expected_content in expected_content_list:
        pytest_assert(
            expected_content in output['stdout'],
            "{} is expected content".format(expected_content)
        )

    for unexpected_content in unexpected_content_list:
        pytest_assert(
            unexpected_content not in output['stdout'],
            "{} is unexpected content".format(unexpected_content)
        )

def expect_op_failure(output):
    logger.info("return code {}".format(output['rc']))
    pytest_assert(
        output['rc'],
        "The command should fail with non zero return code"
    )

def start_limit_hit(duthost, container_name):
    """If start-limit-hit is hit, the service will not start anyway.
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(container_name))
    pytest_assert(
        not service_status['rc'],
        "{} service status cannot be found".format(container_name)
    )

    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False

def reset_start_limit_hit(duthost, container_name, threshold, interval, delay):
    """Reset container if hit start-limit-hit
    """
    logger.info("Reset container '{}' due to start-limit-hit".format(container_name))

    service_reset_failed = duthost.shell("sudo systemctl reset-failed {}.service".format(container_name))
    pytest_assert(
        not service_reset_failed['rc'],
        "{} systemctl reset-failed service fails"
    )

    service_start = duthost.shell("sudo systemctl start {}.service".format(container_name))
    pytest_assert(
        not service_start['rc'],
        "{} systemctl start service fails"
    )

    reset_container = wait_until(threshold,
                        interval,
                        delay,
                        duthost.is_service_fully_started,
                        container_name)
    pytest_assert(
        reset_container,
        "Failed to reset container '{}' due to start-limit-hit".format(container_name)
    )
