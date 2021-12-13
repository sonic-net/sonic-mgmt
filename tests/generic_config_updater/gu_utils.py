import json
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

CONTAINER_SERVICES_LIST = ["swss", "syncd", "radv", "lldp", "dhcp_relay", "teamd", "bgp", "pmon", "telemetry", "acms"]

def generate_tmpfile(duthost):
    """Generate temp file
    """
    return duthost.shell('mktemp')['stdout']

def delete_tmpfile(duthost, tmpfile):
    """Delete temp file
    """
    duthost.file(path=tmpfile, state='absent')

def apply_patch(duthost, json_data, dest_file):
    """Run apply-patch on target duthost

    Args:
        duthost: Device Under Test (DUT)
        json_data: Source json patch to apply
        dest_file: Destination file on duthost
    """
    duthost.copy(content=json.dumps(json_data, indent=4), dest=dest_file)

    cmds = 'config apply-patch {}'.format(dest_file)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    return output

def expect_op_success(duthost, output):
    """Expected success from apply-patch output
    """
    pytest_assert(not output['rc'], "Command is not running successfully")
    pytest_assert(
        "Patch applied successfully" in output['stdout'],
        "Please check if json file is validate"
    )

def expect_op_success_and_reset_check(duthost, output, service_name, timeout, interval, delay):
    """Add contianer reset check after op success

    Args:
        duthost: Device Under Test (DUT)
        output: Command couput
        service_name: Service to reset
        timeout: Maximum time to wait
        interval: Poll interval
        delay: Delay time
    """
    expect_op_success(duthost, output)
    if start_limit_hit(duthost, service_name):
        reset_start_limit_hit(duthost, service_name, timeout, interval, delay)

def expect_res_success(duthost, output, expected_content_list, unexpected_content_list):
    """Check output success with expected and unexpected content

    Args:
        duthost: Device Under Test (DUT)
        output: Command output
        expected_content_list: Expected content from output
        unexpected_content_list: Unexpected content from output
    """
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
    """Expected failure from apply-patch output
    """
    logger.info("return code {}".format(output['rc']))
    pytest_assert(
        output['rc'],
        "The command should fail with non zero return code"
    )

def start_limit_hit(duthost, service_name):
    """If start-limit-hit is hit, the service will not start anyway.

    Args:
        service_name: Service to reset
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(service_name))
    pytest_assert(
        not service_status['rc'],
        "{} service status cannot be found".format(service_name)
    )

    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False

def reset_start_limit_hit(duthost, service_name, timeout, interval, delay):
    """Reset service if hit start-limit-hit

    Args:
        duthost: Device Under Test (DUT)
        service_name: Service to reset
        timeout: Maximum time to wait
        interval: Poll interval
        delay: Delay time
    """
    logger.info("Reset service '{}' due to start-limit-hit".format(service_name))

    service_reset_failed = duthost.shell("sudo systemctl reset-failed {}.service".format(service_name))
    pytest_assert(
        not service_reset_failed['rc'],
        "{} systemctl reset-failed service fails"
    )

    service_start = duthost.shell("sudo systemctl start {}.service".format(service_name))
    pytest_assert(
        not service_start['rc'],
        "{} systemctl start service fails"
    )

    if not service_name in CONTAINER_SERVICES_LIST:
        return

    reset_service = wait_until(timeout,
                        interval,
                        delay,
                        duthost.is_service_fully_started,
                        service_name)
    pytest_assert(
        reset_service,
        "Failed to reset service '{}' due to start-limit-hit".format(service_name)
    )
