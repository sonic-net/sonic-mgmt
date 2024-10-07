import os
import logging
import json
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "../generic_config_updater/templates")
TMP_DIR = '/tmp'

logger = logging.getLogger(__name__)


def format_and_apply_template(duthost, template_name, extra_vars, setup):
    dest_path = os.path.join(TMP_DIR, template_name)

    duts_to_apply = [duthost]
    outputs = []
    if setup["is_dualtor"]:
        duts_to_apply.append(setup["rand_unselected_dut"])


def apply_patch(duthost, json_data, dest_file, ignore_tables=None):
    """Run apply-patch on target duthost

    Args:
        duthost: Device Under Test (DUT)
        json_data: Source json patch to apply
        dest_file: Destination file on duthost
        ignore_tables: to be ignored tables, "-i table_name"
    """
    duthost.copy(content=json.dumps(json_data, indent=4), dest=dest_file)

    cmds = 'config apply-patch {} {}'.format(dest_file, ignore_tables if ignore_tables else "")

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    return output


def replace(duthost, replace_config_file):
    """Run replace with given config file on target duthost

    Args:
        duthost: Device Under Test (DUT)
        replace_config_file: Destination file on duthost
    """
    cmds = 'config replace {}'.format(replace_config_file)

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
    service_status = duthost.shell("systemctl status {}.service | grep 'Active'".format(service_name))
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

    service_reset_failed = duthost.shell("systemctl reset-failed {}.service".format(service_name))
    pytest_assert(
        not service_reset_failed['rc'],
        "{} systemctl reset-failed service fails"
    )

    service_start = duthost.shell("systemctl start {}.service".format(service_name))
    pytest_assert(
        not service_start['rc'],
        "{} systemctl start service fails"
    )

    if service_name not in CONTAINER_SERVICES_LIST:
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


def list_checkpoints(duthost):
    """List checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    cmds = 'config list-checkpoints'

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc'],
        "Failed to list all checkpoint file"
    )

    return output


def verify_checkpoints_exist(duthost, cp):
    """Check if checkpoint file exist in duthost
    """
    output = list_checkpoints(duthost)
    return '"{}"'.format(cp) in output['stdout']


def create_checkpoint(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    cmds = 'config checkpoint {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc']
        and "Checkpoint created successfully" in output['stdout']
        and verify_checkpoints_exist(duthost, cp),
        "Failed to config a checkpoint file: {}".format(cp)
    )


def delete_checkpoint(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    pytest_assert(
        verify_checkpoints_exist(duthost, cp),
        "Failed to find the checkpoint file: {}".format(cp)
    )

    cmds = 'config delete-checkpoint {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

        try:
            # duthost.template uses single quotes, which breaks apply-patch. this replaces them with double quotes
            dut.shell("sed -i \"s/'/\\\"/g\" " + dest_path)
            output = dut.shell("config apply-patch {}".format(dest_path))
            outputs.append(output)
        finally:
            dut.file(path=dest_path, state='absent')

    return outputs


def load_and_apply_json_patch(duthost, file_name, setup):
    with open(os.path.join(TEMPLATES_DIR, file_name)) as file:
        json_patch = json.load(file)

    duts_to_apply = [duthost]
    outputs = []
    if setup["is_dualtor"]:
        duts_to_apply.append(setup["rand_unselected_dut"])

    for dut in duts_to_apply:

        tmpfile = generate_tmpfile(dut)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(dut, json_data=json_patch, dest_file=tmpfile)
            outputs.append(output)
        finally:
            delete_tmpfile(dut, tmpfile)

    return outputs
