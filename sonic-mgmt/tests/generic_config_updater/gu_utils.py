import json
import logging
import pytest
from jsonpointer import JsonPointer
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

CONTAINER_SERVICES_LIST = ["swss", "syncd", "radv", "lldp", "dhcp_relay", "teamd", "bgp", "pmon", "telemetry", "acms"]
DEFAULT_CHECKPOINT_NAME = "test"

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

    pytest_assert(
        not output['rc'] and "Checkpoint deleted successfully" in output['stdout'],
        "Failed to delete a checkpoint file: {}".format(cp)
    )

def rollback(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run rollback on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: rollback filename
    """
    cmds = 'config rollback {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    return output

def rollback_or_reload(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run rollback on target duthost. config_reload if rollback failed.

    Args:
        duthost: Device Under Test (DUT)
    """
    output = rollback(duthost, cp)

    if output['rc'] or "Config rolled back successfully" not in output['stdout']:
        config_reload(duthost)
        pytest.fail("config rollback failed. Restored by config_reload")

def create_path(tokens):
    return JsonPointer.from_parts(tokens).path

def check_show_ip_intf(duthost, intf_name, expected_content_list, unexpected_content_list, is_ipv4=True):
    """Check lo interface status by show command

    Sample output:
    admin@vlab-01:~$ show ip interfaces  | grep -w Vlan1000
    Vlan1000                   192.168.0.1/21       up/up         N/A             N/A
    admin@vlab-01:~$ show ipv6 interfaces | grep -w Vlan1000
    Vlan1000                          fc02:1000::1/64                             up/up         N/A             N/A
                                      fe80::5054:ff:feda:c6af%Vlan1000/64                       N/A             N/A
    """
    address_family = "ip" if is_ipv4 else "ipv6"
    output = duthost.shell("show {} interfaces | grep -w {} || true".format(address_family, intf_name))

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)

def check_vrf_route_for_intf(duthost, vrf_name, intf_name, is_ipv4=True):
    """Check ip route for specific vrf

    Sample output:
    admin@vlab-01:~$ show ip route vrf Vrf_01 | grep -w Loopback0
    C>* 10.1.0.32/32 is directly connected, Loopback0, 00:00:13
    """
    address_family = "ip" if is_ipv4 else "ipv6"
    output = duthost.shell("show {} route vrf {} | grep -w {}".format(address_family, vrf_name, intf_name))

    pytest_assert(not output['rc'],
        "Route not found for {} in vrf {}".format(intf_name, vrf_name))
