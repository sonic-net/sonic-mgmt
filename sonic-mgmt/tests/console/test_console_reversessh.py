import pytest
import pexpect
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any')
]

@pytest.mark.parametrize("target_line", ["1", "2"])
def test_console_reversessh_connectivity(duthost, creds, target_line):
    """
    Test reverse SSH are working as expect.
    Verify serial session is available after connect DUT via reverse SSH
    """
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    pytest_assert(
        check_target_line_status(duthost, target_line, "IDLE"),
        "Target line {} is busy before reverse SSH session start".format(target_line))

    ressh_user = "{}:{}".format(dutuser, target_line)
    try:
        client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'.format(ressh_user, dutip))
        client.expect('[Pp]assword:')
        client.sendline(dutpass)

        # Check the console line state again
        pytest_assert(
            check_target_line_status(duthost, target_line, "BUSY"),
            "Target line {} is idle while reverse SSH session is up".format(target_line))

        # Send escape sequence to exit reverse SSH session
        client.sendcontrol('a')
        client.sendcontrol('x')
    except Exception as e:
        pytest.fail("Not able to do reverse SSH to remote host via DUT")

    pytest_assert(
        wait_until(10, 1, check_target_line_status, duthost, target_line, "IDLE"),
        "Target line {} is busy after exited reverse SSH session".format(target_line))

@pytest.mark.parametrize("target_line", ["1", "2"])
def test_console_reversessh_force_interrupt(duthost, creds, target_line):
    """
    Test reverse SSH are working as expect.
    Verify active serial session can be shut by DUT
    """
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    pytest_assert(
        check_target_line_status(duthost, target_line, "IDLE"),
        "Target line {} is busy before reverse SSH session start".format(target_line))

    ressh_user = "{}:{}".format(dutuser, target_line)
    try:
        client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'.format(ressh_user, dutip))
        client.expect('[Pp]assword:')
        client.sendline(dutpass)

        # Check the console line state again
        pytest_assert(
            check_target_line_status(duthost, target_line, "BUSY"),
            "Target line {} is idle while reverse SSH session is up".format(target_line))
    except Exception as e:
        pytest.fail("Not able to do reverse SSH to remote host via DUT")

    try:
        # Force clear line from DUT
        duthost.shell('sudo sonic-clear line {}'.format(target_line))
    except Exception as e:
        pytest.fail("Not able to do clear line for DUT")

    # Check the session ended within 5s and the line state is idle
    pytest_assert(
        wait_until(5, 1, check_target_line_status, duthost, target_line, "IDLE"),
        "Target line {} not toggle to IDLE state after force clear command sent")

    try:
        client.expect("Picocom was killed")
    except Exception as e:
        pytest.fail("Console session not exit correctly: {}".format(str(e)))

def check_target_line_status(duthost, line, expect_status):
    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    return console_facts['lines'][line]['state'] == expect_status
