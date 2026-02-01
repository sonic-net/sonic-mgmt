import pytest
import pexpect
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo')
]


console_lines = list(map(str, range(1, 49)))


@pytest.fixture(params=["B", "C", "b", "c"])
def custom_escape_char(duthost, request):
    """
    Fixture to set custom escape character and clear it after test
    """
    escape_char = request.param

    # Set escape character for all lines
    try:
        duthost.shell('sudo config console escape {}'.format(escape_char))
    except Exception as e:
        pytest.fail("Not able to set custom escape character: {}".format(e))

    yield escape_char

    # Clear escape character (restore to default)
    try:
        duthost.shell('sudo config console escape clear')
    except Exception:
        pass


@pytest.mark.parametrize("target_line", random.sample(console_lines, 2))
def test_console_reversessh_connectivity(duthost, creds, target_line):
    """
    Test reverse SSH is working as expect.
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
        client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                               .format(ressh_user, dutip))
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
        pytest.fail("Not able to do reverse SSH to remote host via DUT: {}".format(e))

    pytest_assert(
        wait_until(10, 1, 0, check_target_line_status, duthost, target_line, "IDLE"),
        "Target line {} is busy after exited reverse SSH session".format(target_line))


@pytest.mark.parametrize("target_line", random.sample(console_lines, 2))
def test_console_reversessh_force_interrupt(duthost, creds, target_line):
    """
    Test reverse SSH is working as expect.
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
        client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                               .format(ressh_user, dutip))
        client.expect('[Pp]assword:')
        client.sendline(dutpass)

        # Check the console line state again
        pytest_assert(
            check_target_line_status(duthost, target_line, "BUSY"),
            "Target line {} is idle while reverse SSH session is up".format(target_line))
    except Exception as e:
        pytest.fail("Not able to do reverse SSH to remote host via DUT: {}".format(e))

    try:
        # Force clear line from DUT
        duthost.shell('sudo sonic-clear line {}'.format(target_line))
    except Exception as e:
        pytest.fail("Not able to do clear line for DUT: {}".format(e))

    # Check the session ended within 5s and the line state is idle
    pytest_assert(
        wait_until(5, 1, 0, check_target_line_status, duthost, target_line, "IDLE"),
        "Target line {} not toggle to IDLE state after force clear command sent")

    try:
        client.expect("Picocom was killed")
    except Exception as e:
        pytest.fail("Console session not exit correctly: {}".format(e))


@pytest.mark.parametrize("target_line", random.sample(console_lines, 4))
def test_console_reversessh_custom_escape_character(duthost, creds, target_line, custom_escape_char):
    """
    Test reverse SSH with custom escape character.
    Verify that default escape keys don't work when escape character is changed,
    and custom escape keys work correctly
    """
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    pytest_assert(
        check_target_line_status(duthost, target_line, "IDLE"),
        "Target line {} is busy before reverse SSH session start".format(target_line))

    ressh_user = "{}:{}".format(dutuser, target_line)
    try:
        client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                               .format(ressh_user, dutip))
        client.expect('[Pp]assword:')
        client.sendline(dutpass)

        # Check the console line state again
        pytest_assert(
            check_target_line_status(duthost, target_line, "BUSY"),
            "Target line {} is idle while reverse SSH session is up".format(target_line))

        # Try to send default escape sequence (ctrl-A + ctrl-X) - should NOT exit
        client.sendcontrol('a')
        client.sendcontrol('x')

        # Check the line state - should still be BUSY
        pytest_assert(
            check_target_line_status(duthost, target_line, "BUSY"),
            "Target line {} exited with default escape keys when custom escape char is set".format(target_line))

        # Send custom escape sequence (ctrl-B + ctrl-X) - should exit
        client.sendcontrol(custom_escape_char.lower())
        client.sendcontrol('x')
    except Exception as e:
        pytest.fail("Not able to do reverse SSH to remote host via DUT: {}".format(e))

    # Check the session ended and the line state is idle
    pytest_assert(
        wait_until(10, 1, 0, check_target_line_status, duthost, target_line, "IDLE"),
        "Target line {} is busy after exited reverse SSH session with custom escape keys".format(target_line))


def check_target_line_status(duthost, line, expect_status):
    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    return console_facts['lines'][line]['state'] == expect_status
