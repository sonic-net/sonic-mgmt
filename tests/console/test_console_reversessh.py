import pytest
import pexpect

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import check_target_line_status
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo')
]


def _dut_lowest_console_line(conn_graph_facts, duthost):  # noqa: F811
    """Return the lowest console line number recorded for ``duthost`` in
    ``ansible/files/*_serial_links.csv`` (exposed via ``conn_graph_facts``).
    """
    serial_links = conn_graph_facts.get("device_serial_link", {}).get(duthost.hostname, {})
    pytest_assert(
        serial_links,
        "No serial-link entry found for DUT '{}' in conn_graph_facts; check *_serial_links.csv".format(
            duthost.hostname))
    lines = sorted(int(line) for line in serial_links.keys())
    return str(lines[0])


@pytest.fixture(scope="function")
def custom_default_escape_char(duthost):
    """
    Fixture to set custom escape character and clear it after test
    """
    escape_char = "b"

    # Set escape character for all lines
    try:
        duthost.shell('sudo config console default_escape {}'.format(escape_char))
    except Exception as e:
        pytest.fail("Not able to set custom default escape character: {}".format(e))

    yield escape_char

    # Clear escape character (restore to default)
    try:
        duthost.shell('sudo config console default_escape clear')
    except Exception as e:
        pytest.fail("Not able to restore custom default escape character: {}".format(e))


def test_console_reversessh_connectivity(duthost, creds, conn_graph_facts):  # noqa: F811
    """
    Test reverse SSH is working as expect.
    Verify serial session is available after connect DUT via reverse SSH.
    The lowest-numbered console line recorded for the DUT in
    ``*_serial_links.csv`` is used.
    """
    target_line = _dut_lowest_console_line(conn_graph_facts, duthost)
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    pytest_assert(
        check_target_line_status(duthost, target_line, "IDLE"),
        "Target line {} is busy before reverse SSH session start".format(target_line))

    ressh_user = "{}:{}".format(dutuser, target_line)
    client = None
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
    finally:
        # Send escape sequence to exit reverse SSH session
        if client is not None:
            client.sendcontrol('a')
            client.sendcontrol('x')

    pytest_assert(
        wait_until(10, 1, 0, check_target_line_status, duthost, target_line, "IDLE"),
        "Target line {} is busy after exited reverse SSH session".format(target_line))


def test_console_reversessh_force_interrupt(duthost, creds, conn_graph_facts):  # noqa: F811
    """
    Test reverse SSH is working as expect.
    Verify active serial session can be shut by DUT.
    The lowest-numbered console line recorded for the DUT in
    ``*_serial_links.csv`` is used.
    """
    target_line = _dut_lowest_console_line(conn_graph_facts, duthost)
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    pytest_assert(
        check_target_line_status(duthost, target_line, "IDLE"),
        "Target line {} is busy before reverse SSH session start".format(target_line))

    ressh_user = "{}:{}".format(dutuser, target_line)
    client = None
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
        "Target line {} not toggle to IDLE state after force clear command sent".format(target_line))

    try:
        client.expect("Picocom was killed")
    except Exception as e:
        pytest.fail("Console session not exit correctly: {}".format(e))


def test_console_reversessh_custom_default_escape_character(duthost, creds, conn_graph_facts,  # noqa: F811
                                                            custom_default_escape_char):
    """
    Test reverse SSH with custom escape character.
    Verify that default escape keys don't work when escape character is changed,
    and custom escape keys work correctly. The lowest-numbered console line
    recorded for the DUT in ``*_serial_links.csv`` is used.
    """
    target_line = _dut_lowest_console_line(conn_graph_facts, duthost)
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
        client.sendcontrol(custom_default_escape_char.lower())
        client.sendcontrol('x')
    except Exception as e:
        pytest.fail("Not able to do reverse SSH to remote host via DUT: {}".format(e))

    # Check the session ended and the line state is idle
    pytest_assert(
        wait_until(10, 1, 0, check_target_line_status, duthost, target_line, "IDLE"),
        "Target line {} is busy after exited reverse SSH session with custom escape keys".format(target_line))
