import pytest
import pexpect
import re
import string
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


def assert_expect_text(client, text, target_line, timeout_sec=0.1):
    index = client.expect_exact([text, pexpect.EOF, pexpect.TIMEOUT], timeout=timeout_sec)
    if index == 1:
        pytest.fail("Encounter early EOF during testing line {}".format(target_line))
    elif index == 2:
        pytest.fail("Not able to get expected text in {}s".format(timeout_sec))


def create_ssh_client(ip, user, pwd):
    # Set 'echo=False' is very important since pexpect will echo back all inputs to buffer by default
    client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'.format(user, ip),
                           echo=False)
    client.expect('[Pp]assword:')
    client.sendline(pwd)
    return client


def ensure_console_session_up(client, line):
    client.expect_exact('Successful connection to line [{}]'.format(line))
    client.expect_exact('Press ^A ^X to disconnect')


def get_target_lines(duthost):
    """
    retrieve the indices of online line cards.
    Returns a list of indices of the line cards that are online.
    """
    result = duthost.shell("show chassis module status", module_ignore_errors=True)
    lines = result['stdout'].splitlines()
    linecards = []

    # Pattern to match lines that have a "LINE-CARD" entry and "Online" in the Oper-Status column
    linecard_pattern = re.compile(r"^\s*(LINE-CARD\d+)\s+.*?\s+\d+\s+Online\s+up\s+\S+")

    for line in lines:
        match = linecard_pattern.match(line)
        if match:
            linecard_name = match.group(1)
            index = linecard_name.split("LINE-CARD")[1]
            linecards.append(index)

    if not linecards:
        pytest.fail("No line cards are online.")

    return linecards


def handle_pexpect_exceptions(target_line):
    """Handle pexpect exceptions during console interactions."""
    try:
        yield
    except pexpect.exceptions.EOF:
        pytest.fail(f"EOF reached during console interaction for line {target_line}.")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail(f"Timeout reached during console interaction for line {target_line}.")
    except Exception as e:
        pytest.fail(f"Error occured during console interaction for line {target_line}: {e}")


def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def check_target_line_status(duthost, line, expect_status):
    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    return console_facts['lines'][line]['state'] == expect_status


def get_host_ip_and_creds(host, creds):
    """Return ``(ip, user, password)`` for ``host`` using the inventory and
    the ``creds`` fixture. Works for any host registered in the inventory
    (DUT, console fanout, etc.); centralizes the inventory dance every
    console test used to repeat verbatim.
    """
    ip = host.host.options['inventory_manager'].get_host(host.hostname).vars['ansible_host']
    return ip, creds['sonicadmin_user'], creds['sonicadmin_password']


def get_dut_console_lines(conn_graph_facts, duthost):
    """Return the DUT's console line numbers (as strings) sorted ascending by
    numeric value, sourced from the ``*_serial_links.csv`` inventory exposed
    via ``conn_graph_facts['device_serial_link']``.
    """
    dut_serial_links = conn_graph_facts.get('device_serial_link', {}).get(duthost.hostname, {})
    return sorted(dut_serial_links.keys(), key=int)


def disconnect_console_client(client, escape_char='a'):
    """Send the escape sequence (``Ctrl-<escape_char>`` then ``Ctrl-X``) to
    release the console line. Defaults to ``'a'`` to match the ``picocom``
    default; pass a different ``escape_char`` if the test changed the line's
    default escape character. Safe to call with ``None`` and swallows
    teardown errors so the caller's ``finally`` block can chain other
    cleanup work.
    """
    if client is None:
        return
    try:
        client.sendcontrol(escape_char)
        client.sendcontrol('x')
    except Exception:
        # Best-effort during teardown; the line-IDLE check that typically
        # follows will surface any session that did not actually release.
        pass


def wait_for_line_idle(host, target_line, timeout_sec=10, error_msg=None):
    """Wait up to ``timeout_sec`` seconds for ``target_line`` on ``host`` to
    return to the ``IDLE`` state, asserting via ``pytest_assert`` if not.
    """
    if error_msg is None:
        error_msg = "Target line {} is busy after waiting {}s for IDLE".format(target_line, timeout_sec)
    pytest_assert(
        wait_until(timeout_sec, 1, 0, check_target_line_status, host, target_line, "IDLE"),
        error_msg)


def configure_console_line(host, line, baud_rate, flow_control=None):
    """Apply the standard ``config console`` knobs to a single line. If
    ``flow_control`` is ``None`` only the baud rate is set.
    """
    host.command("config console baud {} {}".format(line, baud_rate))
    if flow_control is not None:
        host.command("config console flow_control {} {}".format(flow_control, line))
