import pytest
import pexpect
import re


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
