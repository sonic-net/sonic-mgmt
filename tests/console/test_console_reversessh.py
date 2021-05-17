import pytest

from tests.common.helpers.assertions import pytest_assert
from pexpect import pxssh

pytestmark = [
    pytest.mark.topology('any')
]

def test_console_reversessh_connectivity(duthost):
    """
    Test reverse SSH are working as expect.
    Verify serial session is available after connect DUT via reverse SSH
    """
    duthostvars = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars
    dutip = duthostvars['ansible_host']
    dutuser = duthostvars['ansible_user']
    dutpass = duthostvars['ansible_password']

    target_line = 1

    # Ensure the target console line is clear before testing
    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    if console_facts['lines'][target_line]['state'] == "BUSY":
        duthost.shell('sudo sonic-clear line {}'.format(target_line))

    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    pytest_assert(
        console_facts['lines'][target_line]['state'] == "IDLE",
        "Target line {} is busy before reverse SSH session start".format(target_line))

    client = pxssh.pxssh()
    ressh_user = "{}:{}".format(dutuser, target_line)
    try:
        client.login(dutip, ressh_user, dutpass)

        # Check the console line state again
        console_facts = duthost.console_facts()['ansible_facts']['console_facts']
        pytest_assert(
            console_facts['lines'][target_line]['state'] == "BUSY",
            "Target line {} is idle while reverse SSH session is up".format(target_line))
        
        # Send escape sequence to exit reverse SSH session
        client.sendcontrol('a')
        client.sendcontrol('x')
    except pxssh.ExceptionPxssh as e:
        pytest.fail("Not able to do reverse SSH to remote host via DUT")

    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    pytest_assert(
        console_facts['lines'][target_line]['state'] == "IDLE",
        "Target line {} is busy after exited reverse SSH session".format(target_line))
