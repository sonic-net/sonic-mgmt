"""
Rconsole tests
"""

import getpass
import pexpect
import pytest
import time
import re
import logging

from tests.cisco.common.utils import skip_if_sim
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("t2"),
]


def check_rconsole(duthost, creds, slot):
    """
    Test console are well functional.
    Verify console access is available after connecting from DUT
    """
    retval = False
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']
    hostip, hostuser = "172.17.0.1", getpass.getuser()

    try:
        client = pexpect.spawn(
            "ssh {0}@{1} -q -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "'cd; "
            "sudo /opt/cisco/bin/rconsole.py -s {2}'".format(
                dutuser, dutip, slot))

        client.expect('[Pp]assword:')
        client.sendline(dutpass)

        client.sendline("\n")
        client.sendline("\n")

        i = client.expect(['sonic', 'login', pexpect.EOF], timeout=10)
        if (i == 2):
            logging.info("Rconsole {} unexpected output".format(slot))
        else:
            logging.info("Rconsole {} success".format(slot))
            retval = True

        client.sendcontrol('\\')
        client.sendline('quit')
        client.sendline('exit')
        return retval

    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached")
    except Exception as e:
        pytest.fail("Cannot connect to DUT host via SSH: {}".format(e))


def test_rconsole(duthost, creds, skip_if_sim):
    """
    Tests the remote console connection to an LC
    """

    if not duthost.is_supervisor_node():
        pytest.skip("Rconsole test only supported on RP")

    result = duthost.shell("show chassis module status | grep LINE-CARD | grep Online", 
                 module_ignore_errors=True)['stdout']
    slots = re.findall(r'LINE-CARD(\d+)', result)
    logging.info("Slots available: {}".format(slots))

    if slots:
        ret = check_rconsole(duthost, creds, slots[0])
        pytest_assert(ret == True,
                  "Rconsole Failed to connect slot {}".format(slots[0]))
    else:
        logging.info("No slots available for rconsole")
        assert(False, "No slots available for rconsole")

def check_rconsole_simultaneous(duthost, creds, slot1, slot2):
    """
    Test console are well functional.
    Verify console access is available after connecting from DUT
    """
    retval = False
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']
    hostip, hostuser = "172.17.0.1", getpass.getuser()

    try:
        client1 = pexpect.spawn(
            "ssh {0}@{1} -q -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "'cd; "
            "sudo /opt/cisco/bin/rconsole.py -s {2}'".format(
                dutuser, dutip, slot1))

        client1.expect('[Pp]assword:')
        client1.sendline(dutpass)

        client1.sendline("\n")
        client1.sendline("\n")

        i = client1.expect(['sonic', 'login', pexpect.EOF], timeout=10)
        if (i == 2):
            logging.info("Rconsole {} unexpected output: {}".format(slot1, client1.after))
            retval = False
        else:
            logging.info("Rconsole {} success".format(slot1))
            retval = True

        client2 = pexpect.spawn(
            "ssh {0}@{1} -q -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "'cd; "
            "sudo /opt/cisco/bin/rconsole.py -s {2}'".format(
                dutuser, dutip, slot2))

        client2.expect('[Pp]assword:')
        client2.sendline(dutpass)

        client2.sendline("\n")
        client2.sendline("\n")

        i = client2.expect(['sonic', 'login', pexpect.EOF], timeout=10)
        if (i == 2):
            logging.info("Rconsole {} unexpected output: {}{}".format(slot2, client2.before, client2.after))
            retval = False
        else:
            logging.info("Rconsole {} success".format(slot2))
            retval = True

        client1.sendcontrol('\\')
        client1.sendline('quit')
        client1.sendline('exit')

        client2.sendcontrol('\\')
        client2.sendline('quit')
        client2.sendline('exit')

        return retval

    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached")
    except Exception as e:
        pytest.fail("Cannot connect to DUT host via SSH: {}".format(e))


def test_rconsole_simultaneous(duthost, creds, skip_if_sim):
    """
    Test whethere we can instantiate simultaneous rconsole connections to two LCs
    """

    if not duthost.is_supervisor_node():
        pytest.skip("Rconsole tests only supported on RP")

    result = duthost.shell("show chassis module status | grep LINE-CARD | grep Online",
                 module_ignore_errors=True)['stdout']
    slots = re.findall(r'LINE-CARD(\d+)', result)

    if len(slots) >= 2:
        ret = check_rconsole_simultaneous(duthost, creds, slots[0], slots[1])
        pytest_assert(ret == True,
                  "Rconsole Failed to connect slots {} and {}".format(slots[0], slots[1]))
    else:
        logging.info("No slots available for rconsole")

