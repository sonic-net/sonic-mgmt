import getpass
import pexpect
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs")
]


@pytest.mark.parametrize("target_line", ["1", "2", "3", "4"])
def test_console_availability(duthost, creds, target_line):
    """
    Test console are well functional.
    Verify console access is available after connecting from DUT
    """
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']
    hostip, hostuser = "172.17.0.1", getpass.getuser()

    res = duthost.shell("which socat", module_ignore_errors=True)
    if res["rc"] != 0:
        # install socat to DUT host
        duthost.copy(src="./console/socat", dest="/usr/local/bin/socat", mode=755)

    out = pexpect.run("ssh {}@{} -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 'which socat'".format(
        hostuser, hostip))
    if not out:
        # install socat to KVM host
        pexpect.run("scp -q {} {}@{}:{}".format("./console/socat", hostuser, hostip, "/usr/local/bin/socat"))

    pytest_assert(duthost.shell("socat -V", module_ignore_errors=True)["rc"] == 0,
                  "Invalid socat installation on DUT host")
    pytest_assert(int(pexpect.run("ssh {}@{} -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                                  "'socat -V > /dev/null 2>&1; echo $?'".format(hostuser, hostip))) == 0,
                  "Invalid socat installation on KVM host")

    out = pexpect.run("ssh {0}@{1} -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                      "'sudo killall -q socat;"
                      "sudo lsof -i:{3} > /dev/null &&"
                      "sudo socat TCP-LISTEN:{2},fork,reuseaddr TCP:127.0.0.1:{3} & echo $?'"
                      .format(hostuser, hostip, 2000 + int(target_line), 7000 + int(target_line) - 1))
    pytest_assert(int(out.strip()) == 0, "Failed to start socat on KVM host")

    try:
        client = pexpect.spawn(
            "ssh {2}@{3} -q -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "'sudo killall -q socat;"
            "sudo killall -q picocom;"
            "sudo socat PTY,link=/dev/ttyUSB{0} TCP:10.250.0.1:{1},forever &"
            "while [ ! -e /dev/ttyUSB{0} ]; do sleep 1; done;"
            "sudo config console del {0} > /dev/null 2>&1;"
            "sudo config console add {0} --baud 9600 --devicename device{0};"
            "sudo connect line {0}'".format(
                target_line, 2000 + int(target_line), dutuser, dutip))
        client.expect('[Pp]assword:')
        client.sendline(dutpass)

        i = client.expect(['Successful connection', 'Cannot connect'], timeout=10)
        pytest_assert(i == 0,
                      "Failed to connect line {}".format(target_line))
        client.expect(['login:', '[:>~$]'], timeout=10)
    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached")
    except Exception as e:
        pytest.fail("Cannot connect to DUT host via SSH: {}".format(e))
