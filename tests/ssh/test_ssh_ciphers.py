import pexpect
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_ssh_protocol_version(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    result = duthost.shell("sshd --error", module_ignore_errors=True)
    major_version = result["stderr"].split("OpenSSH_", 1)[1].split(".", 1)[0]
    if major_version < "7" or '[-1' in result["stderr"]:
        pytest.fail("SSHD may support protocol version 1.x, only version 2.x will be passed")

def test_ssh_enc_ciphers(duthosts, rand_one_dut_hostname, enum_dut_ssh_enc_cipher, creds):
    duthost = duthosts[rand_one_dut_hostname]
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']
    dutip = duthost.mgmt_ip

    try:
        connect = pexpect.spawn("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -c {} {}@{}".format(enum_dut_ssh_enc_cipher, dutuser, dutip))
        connect.expect('{}@{}\'s password:'.format(dutuser, dutip))
        connect.sendline(dutpass)

        i = connect.expect('{}@{}:'.format(dutuser, duthost.hostname), timeout=10)
        pytest_assert(i == 0, "Failed to connect")
    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached")
    except Exception as e:
        pytest.fail("Cannot connect to DUT host via SSH: {}".format(e))

def test_ssh_macs(duthosts, rand_one_dut_hostname, enum_dut_ssh_mac, creds):
    duthost = duthosts[rand_one_dut_hostname]
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']
    dutip = duthost.mgmt_ip

    try:
        connect = pexpect.spawn("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -m {} {}@{}".format(enum_dut_ssh_mac, dutuser, dutip))
        connect.expect('{}@{}\'s password:'.format(dutuser, dutip))
        connect.sendline(dutpass)

        i = connect.expect('{}@{}:'.format(dutuser, duthost.hostname), timeout=10)
        pytest_assert(i == 0, "Failed to SSH connect")
    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached")
    except Exception as e:
        pytest.fail("Cannot connect to DUT host via SSH: {}".format(e))

def test_ssh_kex(duthosts, rand_one_dut_hostname, enum_dut_ssh_kex, creds):
    duthost = duthosts[rand_one_dut_hostname]
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']
    dutip = duthost.mgmt_ip

    try:
        connect = pexpect.spawn("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -oKexAlgorithms={} {}@{}".format(enum_dut_ssh_kex, dutuser, dutip))
        connect.expect('{}@{}\'s password:'.format(dutuser, dutip))
        connect.sendline(dutpass)

        i = connect.expect('{}@{}:'.format(dutuser, duthost.hostname), timeout=10)
        pytest_assert(i == 0, "Failed to connect")
    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached")
    except Exception as e:
        pytest.fail("Cannot connect to DUT host via SSH: {}".format(e))

