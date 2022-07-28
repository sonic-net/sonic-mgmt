import pexpect
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def connect_with_specified_ciphers(duthosts, rand_one_dut_hostname, specified_cipher, creds, typename):
    duthost = duthosts[rand_one_dut_hostname]
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']
    sonic_admin_alt_password = duthost.host.options['variable_manager']._hostvars[duthost.hostname].get(
        "ansible_altpassword")
    dutip = duthost.mgmt_ip

    if typename == "enc":
        ssh_cipher_option = "-c {}".format(specified_cipher)
    elif typename == "mac":
        ssh_cipher_option = "-m {}".format(specified_cipher)
    elif typename == "kex":
        ssh_cipher_option = "-o KexAlgorithms={}".format(specified_cipher)
    else:
        pytest.fail("typename only supports enc/mac/kex")

    ssh_cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {} {}@{}".format(ssh_cipher_option, dutuser, dutip)

    try:
        connect = pexpect.spawn(ssh_cmd)
        connect.expect('.*[Pp]assword:')
        connect.sendline(dutpass)

        i = connect.expect('{}@{}:'.format(dutuser, duthost.hostname), timeout=10)
        pytest_assert(i == 0, "Failed to connect")
    except:
        try:
            connect = pexpect.spawn(ssh_cmd)
            connect.expect('.*[Pp]assword:')
            connect.sendline(sonic_admin_alt_password)

            i = connect.expect('{}@{}:'.format(dutuser, duthost.hostname), timeout=10)
            pytest_assert(i == 0, "Failed to connect")
        except pexpect.exceptions.EOF:
            pytest.fail("EOF reached")
        except pexpect.exceptions.TIMEOUT:
            pytest.fail("Timeout reached")
        except Exception as e:
            pytest.fail("Cannot connect to DUT host via SSH: {}".format(e))

def test_ssh_protocol_version(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    result = duthost.shell("sshd --error", module_ignore_errors=True)
    major_version = result["stderr"].split("OpenSSH_", 1)[1].split(".", 1)[0]
    if major_version < "7" or '[-1' in result["stderr"]:
        pytest.fail("SSHD may support protocol version 1.x, only version 2.x will be passed")

def test_ssh_enc_ciphers(duthosts, rand_one_dut_hostname, enum_dut_ssh_enc_cipher, creds):
    typename = "enc"
    connect_with_specified_ciphers(duthosts, rand_one_dut_hostname, enum_dut_ssh_enc_cipher, creds, typename)

def test_ssh_macs(duthosts, rand_one_dut_hostname, enum_dut_ssh_mac, creds):
    typename = "mac"
    connect_with_specified_ciphers(duthosts, rand_one_dut_hostname, enum_dut_ssh_mac, creds, typename)

def test_ssh_kex(duthosts, rand_one_dut_hostname, enum_dut_ssh_kex, creds):
    typename = "kex"
    connect_with_specified_ciphers(duthosts, rand_one_dut_hostname, enum_dut_ssh_kex, creds, typename)
