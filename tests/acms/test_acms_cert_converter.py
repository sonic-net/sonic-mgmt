import time
import logging
import pytest
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.acms.helper import container_name
from tests.acms.helper import generate_pfx_cert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

# Location where this script finally puts the certs after format conversion
certs_path = "/etc/sonic/credentials/"
# Location where ACMS downloads certs from dSMS
acms_certs_path = "/var/opt/msft/client/dsms/sonic-prod/certificates/chained/"
# Location of the uber notify file
uber_notify_file_path = "/var/opt/msft/client/anysecret.notify"
# Certificate name
certs_name = "restapiserver"
# Backup location of the certs
backup_path = "~/acms/"
MIN_TEST_CERT_POSTFIX = 1
MAX_TEST_CERT_POSTFIX = 4


@pytest.fixture(scope='function', autouse=True)
def setup_certs(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "docker exec %s supervisorctl stop cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "mkdir -p %s" % backup_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "mv %s%s* %s" % (certs_path, certs_name, backup_path)
    duthost.shell(dut_command, module_ignore_errors=True)

    yield

    dut_command = "rm -rf %s*" % certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "mv %s%s* %s" % (backup_path, certs_name, certs_path)
    duthost.shell(dut_command, module_ignore_errors=True)


def check_converted_cert(duthost, postfix):
    ret1 = duthost.stat(path="%s%s.key%s" % (certs_path, certs_name, postfix)).get('stat', {}).get('exists', False)
    ret2 = duthost.stat(path="%s%s.crt%s" % (certs_path, certs_name, postfix)).get('stat', {}).get('exists', False)
    return ret1 and ret2


def test_acms_cert_converter(duthosts, rand_one_dut_hostname, localhost):
    """
    Test ACMS cert_converter.py.
    Convert certificates from pfx to cer and key files.
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "mkdir -p %s" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm -rf %s*" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "touch %s" % uber_notify_file_path
    duthost.shell(dut_command, module_ignore_errors=True)
    # Generate a pfx cert file
    generate_pfx_cert(duthost, "acms")
    # Copy the pfx cert file to the DUT
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        duthost.shell("docker exec acms cp /tmp/acms.pfx %s%s.pfx.%s" % (acms_certs_path, certs_name, str(i)), module_ignore_errors=True)
        # Update the notify file
        dut_command = "echo %s%s.pfx.%s > %s%s.pfx.notify" % (acms_certs_path, certs_name, str(i), acms_certs_path, certs_name)
        duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    # Wait for the cert_converter to convert the certs
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        pytest_assert(
            wait_until(30, 1, 0, check_converted_cert, duthost, '.'+str(i)),
            "Failed to convert certs %d" % i)
    pytest_assert(
        wait_until(30, 1, 0, check_converted_cert, duthost, ''),
        "Failed to convert certs link")

    # Verify symbolic link
    dut_command = "docker exec %s supervisorctl stop cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        dut_command = "sudo rm /etc/sonic/credentials/restapiserver.key." + str(i)
        duthost.shell(dut_command, module_ignore_errors=True)
    i = 100
    duthost.shell("docker exec acms cp /tmp/acms.pfx %s%s.pfx.%s" % (acms_certs_path, certs_name, str(i)), module_ignore_errors=True)
    # Update the notify file
    with open("pfx.notify", "w+") as fp:
        fp.write("%s%s.pfx.%s" % (acms_certs_path, certs_name, str(i)))
    duthost.copy(src="pfx.notify", dest="%s%s.pfx.notify" % (acms_certs_path, certs_name))
    dut_command = "docker exec %s supervisorctl start cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    pytest_assert(
        wait_until(30, 1, 0, check_converted_cert, duthost, '.'+str(i)),
        "Failed to convert certs %d" % i)
    pytest_assert(
        wait_until(30, 1, 0, check_converted_cert, duthost, ''),
        "Failed to convert certs link")
    dut_command = "ls -l %s%s.key" % (certs_path, certs_name)
    command_result = duthost.shell(dut_command, module_ignore_errors=True)
    pytest_assert(
        "%s%s.key.%d" % (certs_path, certs_name, i) in command_result['stdout'],
        "symbolic is wrong: " + command_result['stdout'])


def check_converted_cert_clean(duthost, postfix):
    ret1 = duthost.stat(path="%s%s.key%s" % (certs_path, certs_name, postfix)).get('stat', {}).get('exists', False)
    ret2 = duthost.stat(path="%s%s.crt%s" % (certs_path, certs_name, postfix)).get('stat', {}).get('exists', False)
    return not (ret1 or ret2)


def test_acms_cert_converter_clean(duthosts, rand_one_dut_hostname, localhost):
    """
    Test ACMS cert_converter.py.
    Remove link file, crt file and key file.
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "mkdir -p %s" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm -rf %s*" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "touch %s" % uber_notify_file_path
    duthost.shell(dut_command, module_ignore_errors=True)
    # Generate a pfx cert file
    generate_pfx_cert(duthost, "acms")
    # Copy the pfx cert file to the DUT
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        duthost.shell("docker exec acms cp /tmp/acms.pfx %s%s.pfx.%s" % (acms_certs_path, certs_name, str(i)), module_ignore_errors=True)
        # Update the notify file
        dut_command = "echo %s%s.pfx.%s > %s%s.pfx.notify" % (acms_certs_path, certs_name, str(i), acms_certs_path, certs_name)
        duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    # Wait for the cert_converter to convert the certs
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        pytest_assert(
            wait_until(30, 1, 0, check_converted_cert, duthost, '.'+str(i)),
            "Failed to convert certs %d" % i)
    pytest_assert(
        wait_until(30, 1, 0, check_converted_cert, duthost, ''),
        "Failed to convert certs link")
    # remove downloaded certs
    dut_command = "rm -rf %s*" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "touch %s" % uber_notify_file_path
    duthost.shell(dut_command, module_ignore_errors=True)
    # restart cert_converter
    dut_command = "docker exec %s supervisorctl restart cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    # Wait for the cert_converter to remove the certs
    pytest_assert(
        wait_until(30, 1, 0, check_converted_cert_clean, duthost, ''),
        "Failed to remove certs link")
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        pytest_assert(
            wait_until(30, 1, 0, check_converted_cert_clean, duthost, '.'+str(i)),
            "Failed to remove certs %d" % i)


def test_acms_cert_converter_upgrade(duthosts, rand_one_dut_hostname, localhost):
    """
    Test ACMS cert_converter.py.
    After upgrade, cert_converter should clean previous certs and convert new certs.
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "mkdir -p %s" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm -rf %s*" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "touch %s" % uber_notify_file_path
    duthost.shell(dut_command, module_ignore_errors=True)

    # Get current dut time
    dut_command = r"date '+%Y-%m-%d %H:%M:%S'"
    res = duthost.shell(dut_command, module_ignore_errors=True)
    datetime_obj = datetime.strptime(res["stdout"], "%Y-%m-%d %H:%M:%S")
    start_time = datetime_obj.timestamp()

    # Generate dummy cert and key
    # time for dummy cert and key
    dummy_time = "202001010101"
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX+1):
        dut_command = "touch -t %s %s%s.key.%s" % (dummy_time, certs_path, certs_name, str(i))
        duthost.shell(dut_command, module_ignore_errors=True)
        dut_command = "touch -t %s %s%s.crt.%s" % (dummy_time, certs_path, certs_name, str(i))
        duthost.shell(dut_command, module_ignore_errors=True)
    # Link cert and key
    dut_command = "ln -s %s%s.key.%s %s%s.key" % (certs_path, certs_name, str(i), certs_path, certs_name)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "ln -s %s%s.crt.%s %s%s.crt" % (certs_path, certs_name, str(i), certs_path, certs_name)
    duthost.shell(dut_command, module_ignore_errors=True)
    # Generate a pfx cert file
    generate_pfx_cert(duthost, "acms")
    # Copy the pfx cert file to the DUT
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        duthost.shell("docker exec acms cp /tmp/acms.pfx %s%s.pfx.%s" % (acms_certs_path, certs_name, str(i)), module_ignore_errors=True)
        # Update the notify file
        dut_command = "echo %s%s.pfx.%s > %s%s.pfx.notify" % (acms_certs_path, certs_name, str(i), acms_certs_path, certs_name)
        duthost.shell(dut_command, module_ignore_errors=True)

    dut_command = "docker exec %s supervisorctl start cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    # Wait for the cert_converter to convert the certs
    for i in range(MIN_TEST_CERT_POSTFIX, MAX_TEST_CERT_POSTFIX):
        pytest_assert(
            wait_until(30, 1, 0, check_converted_cert, duthost, '.'+str(i)),
            "Failed to convert certs %d" % i)
        # Verify crt modify time
        file_name = "%s%s.crt.%s" % (certs_path, certs_name, str(i))
        dut_command = r"ls --time-style=+'%Y-%m-%d %H:%M:%S' -l "
        dut_command += file_name
        dut_command += r" | awk '{print $6, $7}'"
        res = duthost.shell(dut_command, module_ignore_errors=True)
        datetime_obj = datetime.strptime(res["stdout"], "%Y-%m-%d %H:%M:%S")
        modify_time = datetime_obj.timestamp()
        pytest_assert(modify_time >= start_time, "%s time is wrong" % file_name)
        # Verify key modify time
        file_name = "%s%s.key.%s" % (certs_path, certs_name, str(i))
        dut_command = r"ls --time-style=+'%Y-%m-%d %H:%M:%S' -l "
        dut_command += file_name
        dut_command += r" | awk '{print $6, $7}'"
        res = duthost.shell(dut_command, module_ignore_errors=True)
        datetime_obj = datetime.strptime(res["stdout"], "%Y-%m-%d %H:%M:%S")
        modify_time = datetime_obj.timestamp()
        pytest_assert(modify_time >= start_time, "%s time is wrong" % file_name)
    pytest_assert(
        wait_until(30, 1, 0, check_converted_cert, duthost, ''),
        "Failed to convert certs link")
    dut_command = "ls -l %s%s.key" % (certs_path, certs_name)
    command_result = duthost.shell(dut_command, module_ignore_errors=True)
    pytest_assert(
        "%s%s.key.%d" % (certs_path, certs_name, i) in command_result['stdout'],
        "symbolic is wrong: " + command_result['stdout'])
