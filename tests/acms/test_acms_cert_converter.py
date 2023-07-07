import time
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.acms.helper import container_name

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


@pytest.fixture(scope='function', autouse=True)
def setup_certs(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "docker exec %s supervisorctl stop cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo mkdir -p %s" % backup_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo mv %s%s* %s" % (certs_path, certs_name, backup_path)
    duthost.shell(dut_command, module_ignore_errors=True)

    yield

    dut_command = "sudo rm -rf %s*" % certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo mv %s%s* %s" % (backup_path, certs_name, certs_path)
    duthost.shell(dut_command, module_ignore_errors=True)


def generate_pfx_cert(localhost, cert_name):
    """
    Generate a pfx cert file on the DUT.
    """
    command = "openssl genrsa -out %s.key 2048" % (cert_name)
    localhost.shell(command)
    command = "openssl req -new -x509 -key %s.key -out %s.crt -subj '/CN=test.server.restapi.sonic' -days 3650" % (cert_name, cert_name)
    localhost.shell(command)
    command = "openssl pkcs12 -export -out %s.pfx -inkey %s.key -in %s.crt -password pass:" % (cert_name, cert_name, cert_name)
    localhost.shell(command)


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
    dut_command = "sudo mkdir -p %s" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo rm -rf %s*" % acms_certs_path
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo touch %s" % uber_notify_file_path
    duthost.shell(dut_command, module_ignore_errors=True)
    # Generate a pfx cert file
    generate_pfx_cert(localhost, "acms")
    # Copy the pfx cert file to the DUT
    for i in range(1, 4):
        duthost.copy(src="acms.pfx", dest="%s%s.pfx.%s" % (acms_certs_path, certs_name, str(i)))
        # Update the notify file
        dut_command = "sudo echo %s%s.pfx.%s > %s%s.pfx.notify" % (acms_certs_path, certs_name, str(i), acms_certs_path, certs_name)
        duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    # Wait for the cert_converter to convert the certs
    for i in range(1, 4):
        pytest_assert(
            wait_until(30, 1, 0, check_converted_cert, duthost, '.'+str(i)),
            "Failed to convert certs %d" % i)
    pytest_assert(
        wait_until(30, 1, 0, check_converted_cert, duthost, ''),
        "Failed to convert certs link")
