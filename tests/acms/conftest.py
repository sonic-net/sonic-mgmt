import pytest

from tests.common.helpers.dut_utils import is_container_running
from tests.acms.helper import container_name


@pytest.fixture(scope='module', autouse=True)
def setup_acms(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    if not is_container_running(duthost, container_name):
        pytest.skip("ACMS container is not running")
    dut_command = "docker exec %s supervisorctl stop start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop acms" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop cert_converter" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    yield

    dut_command = "sudo rm /etc/sonic/credentials/sonic_acms_bootstrap-*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "systemctl reset-failed %s; systemctl restart %s" % (container_name, container_name)
    duthost.shell(dut_command)
