import pytest

from tests.common.helpers.dut_utils import is_container_running
from tests.acms.helper import container_name, sidecar_container_name, watchdog_container_name


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

    dut_command = "rm /etc/sonic/credentials/sonic_acms_bootstrap-*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl reload" % (container_name)
    duthost.shell(dut_command)


@pytest.fixture(scope="module")
def verify_acms_containers_running(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    for container in [container_name, watchdog_container_name, sidecar_container_name]:
        if not is_container_running(duthost, container):
            pytest.skip(f"Container {container} is not running")
