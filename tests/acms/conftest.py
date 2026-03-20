import logging
import pytest

from tests.common.helpers.dut_utils import is_container_running
from tests.acms.helper import cn, create_acms_conf, TEST_DATA_CLOUD, sidecar_container_name, watchdog_container_name
import tests.acms.helper as acms_helper


logger = logging.getLogger(__name__)
container_name = "acms"


def pytest_configure(config):
    """Detect if running in container_upgrade mode via --container_test flag.
    Runs before test collection so module-level container_name = cn.name gets the correct value."""
    global container_name
    container_test = config.getoption("--container_test", default="")
    if container_test:
        cn.name = "k8s_acms_ds"
        acms_helper.container_name = cn.name
        container_name = cn.name


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


def check_ca_cert(duthost, cert_name):
    """
    Check if CA cert is downloaded.
    """
    dut_command = "docker exec %s ls /etc/sonic/credentials" % container_name
    command_result = duthost.shell(dut_command)
    return cert_name in command_result["stdout"]


@pytest.fixture(scope='function', params=TEST_DATA_CLOUD, ids=[d["cloudtype"] for d in TEST_DATA_CLOUD])
def setup_ca_pem_cert(request, duthosts, rand_one_dut_hostname, creds):
    """
    Test ACMS CA_cert_downloader.py functionality.
    """
    test_data = request.param
    duthost = duthosts[rand_one_dut_hostname]
    http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    if ("http" not in http_proxy):
        pytest.skip("ACMS does not work without http proxy: " + http_proxy)
    cloudtype = test_data["cloudtype"]
    region_list = test_data["region_list"]
    for region in region_list:
        logger.info("Testing region %s in cloud %s" % (region, cloudtype))
        dut_command = "rm /var/opt/msft/client/*"
        duthost.shell(dut_command, module_ignore_errors=True)
        dut_command = "rm /etc/sonic/credentials/*"
        duthost.shell(dut_command, module_ignore_errors=True)
        create_acms_conf(region, cloudtype, duthost, "/var/opt/msft/client/acms_secrets.ini")
        dut_command = 'timeout %ds docker exec -e http_proxy="%s" -e https_proxy="%s" %s CA_cert_downloader.py' \
            % (5, http_proxy, https_proxy, container_name)
        duthost.shell(dut_command, module_ignore_errors=True)
        if check_ca_cert(duthost, 'ROOT_CERTIFICATE.pem'):
            return
        logger.info("Failed to download CA cert for cloud %s region %s" % (cloudtype, region))
        dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
        duthost.shell(dut_command, module_ignore_errors=True)
    pytest.fail("Failed to download CA cert for %s" % cloudtype)
