import logging
import pytest
import time

from tests.acms.helper import container_name
from tests.acms.helper import create_acms_conf
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


test_data_cloud = [
    {
        "cloudtype": "Public",
        "region_list": ["useast", "japaneast", "asiaeast"]
    },
    {
        "cloudtype": "FairFax",
        "region_list": ["usgoveast", "usgovsc", "usgovsw"]
    },
    {
        "cloudtype": "Mooncake",
        "region_list": ["chinaeast", "chinaeast2", "chinaeast3"]
    }
]


@pytest.fixture(scope='function', autouse=True)
def setup_certs(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "docker exec %s supervisorctl stop start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop acms" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)

    yield

    dut_command = "sudo rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sudo rm /etc/sonic/credentials/*"
    duthost.shell(dut_command, module_ignore_errors=True)


def check_ca_cert(duthost, cert_name):
    """
    Check if CA cert is downloaded.
    """
    dut_command = "docker exec %s ls /etc/sonic/credentials" % container_name
    command_result = duthost.shell(dut_command)
    return cert_name in command_result["stdout"]


@pytest.mark.parametrize("test_data", test_data_cloud)
def test_acms_cert_downloader(duthosts, rand_one_dut_hostname, creds, test_data):
    """
    Test ACMS CA_cert_downloader.py functionality.
    """
    duthost = duthosts[rand_one_dut_hostname]
    http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    if ("http" not in http_proxy):
        pytest.skip("ACMS does not work without http proxy: " + http_proxy)
    cloudtype = test_data["cloudtype"]
    region_list = test_data["region_list"]
    for region in region_list:
        logger.info("Testing region %s in cloud %s" % (region, cloudtype))
        dut_command = "sudo rm /var/opt/msft/client/*"
        duthost.shell(dut_command, module_ignore_errors=True)
        dut_command = "sudo rm /etc/sonic/credentials/*"
        duthost.shell(dut_command, module_ignore_errors=True)
        create_acms_conf(region, cloudtype, duthost, "/var/opt/msft/client/acms_secrets.ini")
        dut_command = 'timeout %ds docker exec -e http_proxy="%s" -e https_proxy="%s" %s\
 /usr/bin/CA_cert_downloader.py' % (5, http_proxy, https_proxy, container_name)
        duthost.shell(dut_command, module_ignore_errors=True)
        if check_ca_cert(duthost, 'ROOT_CERTIFICATE.pem'):
            return
        logger.info("Failed to download CA cert for cloud %s region %s" % (cloudtype, region))
        dut_command = "docker exec %s supervisorctl stop CA_cert_downloader" % container_name
        duthost.shell(dut_command, module_ignore_errors=True)
    pytest.fail("Failed to download CA cert for %s" % cloudtype)
