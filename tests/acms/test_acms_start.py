import time
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.acms.helper import container_name
from tests.acms.helper import generate_pfx_cert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

test_data_cloud = [
    {
        "cloudtype": "Public",
        "region": "useast",
        "url": "https://useast-dsms.dsms.core.windows.net"
    },
    {
        "cloudtype": "FairFax",
        "region": "usgoveast",
        "url": "https://usgoveast-dsms.dsms.core.usgovcloudapi.net"
    },
    {
        "cloudtype": "Mooncake",
        "region": "chinaeast",
        "url": "https://chinaeast-dsms.dsms.core.chinacloudapi.cn"
    }
]


@pytest.fixture(scope='function', autouse=True)
def setup_certs(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    dut_command = "docker exec %s supervisorctl stop start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop acms" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/sonic_acms_bootstrap-*"
    duthost.shell(dut_command, module_ignore_errors=True)

    yield

    dut_command = "rm /var/opt/msft/client/*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "rm /etc/sonic/credentials/sonic_acms_bootstrap-*"
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "sonic-db-cli CONFIG_DB hset 'DEVICE_METADATA|localhost' 'cloudtype' 'Public'"
    duthost.shell(dut_command, module_ignore_errors=True)


def check_acms_conf(duthost, url):
    dut_command = "cat /var/opt/msft/client/acms_secrets.ini"
    ret = duthost.shell(dut_command)
    if ret["rc"] != 0:
        return False
    logger.info("acms_secrets.ini: %s" % ret["stdout"])
    return url in ret["stdout"]


@pytest.mark.parametrize("test_data", test_data_cloud)
def test_acms_start(duthosts, rand_one_dut_hostname, creds, test_data):
    """
    Test ACMS start.py.
    Verify different cloud type and region.
    """
    duthost = duthosts[rand_one_dut_hostname]
    cloudtype = test_data["cloudtype"]
    region = test_data["region"]
    url = test_data["url"]
    logger.info("cloudtype: %s, region: %s, url: %s" % (cloudtype, region, url))
    dut_command = "sonic-db-cli CONFIG_DB hset 'DEVICE_METADATA|localhost' 'cloudtype' '%s'" % cloudtype
    duthost.shell(dut_command, module_ignore_errors=True)
    generate_pfx_cert(duthost, "acms")
    dut_command = "docker exec acms cp /tmp/acms.pfx /etc/sonic/credentials/sonic_acms_bootstrap-%s.pfx" % region
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    pytest_assert(
        wait_until(30, 1, 0, check_acms_conf, duthost, url),
        "Failed to update acms_secrets.ini")
