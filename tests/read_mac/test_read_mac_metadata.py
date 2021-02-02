import pytest
import logging

from tests.common.utilities import wait
from tests.common.utilities import wait_until
from tests.common.plugins.sanity_check import checks
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.helpers.assertions import pytest_assert
from datetime import datetime
from tests.common.reboot import reboot
from tests.common import config_reload

logger = logging.getLogger(__name__)

BINARY_FILE_ON_LOCALHOST_1 = "/tmp/sonic_image_on_localhost_1.bin"
BINARY_FILE_ON_LOCALHOST_2 = "/tmp/sonic_image_on_localhost_2.bin"
BINARY_FILE_ON_DUTHOST = "/tmp/sonic_image_on_duthost.bin"

pytestmark = [
    pytest.mark.topology('any')
]

@pytest.fixture(scope='function')
def cleanup_read_mac(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    logger.info('Remove temporary images')
    duthost.shell("rm -rf {}".format(BINARY_FILE_ON_DUTHOST))
    localhost.shell("rm -rf {}".format(BINARY_FILE_ON_LOCALHOST_1))
    localhost.shell("rm -rf {}".format(BINARY_FILE_ON_LOCALHOST_2))

    backup_minigraph_exist = duthost.stat(path = "/etc/sonic/minigraph.xml.backup")["stat"]["exists"]
    if backup_minigraph_exist:
        logger.info("Apply minigraph from backup")
        duthost.shell("mv /etc/sonic/minigraph.xml.backup /etc/sonic/minigraph.xml")
        config_reload(duthost, config_source='minigraph')


class ReadMACMetadata():
    def __init__(self, request):
        image1 = request.config.getoption("--image1")
        image2 = request.config.getoption("--image2")
        self.iteration = request.config.getoption("--iteration")
        self.minigraph1 = request.config.getoption("--minigraph1")
        self.minigraph2 = request.config.getoption("--minigraph2")

        if self.iteration < 1:
            pytest.fail("Please specify --iteration in correct range")

        self.request = request
        duthost = request.getfixturevalue('duthost')
        localhost = self.request.getfixturevalue('localhost')

        minigraph_exist = duthost.stat(path = "/etc/sonic/minigraph.xml")["stat"]["exists"]
        if (self.minigraph1 is not None or self.minigraph2 is not None) and minigraph_exist:
            logger.info("Store current minigraph for debug purpose")
            duthost.shell("cp /etc/sonic/minigraph.xml /etc/sonic/minigraph.xml.backup")

        logger.info("Download SONiC image1:  {}".format(image1))
        localhost.get_url(url=image1, dest=BINARY_FILE_ON_LOCALHOST_1)

        logger.info("Download SONiC image2:  {}".format(image2))
        localhost.get_url(url=image2, dest=BINARY_FILE_ON_LOCALHOST_2)

    def run_test_in_reinstall_loop(self):
        logger.info("Verify MAC in image reinstall loop")
        duthost  = self.request.getfixturevalue('duthost')
        localhost = self.request.getfixturevalue('localhost')

        for counter in range(1, self.iteration + 1):
            current_minigraph = self.minigraph1 if counter % 2 == 1 else self.minigraph2

            logger.info("Iteration #{}".format(counter))
            if current_minigraph:
                logger.info("Copy specified minigraph {} to the /etc/sonic folder".format(current_minigraph))
                duthost.copy(src=current_minigraph, dest="/etc/sonic/minigraph.xml")

            loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="read_mac_metadata")
            loganalyzer.match_regex = [ ".*can't parse mac address 'None'*" ]

            with loganalyzer:
                self.deploy_image_to_duthost(duthost, counter)
                reboot(duthost, localhost, wait=120)
                logger.info("Wait until system is stable")
                pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started), "Not all critical services are fully started")

            if current_minigraph:
                logger.info("Execute cli 'config load_minigraph -y' to apply new minigraph")
                config_reload(duthost, config_source='minigraph')

            logger.info("Remove old (not current) sonic image")
            duthost.reduce_and_add_sonic_images(disk_used_pcent = 1)
            self.check_mtu_and_interfaces(duthost)

    def deploy_image_to_duthost(self, duthost, counter):
        logger.info("Upload SONiC image to device")
        if counter % 2 == 1:
            duthost.copy(src=BINARY_FILE_ON_LOCALHOST_1, dest=BINARY_FILE_ON_DUTHOST)
        else:
            duthost.copy(src=BINARY_FILE_ON_LOCALHOST_2, dest=BINARY_FILE_ON_DUTHOST)

        logger.info("Installing new SONiC image")
        duthost.shell("sonic_installer install -y {}".format(BINARY_FILE_ON_DUTHOST))

    def check_mtu_and_interfaces(self, duthost):
        logger.info("Verify that MAC address fits template XX:XX:XX:XX:XX:XX")
        mac = duthost.shell("redis-cli -n 4 hget 'DEVICE_METADATA|localhost' mac| grep -io '[0-9a-fA-F:]\{17\}'",  module_ignore_errors=True)['stdout']
        logger.info("DUT MAC is {}".format(mac))

        if not mac:
            pytest.fail("MAC entry does not exist")

        logger.info("Verify interfaces are UP and MTU == 9100")
        checks.check_interfaces(duthost)

        cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        non_default_ports = [k for k,v in cfg_facts["PORT"].items() if "mtu" in v and v["mtu"] != "9100" and "admin_status" in v and v["admin_status"] == "up" ]
        non_default_portchannel = [k for k,v in cfg_facts["PORTCHANNEL"].items() if "mtu" in v and v["mtu"] != "9100" and "admin_status" in v and v["admin_status"] == "up" ]

        if len(non_default_ports) != 0 or len(non_default_portchannel) != 0:
            pytest.fail("There are ports/portchannel with non default MTU:\nPorts: {}\nPortchannel: {}".format(non_default_ports,non_default_portchannel))


@pytest.mark.disable_loganalyzer
def test_read_mac_metadata(request,cleanup_read_mac):
    """
    Verify that after installing new image on duthost MAC remains valid on interfaces
    """
    read_mac_metadata = ReadMACMetadata(request)
    read_mac_metadata.run_test_in_reinstall_loop()

