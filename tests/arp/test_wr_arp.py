import logging
import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                             # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                                # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses                                 # noqa F401
from tests.common.fixtures.ptfhost_utils import skip_traffic_test                                   # noqa F401
from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies     # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.arp_utils import setupFerret, teardownRouteToPtfhost, setupRouteToPtfhost, \
    PTFRUNNER_QLEN, VXLAN_CONFIG_FILE, DEFAULT_TEST_DURATION, testWrArp

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]


@pytest.fixture(scope='class', autouse=True)
def setupFerretFixture(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    setupFerret(duthost, ptfhost, tbinfo)


@pytest.fixture(scope='class', autouse=True)
def clean_dut(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    yield
    logger.info("Clear ARP cache on DUT")
    duthost.command('sonic-clear arp')


@pytest.fixture(scope='class', autouse=True)
def setupRouteToPtfhostFixture(duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]
    route, ptfIp, gwIp = setupRouteToPtfhost(duthost, ptfhost)
    yield
    teardownRouteToPtfhost(duthost, route, ptfIp, gwIp)


def checkWarmbootFlag(duthost):
    """
        Checks if warm-reboot system flag is set to false.
    """
    warmbootFlag = duthost.shell(
        cmd='sonic-db-cli STATE_DB hget "WARM_RESTART_ENABLE_TABLE|system" enable')['stdout']
    logger.info("warmbootFlag: " + warmbootFlag)
    return warmbootFlag != 'true'


@pytest.fixture(scope='class', autouse=True)
def warmRebootSystemFlag(duthost):
    """
        Sets warm-reboot system flag to false after test. This class-scope fixture runs once before test start

        Args:
            duthost (AnsibleHost): Device Under Test (DUT)

        Returns:
            None
    """
    yield
    if not wait_until(300, 10, 0, checkWarmbootFlag, duthost):
        logger.info('Setting warm-reboot system flag to false')
        duthost.shell(cmd='sonic-db-cli STATE_DB hset "WARM_RESTART_ENABLE_TABLE|system" enable false')


def test_wr_arp(request, duthost, ptfhost, creds, skip_traffic_test):   # noqa F811
    '''
        Control Plane Assistant test for Warm-Reboot.

        The test first start Ferret server, implemented in Python. Then initiate Warm-Reboot procedure.
        While the host in Warm-Reboot test continuously sending ARP request to the Vlan member ports and
        expect to  receive ARP replies. The test will fail as soon as there is no replies for
        more than 25 seconds for one of the Vlan member ports.

        Args:
            request: pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    '''
    testWrArp(request, duthost, ptfhost, creds, skip_traffic_test)


def test_wr_arp_advance(request, duthost, ptfhost, creds, skip_traffic_test):    # noqa F811
    testDuration = request.config.getoption('--test_duration', default=DEFAULT_TEST_DURATION)
    ptfIp = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    dutIp = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    logger.info('Warm-Reboot Control-Plane assist feature')
    sonicadmin_alt_password = duthost.host.options['variable_manager'].\
        _hostvars[duthost.hostname]['sonic_default_passwords']
    if skip_traffic_test is True:
        return
    ptf_runner(
        ptfhost,
        'ptftests',
        'wr_arp.ArpTest',
        qlen=PTFRUNNER_QLEN,
        platform_dir='ptftests',
        platform='remote',
        params={
            'ferret_ip': ptfIp,
            'dut_ssh': dutIp,
            'dut_username': creds['sonicadmin_user'],
            'dut_password': creds['sonicadmin_password'],
            "alt_password": sonicadmin_alt_password,
            'config_file': VXLAN_CONFIG_FILE,
            'how_long': testDuration,
            'advance': True,
        },
        log_file='/tmp/wr_arp.ArpTest.Advance.log',
        is_python3=True
    )
