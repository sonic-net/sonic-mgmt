import logging
import pytest
import time

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm
from .files.pfcwd_helper import start_wd_on_ports

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope='module', autouse=True)
def stop_pfcwd(duthosts, rand_one_dut_hostname):
    """
    Fixture that stops PFC Watchdog before each test run

    Args:
        duthost (AnsibleHost): DUT instance
    """
    duthost = duthosts[rand_one_dut_hostname]
    logger.info("--- Stop Pfcwd --")
    duthost.command("pfcwd stop")

@pytest.fixture(autouse=True)
def ignore_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    """
    Fixture that ignores expected failures during test execution.

    Args:
        duthost (AnsibleHost): DUT instance
        loganalyzer (loganalyzer): Loganalyzer utility fixture
    """
    if loganalyzer:
        ignoreRegex = [
            ".*ERR syncd#syncd: :- process_on_fdb_event: invalid OIDs in fdb notifications, NOT translating and NOT storing in ASIC DB.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: FDB notification was not sent since it contain invalid OIDs, bug.*"
        ]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

    yield

@pytest.fixture(scope='class', autouse=True)
def pfcwd_timer_setup_restore(setup_pfc_test, fanout_graph_facts, duthosts, rand_one_dut_hostname, fanouthosts):
    """
    Fixture that inits the test vars, start PFCwd on ports and cleans up after the test run

    Args:
        setup_pfc_test (fixture): module scoped, autouse PFC fixture
        fanout_graph_facts (fixture): fanout graph info
        duthost (AnsibleHost): DUT instance
        fanouthosts (AnsibleHost): fanout instance

    Yields:
        timers (dict): pfcwd timer values
        storm_handle (PFCStorm): class PFCStorm instance
    """
    duthost = duthosts[rand_one_dut_hostname]
    logger.info("--- Pfcwd timer test setup ---")
    setup_info = setup_pfc_test
    test_ports = setup_info['test_ports']
    timers = setup_info['pfc_timers']
    eth0_ip = setup_info['eth0_ip']
    pfc_wd_test_port = test_ports.keys()[0]
    neighbors = setup_info['neighbors']
    fanout_info = fanout_graph_facts
    dut = duthost
    fanout = fanouthosts
    peer_params = populate_peer_info(neighbors, fanout_info, pfc_wd_test_port)
    storm_handle = set_storm_params(dut, fanout_info, fanout, peer_params)
    timers['pfc_wd_restore_time'] = 400
    start_wd_on_ports(dut, pfc_wd_test_port, timers['pfc_wd_restore_time'],
                      timers['pfc_wd_detect_time'])
    # enable routing from mgmt interface to localhost
    dut.sysctl(name="net.ipv4.conf.eth0.route_localnet", value=1, sysctl_set=True)
    # rule to forward syslog packets from mgmt interface to localhost
    syslog_ip = duthost.get_rsyslog_ipv4()
    dut.iptables(action="insert", chain="PREROUTING", table="nat", protocol="udp",
                 destination=eth0_ip, destination_port=514, jump="DNAT",
                 to_destination="{}:514".format(syslog_ip))

    logger.info("--- Pfcwd Timer Testrun ---")
    yield { 'timers' : timers,
            'storm_handle': storm_handle
          }

    logger.info("--- Pfcwd timer test cleanup ---")
    dut.iptables(table="nat", flush="yes")
    dut.sysctl(name="net.ipv4.conf.eth0.route_localnet", value=0, sysctl_set=True)
    storm_handle.stop_storm()

def populate_peer_info(neighbors, fanout_info, port):
    """
    Build the peer_info map which will be used by the storm generation class

    Args:
        neighbors (dict): fanout info for each DUT port
        fanout_info (dict): fanout graph info
        port (string): test port

    Returns:
        peer_info (dict): all PFC params needed for fanout for storm generation
    """
    peer_dev = neighbors[port]['peerdevice']
    peer_port = neighbors[port]['peerport']
    peer_info = {'peerdevice': peer_dev,
                 'hwsku': fanout_info[peer_dev]['device_info']['HwSku'],
                 'pfc_fanout_interface': peer_port
                }
    return peer_info

def set_storm_params(dut, fanout_info, fanout, peer_params):
    """
    Setup storm parameters

    Args:
        dut (AnsibleHost): DUT instance
        fanout_info (fixture): fanout graph info
        fanout (AnsibleHost): fanout instance
        peer_params (dict): all PFC params needed for fanout for storm generation

    Returns:
        storm_handle (PFCStorm): class PFCStorm intance
    """
    logger.info("Setting up storm params")
    pfc_queue_index = 4
    pfc_frames_count = 300000
    storm_handle = PFCStorm(dut, fanout_info, fanout, pfc_queue_idx=pfc_queue_index,
                           pfc_frames_number=pfc_frames_count, peer_info=peer_params)
    storm_handle.deploy_pfc_gen()
    return storm_handle

@pytest.mark.usefixtures('pfcwd_timer_setup_restore')
class TestPfcwdAllTimer(object):
    """ PFCwd timer test class """
    def run_test(self):
        """
        Test execution
        """
        logger.info("Flush logs")
        self.dut.shell("logrotate -f /etc/logrotate.conf")
        self.storm_handle.start_storm()
        logger.info("Wait for queue to recover from PFC storm")
        time.sleep(8)

        storm_start_ms = self.retrieve_timestamp("[P]FC_STORM_START")
        storm_detect_ms = self.retrieve_timestamp("[d]etected PFC storm")
        logger.info("Wait for PFC storm end marker to appear in logs")
        time.sleep(1)
        storm_end_ms = self.retrieve_timestamp("[P]FC_STORM_END")
        storm_restore_ms = self.retrieve_timestamp("[s]torm restored")
        real_detect_time = storm_detect_ms - storm_start_ms
        real_restore_time = storm_restore_ms - storm_end_ms
        self.all_detect_time.append(real_detect_time)
        self.all_restore_time.append(real_restore_time)

    def verify_pfcwd_timers(self):
        """
        Compare the timestamps obtained and verify the timer accuracy
        """
        self.all_detect_time.sort()
        self.all_restore_time.sort()
        logger.info("Verify that real detection time is not greater than configured")
        config_detect_time = self.timers['pfc_wd_detect_time'] + self.timers['pfc_wd_poll_time']
        err_msg = ("Real detection time is greater than configured: Real detect time: {} "
                   "Expected: {} (wd_detect_time + wd_poll_time)".format(self.all_detect_time[9],
                                                                         config_detect_time))
        pytest_assert(self.all_detect_time[9] < config_detect_time, err_msg)

        logger.info("Verify that real detection time is not less than configured")
        err_msg = ("Real detection time is less than configured: Real detect time: {} "
                   "Expected: {} (wd_detect_time)".format(self.all_detect_time[9],
                                                          self.timers['pfc_wd_detect_time']))
        pytest_assert(self.all_detect_time[9] > self.timers['pfc_wd_detect_time'], err_msg)

        logger.info("Verify that real restoration time is not less than configured")
        err_msg = ("Real restoration time is less than configured: Real restore time: {} "
                   "Expected: {} (wd_restore_time)".format(self.all_restore_time[9],
                                                           self.timers['pfc_wd_restore_time']))
        pytest_assert(self.all_restore_time[9] > self.timers['pfc_wd_restore_time'], err_msg)

        logger.info("Verify that real restoration time is less than configured")
        config_restore_time = self.timers['pfc_wd_restore_time'] + self.timers['pfc_wd_poll_time']
        err_msg = ("Real restoration time is greater than configured: Real restore time: {} "
                   "Expected: {} (wd_restore_time + wd_poll_time)".format(self.all_restore_time[9],
                                                                          config_restore_time))
        pytest_assert(self.all_restore_time[9] < config_restore_time, err_msg)

    def retrieve_timestamp(self, pattern):
        """
        Retreives the syslog timestamp in ms associated with the pattern

        Args:
            pattern (string): pattern to be searched in the syslog

        Returns:
            timestamp_ms (int): syslog timestamp in ms for the line matching the pattern
        """
        cmd = "grep \"{}\" /var/log/syslog".format(pattern)
        syslog_msg =self.dut.shell(cmd)['stdout']
        timestamp = syslog_msg.replace('  ', ' ').split(' ')[2]
        timestamp_ms = self.dut.shell("date -d {} +%s%3N".format(timestamp))['stdout']
        return int(timestamp_ms)

    def test_pfcwd_timer_accuracy(self, duthosts, rand_one_dut_hostname, pfcwd_timer_setup_restore):
        """
        Tests PFCwd timer accuracy

        Args:
            duthost (AnsibleHost): DUT instance
            pfcwd_timer_setup_restore (fixture): class scoped autouse setup fixture
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup_info = pfcwd_timer_setup_restore
        self.storm_handle = setup_info['storm_handle']
        self.timers = setup_info['timers']
        self.dut = duthost
        self.all_detect_time = list()
        self.all_restore_time = list()
        try:
            for i in xrange(1, 20):
                logger.info("--- Pfcwd Timer Test iteration #{}".format(i))
                self.run_test()
            self.verify_pfcwd_timers()

        except Exception as e:
            pytest.fail(str(e))

        finally:
            if self.storm_handle:
                self.storm_handle.stop_storm()
