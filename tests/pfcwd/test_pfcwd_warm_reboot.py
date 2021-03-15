import datetime
import logging
import os
import pytest
import random
import time
import traceback

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.reboot import reboot
from tests.common.reboot import DUT_ACTIVE
from tests.common.utilities import InterruptableThread
from tests.common.utilities import join_all
from tests.ptf_runner import ptf_runner

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
EXPECT_PFC_WD_DETECT_RE = ".* detected PFC storm .*"
EXPECT_PFC_WD_RESTORE_RE = ".*storm restored.*"
TESTCASE_INFO = {'no_storm': { 'test_sequence': ["detect", "restore", "warm-reboot", "detect", "restore"],
                               'desc': "Test PFC storm detect/restore before and after warm boot" },
                 'storm': { 'test_sequence': ["detect", "warm-reboot", "detect", "restore"],
                            'desc': "Test PFC storm detect with on going storm after warm boot followed by restore" },
                 'async_storm': { 'test_sequence': ["storm_defer", "warm-reboot", "detect", "restore"],
                                  'desc': "Test PFC async storm start/end with warm boot followed by detect/restore" }
                }
ACTIONS = { 'detect': 0,
            'restore': 1,
            'storm_defer': 2
          }

pytestmark = [pytest.mark.disable_loganalyzer,
              pytest.mark.topology('t0')
             ]

logger = logging.getLogger(__name__)

@pytest.fixture(autouse=True)
def setup_pfcwd(duthosts, rand_one_dut_hostname):
    """
    Setup PFCwd before the test run

    Args:
        duthost(AnsibleHost) : dut instance
    """
    duthost = duthosts[rand_one_dut_hostname]
    logger.info("Setup the default pfcwd config for warm-reboot test")
    duthost.command("redis-cli -n 4 hset \"DEVICE_METADATA|localhost\" "
                    "default_pfcwd_status enable")
    duthost.command("pfcwd stop")
    time.sleep(5)
    duthost.command("pfcwd start_default")

class PfcCmd(object):
    @staticmethod
    def set_storm_status(dut, queue_oid, storm_status):
        """
        Sets the PFC storm status on the queue

        Args:
            dut(AnsibleHost) : dut instance
            queue_oid(string) : queue oid for which the storm status needs to be set
            storm_status(string) : debug storm status (enabled/disabled)
        """
        cmd = "redis-cli -n 2 HSET COUNTERS:{} DEBUG_STORM {}"
        dut.command(cmd.format(queue_oid, storm_status))

    @staticmethod
    def get_queue_oid(dut, port, queue_num):
        """
        Retreive queue oid

        Args:
            dut(AnsibleHost) : dut instance
            port(string) : port name
            queue_num(int) : queue number

        Returns:
            queue oid(string)
        """
        cmd = "redis-cli -n 2 HGET COUNTERS_QUEUE_NAME_MAP {}:{}".format(port, queue_num)
        return dut.command(cmd)['stdout']


class SetupPfcwdFunc(object):
    """ Test setup per port """
    def setup_test_params(self, port, vlan, idx):
        """
        Sets up test parameters associated with a DUT port

        Args:
            port(string) : DUT port
            vlan(dict) : DUT vlan info
        """
        logger.info("--- Setting up test params for port {} ---".format(port))
        self.setup_port_params(port, idx)
        self.resolve_arp(vlan)

    def setup_port_params(self, port, idx):
        """
        Gather all the parameters needed for storm generation and ptf test based off the DUT port

        Args:
            port(string) : DUT port
        """
        self.pfc_wd = dict()
        self.pfc_wd['queue_indices'] = [4]
        if (self.seed % 2) != 0:
            self.pfc_wd['queue_indices'].append(3)
        self.pfc_wd['test_pkt_count'] = 100
        self.pfc_wd['frames_number'] = 10000000000000
        self.peer_device = self.ports[port]['peer_device']
        self.pfc_wd['test_port'] = port
        self.pfc_wd['rx_port'] = self.ports[port]['rx_port']
        self.pfc_wd['test_neighbor_addr'] = self.ports[port]['test_neighbor_addr']
        self.pfc_wd['rx_neighbor_addr'] = self.ports[port]['rx_neighbor_addr']
        self.pfc_wd['test_port_id'] = self.ports[port]['test_port_id']
        self.pfc_wd['rx_port_id'] = self.ports[port]['rx_port_id']
        self.pfc_wd['port_type'] = self.ports[port]['test_port_type']
        self.pfc_wd['test_port_ids'] = list()
        if self.pfc_wd['port_type'] == "portchannel":
            self.pfc_wd['test_port_ids'] = self.ports[port]['test_portchannel_members']
        elif self.pfc_wd['port_type'] in ["vlan", "interface"]:
            self.pfc_wd['test_port_ids'] = [self.pfc_wd['test_port_id']]
        self.pfc_wd['fake_storm'] = False if not idx else self.fake_storm

    def resolve_arp(self, vlan):
        """
        Populate ARP info for the DUT vlan port

        Args:
            vlan(dict) : DUT vlan info
        """
        if self.pfc_wd['port_type'] == "vlan":
            self.ptf.script("./scripts/remove_ip.sh")
            self.ptf.command("ifconfig eth{} {}".format(self.pfc_wd['test_port_id'],
                                                        self.pfc_wd['test_neighbor_addr']))
            self.ptf.command("ping {} -c 10".format(vlan['addr']))
            self.dut.command("docker exec -i swss arping {} -c 5".format(self.pfc_wd['test_neighbor_addr']))

    def storm_defer_setup(self):
        """
        Set the defer start and stop values and calculate the max wait time

        Max wait time will be used after warm boot to wait for all the storms to end prior
        to starting the next detect
        """
        self.pfc_wd['storm_start_defer'] = random.randrange(120)
        self.pfc_wd['storm_stop_defer'] = random.randrange(self.pfc_wd['storm_start_defer'] + 5, 125)
        self.max_wait = max(self.max_wait, self.pfc_wd['storm_stop_defer'])

    def storm_setup(self, port, queue, storm_defer=False):
        """
        Prepare fanout for the storm generation

        Args:
            port(string) : DUT port
            queue(int): The queue on the DUT port which will get stormed
            storm_defer(bool): if the storm needs to be deferred, default: False
        """
        peer_info = {'peerdevice': self.peer_device,
                     'hwsku': self.fanout_info[self.peer_device]['device_info']['HwSku'],
                     'pfc_fanout_interface': self.neighbors[port]['peerport']
                    }

        if storm_defer:
            self.storm_handle[port][queue] = PFCStorm(self.dut, self.fanout_info, self.fanout,
                                                      pfc_queue_idx=queue,
                                                      pfc_frames_number=self.pfc_wd['frames_number'],
                                                      peer_info=peer_info,
                                                      pfc_storm_defer_time=self.pfc_wd['storm_start_defer'],
                                                      pfc_storm_stop_defer_time=self.pfc_wd['storm_stop_defer'])
        else:
            self.storm_handle[port][queue] = PFCStorm(self.dut, self.fanout_info, self.fanout,
                                                      pfc_queue_idx=queue,
                                                      pfc_frames_number=self.pfc_wd['frames_number'],
                                                      peer_info=peer_info)
        # new peer device
        if not self.peer_dev_list or self.peer_device not in self.peer_dev_list:
            self.peer_dev_list[self.peer_device] = peer_info['hwsku']
            self.storm_handle[port][queue].deploy_pfc_gen()


class SendVerifyTraffic(object):
    """ PTF test """
    def __init__(self, ptf, router_mac, pfc_params, queue):
        """
        Args:
            ptf(AnsibleHost) : ptf instance
            router_mac(string) : router mac address
            ptf_params(dict) : all PFC test params specific to the DUT port
            queue(int): queue to check the wd action
        """
        self.ptf = ptf
        self.router_mac = router_mac
        self.pfc_wd_test_pkt_count = pfc_params['test_pkt_count']
        self.pfc_wd_rx_port_id = pfc_params['rx_port_id']
        self.pfc_wd_test_port =  pfc_params['test_port']
        self.pfc_wd_test_port_id = pfc_params['test_port_id']
        self.pfc_wd_test_port_ids = pfc_params['test_port_ids']
        self.pfc_wd_test_neighbor_addr = pfc_params['test_neighbor_addr']
        self.pfc_wd_rx_neighbor_addr = pfc_params['rx_neighbor_addr']
        self.port_type = pfc_params['port_type']
        self.queue = queue

    def verify_tx_egress(self, wd_action):
        """
        Send traffic with test port as the egress and verify if the packets get forwarded
        or dropped based on the action

        Args:
            wd_action(string): pfcwd action expected on that port and queue (valid values: drop, forward)
        """
        logger.info("Check for egress {} on Tx port {}".format(wd_action, self.pfc_wd_test_port))
        dst_port = "[" + str(self.pfc_wd_test_port_id) + "]"
        if wd_action == "forward" and  type(self.pfc_wd_test_port_ids) == list:
            dst_port = "".join(str(self.pfc_wd_test_port_ids)).replace(',', '')
        ptf_params = {'router_mac': self.router_mac,
                      'queue_index': self.queue,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_rx_port_id[0],
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_test_neighbor_addr,
                      'port_type': self.port_type,
                      'wd_action': wd_action}
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file)

    def verify_rx_ingress(self, wd_action):
        """
        Send traffic with test port as the ingress and verify if the packets get forwarded
        or dropped based on the action

        Args:
            wd_action(string): pfcwd action expected on that port and queue (valid values: drop, forward)
        """
        logger.info("Check for ingress {} on Rx port {}".format(wd_action, self.pfc_wd_test_port))
        if type(self.pfc_wd_rx_port_id) == list:
            dst_port = "".join(str(self.pfc_wd_rx_port_id)).replace(',', '')
        else:
            dst_port = "[ " + str(self.pfc_wd_rx_port_id) + " ]"
        ptf_params = {'router_mac': self.router_mac,
                      'queue_index': self.queue,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_test_port_id,
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_rx_neighbor_addr,
                      'port_type': self.port_type,
                      'wd_action': wd_action}
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file)

    def verify_wd_func(self, detect=True):
        """
        PTF traffic send and verify

        Args:
            detect(bool) : if the current iteration is a storm detect or not (default: True)
        """
        if detect:
            wd_action="drop"
        else:
            wd_action = "forward"
        logger.info("--- Verify PFCwd function for action {} ---".format(wd_action))
        self.verify_tx_egress(wd_action)
        self.verify_rx_ingress(wd_action)


class TestPfcwdWb(SetupPfcwdFunc):
    """ Test PFCwd warm-reboot function and supporting methods """
    def storm_detect_path(self, port, queue, first_detect_after_wb=False):
        """
        Storm detection action and associated verifications

        Args:
            port(string) : DUT port
            queue(int): queue on the port that will be stormed
            first_detect_after_wb(bool): first detect iteration after warm reboot (default: False)
        """
        # for the first iteration after wb, do not write a marker to the log but specify the start msg from
        # where to search the logs
        start_marker = None
        if first_detect_after_wb:
            start_marker = "NOTICE swss#orchagent: :- setWarmStartState: orchagent warm start state changed to initialized"
        self.loganalyzer = LogAnalyzer(ansible_host=self.dut,
                                       marker_prefix="pfcwd_wb_storm_detect_port_{}_queue_{}".format(port, queue),
                                       start_marker=start_marker)
        marker = self.loganalyzer.init()
        time.sleep(5)
        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_pfc_wd_messages")
        reg_exp = self.loganalyzer.parse_regexp_file(src=ignore_file)
        self.loganalyzer.ignore_regex.extend(reg_exp)
        self.loganalyzer.expect_regex = []
        self.loganalyzer.expect_regex.extend([EXPECT_PFC_WD_DETECT_RE])
        self.loganalyzer.match_regex = []

        # ongoing storm. no need to start a new one
        if not first_detect_after_wb:
            if not self.pfc_wd['fake_storm']:
                self.storm_handle[port][queue].start_storm()
                time.sleep(15 * len(self.pfc_wd['queue_indices']))
            else:
                PfcCmd.set_storm_status(self.dut, self.oid_map[(port, queue)], "enabled")
                time.sleep(5)
        else:
            # for the first iteration after wb, check the log for detect msgs for the ongoing storms
            self.loganalyzer.expected_matches_target = len(self.ports) * len(self.pfc_wd['queue_indices'])
            time.sleep(20)

        # storm detect check
        logger.info("Verify if PFC storm is detected on port {} queue {}".format(port, queue))
        self.loganalyzer.analyze(marker)

    def storm_restore_path(self, port, queue):
        """
        Storm restoration action and associated verifications

        Args:
            port(string) : DUT port
            queue(int): queue on the port where storm would be restored
        """
        marker = self.loganalyzer.update_marker_prefix("pfcwd_wb_storm_restore_port_{}_queue_{}".format(port, queue))
        time.sleep(5)
        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_pfc_wd_messages")
        reg_exp = self.loganalyzer.parse_regexp_file(src=ignore_file)
        self.loganalyzer.ignore_regex.extend(reg_exp)
        self.loganalyzer.expect_regex = []
        self.loganalyzer.expect_regex.extend([EXPECT_PFC_WD_RESTORE_RE])
        self.loganalyzer.match_regex = []
        self.loganalyzer.expected_matches_target = 0

        if not self.pfc_wd['fake_storm']:
            self.storm_handle[port][queue].stop_storm()
            time.sleep(15)
        else:
            PfcCmd.set_storm_status(self.dut, self.oid_map[(port, queue)], "disabled")
            time.sleep(5)

        # storm restore check
        logger.info("Verify if PFC storm is restored on port {}".format(port))
        self.loganalyzer.analyze(marker)

    def defer_fake_storm(self, port, queue, start_defer, stop_defer):
        time.sleep(start_defer)
        DUT_ACTIVE.wait()
        PfcCmd.set_storm_status(self.dut, self.oid_map[(port, queue)], "enabled")
        time.sleep(stop_defer)
        DUT_ACTIVE.wait()
        PfcCmd.set_storm_status(self.dut, self.oid_map[(port, queue)], "disabled")

    def run_test(self, port, queue, detect=True, storm_start=True, first_detect_after_wb=False,
                 storm_defer=False):
        """
        Test method that invokes the storm detection and restoration path which includes the traffic
        test

        Args:
            port(string) : DUT port
            queue(int): queue on the port which would be stormed/restored
            detect(bool): if the detect logic needs to be called (default: True)
            storm_start(bool): used to decide certain actions in the detect logic (default: True)
            first_detect_after_wb(bool): used to decide certain actions in the detect logic (default: False)
            storm_defer(bool): use the storm defer logic or not (default: False)
        """
        # for deferred storm, return to main loop for next action which is warm boot
        if storm_defer:
            if not self.pfc_wd['fake_storm']:
                self.storm_handle[port][queue].start_storm()
                self.storm_handle[port][queue].stop_storm()
            else:
                thread = InterruptableThread(
                    target=self.defer_fake_storm,
                    args=(port, queue, self.pfc_wd['storm_start_defer'],
                          self.pfc_wd['storm_stop_defer']))
                thread.daemon = True
                thread.start()
                self.storm_threads.append(thread)
            return

        if detect:
            if storm_start or first_detect_after_wb:
                logger.info("--- Storm detection path for port {} queue {} ---".format(port, queue))
                self.storm_detect_path(port, queue, first_detect_after_wb=first_detect_after_wb)
        else:
            logger.info("--- Storm restoration path for port {} queue {} ---".format(port, queue))
            self.storm_restore_path(port, queue)
        # test pfcwd functionality on a storm/restore
        self.traffic_inst.verify_wd_func(detect=detect)

    @pytest.fixture(autouse=True)
    def pfcwd_wb_test_cleanup(self):
        """
        Cleanup method
        """
        yield

        # stop all threads that might stuck in wait
        DUT_ACTIVE.set()
        for thread in self.storm_threads:
            thread_exception = thread.join(timeout=0.1,
                                           suppress_exception=True)
            if thread_exception:
                logger.debug("Exception in thread %r:", thread)
                logger.debug(
                    "".join(traceback.format_exception(*thread_exception))
                    )
        self.stop_all_storm()
        time.sleep(5)
        logger.info("--- Stop PFC WD ---")
        self.dut.command("pfcwd stop")

    def stop_all_storm(self):
        """
        Stop all the storms after each test run
        """
        if self.storm_handle:
            logger.info("--- Stopping storm on all ports ---")
            for port in self.storm_handle:
                for queue in self.storm_handle[port]:
                    if self.storm_handle[port][queue]:
                        logger.info("--- Stop pfc storm on port {} queue {}".format(port, queue))
                        self.storm_handle[port][queue].stop_storm()
                    else:
                        logger.info("--- Disabling fake storm on port {} queue {}".format(port, queue))
                        PfcCmd.set_storm_status(self.dut, self.oid_map[(port, queue)], "disabled")

    def pfcwd_wb_helper(self, fake_storm, testcase_actions, setup_pfc_test, fanout_graph_facts, ptfhost,
                        duthost, localhost, fanouthosts):
        """
        Helper method that initializes the vars and starts the test execution

        Args:
            fake_storm(bool): if fake storm is enabled or disabled
            testcase_actions(list): list of actions that the test will go through
            setup_pfc_test(fixture): module scoped autouse fixture
            fanout_graph_facts(fixture): fanout info
            ptfhost(AnsibleHost): PTF instance
            duthost(AnsibleHost): DUT instance
            localhost(AnsibleHost): local instance
            fanouthosts(AnsibleHost): fanout instance
        """
        setup_info = setup_pfc_test
        self.fanout_info = fanout_graph_facts
        self.ptf = ptfhost
        self.dut = duthost
        self.fanout = fanouthosts
        self.timers = setup_info['pfc_timers']
        self.ports = setup_info['selected_test_ports']
        self.neighbors = setup_info['neighbors']
        dut_facts = self.dut.facts
        self.peer_dev_list = dict()
        self.seed = int(datetime.datetime.today().day)
        self.storm_handle = dict()
        bitmask = 0
        storm_deferred = 0
        storm_restored = 0
        self.max_wait = 0
        self.fake_storm = fake_storm
        self.oid_map = dict()
        self.storm_threads = []

        for t_idx, test_action in enumerate(testcase_actions):
            if 'warm-reboot' in test_action:
                reboot(self.dut, localhost, reboot_type="warm")
                continue

            # one of the factors to decide if the storm needs to be started
            storm_restored = bitmask and (bitmask & 2)
            # if the action prior to the warm-reboot was a 'storm_defer', ensure that all the storms are
            # stopped
            storm_deferred = bitmask and (bitmask & 4)
            if storm_deferred:
                logger.info("Wait for all the deferred storms to start and stop ...")
                join_all(self.storm_threads, self.max_wait)
                self.storm_threads = []
                self.storm_handle = dict()

            bitmask = (1 << ACTIONS[test_action])
            for p_idx, port in enumerate(self.ports):
                logger.info("")
                logger.info("--- Testing on {} ---".format(port))
                self.setup_test_params(port, setup_info['vlan'], p_idx)
                for q_idx, queue in enumerate(self.pfc_wd['queue_indices']):
                    if not t_idx or storm_deferred:
                        if not q_idx:
                            self.storm_handle[port] = dict()
                        self.storm_handle[port][queue] = None

                        # setup the defer parameters if the storm is deferred currently
                        if (bitmask & 4):
                            self.storm_defer_setup()

                        if not self.pfc_wd['fake_storm']:
                            self.storm_setup(port, queue, storm_defer=(bitmask & 4))
                        else:
                            self.oid_map[(port, queue)] = PfcCmd.get_queue_oid(self.dut, port, queue)

                    self.traffic_inst = SendVerifyTraffic(self.ptf, dut_facts['router_mac'], self.pfc_wd, queue)
                    self.run_test(port, queue, detect=(bitmask & 1),
                                  storm_start=not t_idx or storm_deferred or storm_restored,
                                  first_detect_after_wb=(t_idx == 2 and not p_idx and not q_idx and not storm_deferred),
                                  storm_defer=(bitmask & 4))

    @pytest.fixture(params=['no_storm', 'storm', 'async_storm'])
    def testcase_action(self, request):
        """
        Parameters to invoke the pfcwd warm boot test

        Args:
            request(pytest) : pytest request object

        Yields:
            testcase_action(string) : testcase to execute
        """
        yield request.param

    def test_pfcwd_wb(self, fake_storm, testcase_action, setup_pfc_test, fanout_graph_facts, ptfhost, duthosts, rand_one_dut_hostname, localhost, fanouthosts):
        """
        Tests PFCwd warm reboot with various testcase actions

        Args:
            fake_storm(fixture): fake storm status
            testcase_action(fixture): testcase to execute (values: 'no_storm', 'storm', 'async_storm')

                'no_storm' : PFCwd storm detection/restore before and after warm reboot
                'storm' : PFC storm started and detected before warm-reboot. Storm is ongoing during warm boot and lasts
                          past the warm boot finish. Verifies if the storm is detected after warm-reboot.
                          PFC storm is stopped and 465 restored after warm boot
                'async_storm': PFC storm asynchronously starts at a random time and lasts a random period at fanout.
                               Warm reboot is done. Wait for all the storms to finish and then verify the storm detect/restore
                               logic

            setup_pfc_test(fixture) : Module scoped autouse fixture for PFCwd
            fanout_graph_facts(fixture) : fanout graph info
            ptfhost(AnsibleHost) : ptf host instance
            duthost(AnsibleHost) : DUT instance
            localhost(AnsibleHost) : localhost instance
            fanouthosts(AnsibleHost): fanout instance
        """
        duthost = duthosts[rand_one_dut_hostname]
        logger.info("--- {} ---".format(TESTCASE_INFO[testcase_action]['desc']))
        self.pfcwd_wb_helper(fake_storm, TESTCASE_INFO[testcase_action]['test_sequence'], setup_pfc_test,
                             fanout_graph_facts, ptfhost, duthost, localhost, fanouthosts)
