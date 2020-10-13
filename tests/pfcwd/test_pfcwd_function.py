import datetime
import logging
import os
import pytest
import time

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from .files.pfcwd_helper import start_wd_on_ports
from tests.ptf_runner import ptf_runner

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
EXPECT_PFC_WD_DETECT_RE = ".* detected PFC storm .*"
EXPECT_PFC_WD_RESTORE_RE = ".*storm restored.*"
WD_ACTION_MSG_PFX = { "dontcare": "Verify PFCWD detection when queue buffer is not empty and proper function of drop action",
                      "drop": "Verify proper function of drop action",
                      "forward": "Verify proper function of forward action"
                    }

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope='function', autouse=True)
def stop_pfcwd(duthost):
    """
    Fixture that stops PFC Watchdog before each test run

    Args:
        duthost(AnsibleHost) : dut instance
    """
    logger.info("--- Stop Pfcwd --")
    duthost.command("pfcwd stop")

class PfcCmd(object):
    @staticmethod
    def counter_cmd(dut, queue_oid, attr):
        """
        Retreive queue counters

        Args:
            dut(AnsibleHost) : dut instance
            queue_oid(string) : queue oid for which the counter value needs to be retreived
            attr(string) : counter name

        Returns:
            counter value(string)
        """
        cmd = "redis-cli -n 2 HGET COUNTERS:{}"
        return dut.command("{} {}".format(cmd.format(queue_oid), attr))['stdout']

    @staticmethod
    def set_storm_status(dut, queue_oid, storm_status):
        """
        Sets PFC storm status for the queue

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

class PfcPktCntrs(object):
    """ PFCwd counter retrieval and verifications  """
    def __init__(self, dut, action):
       """
       Args:
           dut(AnsibleHost) : dut instance
           action(string): PFCwd action for traffic test
       """
       self.dut = dut
       self.action = action if action != "dontcare" else "drop"
       if self.action != "forward":
           self.pkt_cntrs_tx = ['PFC_WD_QUEUE_STATS_TX_DROPPED_PACKETS', 'PFC_WD_QUEUE_STATS_TX_DROPPED_PACKETS_LAST']
           self.pkt_cntrs_rx = ['PFC_WD_QUEUE_STATS_RX_DROPPED_PACKETS', 'PFC_WD_QUEUE_STATS_RX_DROPPED_PACKETS_LAST']
           self.err_msg_tx = [("Tx drop cnt check failed: Tx drop before: {}  Tx drop after: {} "
                               "Expected (diff): {} Obtained: {}"),
                               "Tx drop last cnt check failed: Expected: {} Obtained: {}"
                             ]
           self.err_msg_rx = [("Rx drop cnt check failed: Rx drop before: {}  Rx drop after: {} "
                               "Expected (diff): {} Obtained: {}"),
                               "Rx drop last cnt check failed: Expected: {} Obtained: {}"
                             ]
       else:
           self.pkt_cntrs_tx = ['PFC_WD_QUEUE_STATS_TX_PACKETS', 'PFC_WD_QUEUE_STATS_TX_PACKETS_LAST']
           self.pkt_cntrs_rx = ['PFC_WD_QUEUE_STATS_RX_PACKETS', 'PFC_WD_QUEUE_STATS_RX_PACKETS_LAST']
           self.err_msg_tx = [("Tx forward cnt check failed: Tx forward before: {}  Tx forward after: {} "
                               "Expected (diff): {} Obtained: {}"),
                               "Tx forward last cnt check failed: Expected: {} Obtained: {}"
                             ]
           self.err_msg_rx = [("Rx forward cnt check failed: Rx forward before: {}  Rx forward after: {} "
                               "Expected (diff): {} Obtained: {}"),
                               "Rx forward last cnt check failed: Expected: {} Obtained: {}"
                             ]
       self.cntr_val = dict()

    def get_pkt_cnts(self, queue_oid, begin=True):
        """
        Retrieves the PFCwd counter values before and after the test

        Args:
            queue_oid(string) : queue oid
            begin(bool) : if the counter collection is before or after the test

        """
        test_state = ['end', 'begin']
        state = test_state[begin]
        self.cntr_val["tx_{}".format(state)] = int(PfcCmd.counter_cmd(self.dut, queue_oid, self.pkt_cntrs_tx[0]))
        self.cntr_val["rx_{}".format(state)] = int(PfcCmd.counter_cmd(self.dut, queue_oid, self.pkt_cntrs_rx[0]))

        if not begin:
            self.cntr_val["tx_last"] = int(PfcCmd.counter_cmd(self.dut, queue_oid, self.pkt_cntrs_tx[1]))
            self.cntr_val["rx_last"] = int(PfcCmd.counter_cmd(self.dut, queue_oid, self.pkt_cntrs_rx[1]))

    def verify_pkt_cnts(self, port_type, pkt_cnt):
        """
        Validate the packet cnts after the test

        Args:
            port_type(string) : the type of port (eg. portchannel, vlan, interface)
            pkt_cnt(int) : Number of test packets sent from the PTF
        """
        logger.info("--- Checking Tx {} cntrs ---".format(self.action))
        tx_diff = self.cntr_val["tx_end"] - self.cntr_val["tx_begin"]
        if (port_type in ['vlan', 'interface'] and tx_diff != pkt_cnt) or tx_diff <= 0:
            err_msg = self.err_msg_tx[0].format(self.cntr_val["tx_begin"], self.cntr_val["tx_end"], pkt_cnt, tx_diff)
            pytest_assert(err_msg)

        if (port_type in ['vlan', 'interface'] and self.cntr_val["tx_last"] != pkt_cnt) or self.cntr_val["tx_last"] <= 0:
            err_msg = self.err_msg_tx[1].format(pkt_cnt, self.cntr_val["tx_last"])
            pytest_assert(err_msg)

        logger.info("--- Checking Rx {} cntrs ---".format(self.action))
        rx_diff = self.cntr_val["rx_end"] - self.cntr_val["rx_begin"]
        if (port_type in ['vlan', 'interface'] and rx_diff != pkt_cnt) or rx_diff <= 0:
            err_msg = self.err_msg_rx[0].format(self.cntr_val["rx_begin"], self.cntr_val["rx_end"], pkt_cnt, rx_diff)
            pytest_assert(err_msg)

        if (port_type in ['vlan', 'interface'] and self.cntr_val["rx_last"] != pkt_cnt) or self.cntr_val["rx_last"] <= 0:
            err_msg = self.err_msg_rx[1].format(pkt_cnt, self.cntr_val["rx_last"])
            pytest_assert(err_msg)

class SetupPfcwdFunc(object):
    """ Test setup per port """
    def setup_test_params(self, port, vlan, init=False):
        """
        Sets up test parameters associated with a DUT port

        Args:
            port(string) : DUT port
            vlan(dict) : DUT vlan info
            init(bool) : If the fanout needs to be initialized or not
        """
        logger.info("--- Setting up test params for port {} ---".format(port))
        self.setup_port_params(port, init=init)
        self.resolve_arp(vlan)
        if not self.pfc_wd['fake_storm']:
            self.storm_setup(init=init)

    def setup_port_params(self, port, init=False):
         """
         Gather all the parameters needed for storm generation and ptf test based off the DUT port

         Args:
             port(string) : DUT port
         """
         self.pfc_wd = dict()
         self.pfc_wd['fake_storm'] = False if init else self.fake_storm
         self.pfc_wd['test_pkt_count'] = 100
         self.pfc_wd['queue_index'] = 4
         self.pfc_wd['frames_number'] = 100000000
         self.pfc_wd['test_port_ids'] = list()
         self.peer_device = self.ports[port]['peer_device']
         self.pfc_wd['test_port'] = port
         self.pfc_wd['rx_port'] = self.ports[port]['rx_port']
         self.pfc_wd['test_neighbor_addr'] = self.ports[port]['test_neighbor_addr']
         self.pfc_wd['rx_neighbor_addr'] = self.ports[port]['rx_neighbor_addr']
         self.pfc_wd['test_port_id'] = self.ports[port]['test_port_id']
         self.pfc_wd['rx_port_id'] = self.ports[port]['rx_port_id']
         self.pfc_wd['port_type'] = self.ports[port]['test_port_type']
         if self.pfc_wd['port_type'] == "portchannel":
             self.pfc_wd['test_port_ids'] = self.ports[port]['test_portchannel_members']
         elif self.pfc_wd['port_type'] in ["vlan", "interface"]:
             self.pfc_wd['test_port_ids'] = self.pfc_wd['test_port_id']
         self.queue_oid = PfcCmd.get_queue_oid(self.dut, port, self.pfc_wd['queue_index'])

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

    def storm_setup(self, init=False):
        """
        Prepare fanout for the storm generation

        Args:
            init(bool): if the storm class needs to be initialized or not
        """
        # new peer device
        if not self.peer_dev_list or self.peer_device not in self.peer_dev_list:
            peer_info = {'peerdevice': self.peer_device,
                         'hwsku': self.fanout_info[self.peer_device]['device_info']['HwSku'],
                         'pfc_fanout_interface': self.neighbors[self.pfc_wd['test_port']]['peerport']
                        }
            self.peer_dev_list[self.peer_device] = peer_info['hwsku']

            # get pfc storm handle
            if init:
                self.storm_hndle = PFCStorm(self.dut, self.fanout_info, self.fanout,
                                            pfc_queue_idx=self.pfc_wd['queue_index'],
                                            pfc_frames_number=self.pfc_wd['frames_number'],
                                            peer_info=peer_info)
            self.storm_hndle.update_peer_info(peer_info)
            self.storm_hndle.deploy_pfc_gen()

        # peer device already exists. only interface changes
        else:
            peer_info = {'peerdevice': self.peer_device,
                         'hwsku': self.peer_dev_list[self.peer_device],
                         'pfc_fanout_interface': self.neighbors[self.pfc_wd['test_port']]['peerport']
                        }

            self.storm_hndle.update_peer_info(peer_info)


class SendVerifyTraffic():
    """ PTF test """
    def __init__(self, ptf, eth0_mac, pfc_params):
        """
        Args:
            ptf(AnsibleHost) : ptf instance
            eth0_mac(string) : mac addr of eth0
            ptf_params(dict) : all PFC test params specific to the DUT port
        """
        self.ptf = ptf
        self.eth0_mac = eth0_mac
        self.pfc_queue_index = pfc_params['queue_index']
        self.pfc_wd_test_pkt_count = pfc_params['test_pkt_count']
        self.pfc_wd_rx_port_id = pfc_params['rx_port_id']
        self.pfc_wd_test_port =  pfc_params['test_port']
        self.pfc_wd_test_port_id = pfc_params['test_port_id']
        self.pfc_wd_test_port_ids = pfc_params['test_port_ids']
        self.pfc_wd_test_neighbor_addr = pfc_params['test_neighbor_addr']
        self.pfc_wd_rx_neighbor_addr = pfc_params['rx_neighbor_addr']
        self.port_type = pfc_params['port_type']

    def verify_tx_egress(self, action):
        """
        Send traffic with test port as the egress and verify if the packets get forwarded
        or dropped based on the action

        Args:
            action(string) : PTF test action
        """
        logger.info("Check for egress {} on Tx port {}".format(action, self.pfc_wd_test_port))
        dst_port = "[" + str(self.pfc_wd_test_port_id) + "]"
        if action == "forward" and  type(self.pfc_wd_test_port_ids) == list:
                dst_port = "".join(str(self.pfc_wd_test_port_ids)).replace(',', '')
        ptf_params = {'router_mac': self.eth0_mac,
                      'queue_index': self.pfc_queue_index,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_rx_port_id[0],
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_test_neighbor_addr,
                      'port_type': self.port_type,
                      'wd_action': action}
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file)

    def verify_rx_ingress(self, action):
        """
        Send traffic with test port as the ingress and verify if the packets get forwarded
        or dropped based on the action

        Args:
            action(string) : PTF test action
        """
        logger.info("Check for ingress {} on Rx port {}".format(action, self.pfc_wd_test_port))
        if type(self.pfc_wd_rx_port_id) == list:
            dst_port = "".join(str(self.pfc_wd_rx_port_id)).replace(',', '')
        else:
            dst_port = "[ " + str(self.pfc_wd_rx_port_id) + " ]"
        ptf_params = {'router_mac': self.eth0_mac,
                      'queue_index': self.pfc_queue_index,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_test_port_id,
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_rx_neighbor_addr,
                      'port_type': self.port_type,
                      'wd_action': action}
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file)

    def verify_other_pfc_queue(self):
        """
        Send traffic on the other PFC queue (not in storm) and verify that the packets get forwarded
        """
        logger.info("Send packets via {} to verify other PFC queue is not affected".format(self.pfc_wd_test_port))
        if type(self.pfc_wd_test_port_ids) == list:
            dst_port = "".join(str(self.pfc_wd_test_port_ids)).replace(',', '')
        else:
            dst_port = "[ " + str(self.pfc_wd_test_port_ids) + " ]"
        ptf_params = {'router_mac': self.eth0_mac,
                      'queue_index': self.pfc_queue_index - 1,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_rx_port_id[0],
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_test_neighbor_addr,
                      'port_type': self.port_type,
                      'wd_action': 'forward'}
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file)

    def verify_other_pfc_pg(self):
        """
        Send traffic on the other PFC PG (not in storm) and verify that the packets get forwarded
        """
        logger.info("Send packets to {} to verify other PFC pg is not affected".format(self.pfc_wd_test_port))
        if type(self.pfc_wd_rx_port_id) == list:
            dst_port = "".join(str(self.pfc_wd_rx_port_id)).replace(',', '')
        else:
            dst_port = "[ " + str(self.pfc_wd_rx_port_id) + " ]"
        ptf_params = {'router_mac': self.eth0_mac,
                      'queue_index': self.pfc_queue_index - 1,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_test_port_id,
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_rx_neighbor_addr,
                      'port_type': self.port_type,
                      'wd_action': 'forward'}
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file)

    def fill_buffer(self):
        """
        Send traffic to fill up the buffer. No verification
        """
        logger.info("Send packets to {} to fill up the buffer".format(self.pfc_wd_test_port))
        ptf_params = {'router_mac': self.eth0_mac,
                      'queue_index': self.pfc_queue_index,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_rx_port_id[0],
                      'port_dst': "[" + str(self.pfc_wd_test_port_id) + "]",
                      'ip_dst': self.pfc_wd_test_neighbor_addr,
                      'port_type': self.port_type,
                      'wd_action': 'dontcare'}
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file)

    def verify_wd_func(self, action):
        """
        PTF traffic send and verify

        Args:
            action(string) : PTF traffic test action
        """
        logger.info("--- Verify PFCwd function for action {} ---".format(action))
        self.verify_tx_egress(action)
        self.verify_rx_ingress(action)
        self.verify_other_pfc_queue()
        self.verify_other_pfc_pg()


class TestPfcwdFunc(SetupPfcwdFunc):
    """ Test PFC function and supporting methods """
    def storm_detect_path(self, dut, port, action):
        """
        Storm detection action and associated verifications

        Args:
            dut(AnsibleHost) : DUT instance
            port(string) : DUT port
            action(string) : PTF test action

        Returns:
            loganalyzer(Loganalyzer) : instance
        """
        restore_time = self.timers['pfc_wd_restore_time_large']
        detect_time = self.timers['pfc_wd_detect_time']

        loganalyzer = LogAnalyzer(ansible_host=self.dut,
                                  marker_prefix="pfc_function_storm_detect_{}_port_{}".format(action, port))
        marker = loganalyzer.init()
        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_pfc_wd_messages")
        reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
        loganalyzer.ignore_regex.extend(reg_exp)
        loganalyzer.expect_regex = []
        loganalyzer.expect_regex.extend([EXPECT_PFC_WD_DETECT_RE])
        loganalyzer.match_regex = []

        if action != "dontcare":
            start_wd_on_ports(dut, port, restore_time, detect_time, action)

        if not self.pfc_wd['fake_storm']:
            self.storm_hndle.start_storm()

        if action == "dontcare":
            self.traffic_inst.fill_buffer()
            start_wd_on_ports(dut, port, restore_time, detect_time, "drop")

        # placing this here to cover all action types. for 'dontcare' action, wd is started much later after the pfc storm is started
        if self.pfc_wd['fake_storm']:
            PfcCmd.set_storm_status(dut, self.queue_oid, "enabled")

        time.sleep(5)

        # storm detect
        logger.info("Verify if PFC storm is detected on port {}".format(port))
        loganalyzer.analyze(marker)
        self.stats.get_pkt_cnts(self.queue_oid, begin=True)
        # test pfcwd functionality on a storm
        self.traffic_inst.verify_wd_func(action if action != "dontcare" else "drop")
        return loganalyzer

    def storm_restore_path(self, dut, loganalyzer, port, action):
        """
        Storm restoration action and associated verifications

        Args:
            loganalyzer(Loganalyzer) : loganalyzer instance
            port(string) : DUT port
            action(string) : PTF test action
        """
        marker = loganalyzer.update_marker_prefix("pfc_function_storm_restore_{}_port_{}".format(action, port))
        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_pfc_wd_messages")
        reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
        loganalyzer.ignore_regex.extend(reg_exp)
        loganalyzer.expect_regex = []
        loganalyzer.expect_regex.extend([EXPECT_PFC_WD_RESTORE_RE])
        loganalyzer.match_regex = []

        if self.pfc_wd['fake_storm']:
            PfcCmd.set_storm_status(dut, self.queue_oid, "disabled")
        else:
            self.storm_hndle.stop_storm()
        time.sleep(self.timers['pfc_wd_wait_for_restore_time'])
        # storm restore
        logger.info("Verify if PFC storm is restored on port {}".format(port))
        loganalyzer.analyze(marker)
        self.stats.get_pkt_cnts(self.queue_oid, begin=False)

    def run_test(self, dut, port, action):
        """
        Test method that invokes the storm detection and restoration path which includes the traffic
        test and associated counter verifications

        Args:
            dut(AnsibleHost) : DUT instance
            port(string) : DUT port
            action(string) : PTF test action
        """
        logger.info("--- Storm detection path for port {} ---".format(port))
        loganalyzer = self.storm_detect_path(dut, port, action)
        logger.info("--- Storm restoration path for port {} ---".format(port))
        self.storm_restore_path(dut, loganalyzer, port, action)
        logger.info("--- Verify PFCwd counters for port {} ---".format(port))
        self.stats.verify_pkt_cnts(self.pfc_wd['port_type'], self.pfc_wd['test_pkt_count'])

    def test_pfcwd_actions(self, request, setup_pfc_test, fanout_graph_facts, ptfhost, duthost, fanouthosts):
        """
        PFCwd functional test

        Args:
            request(object) : pytest request object
            setup_pfc_test(fixture) : Module scoped autouse fixture for PFCwd
            fanout_graph_facts(fixture) : fanout graph info
            ptfhost(AnsibleHost) : ptf host instance
            duthost(AnsibleHost) : DUT instance
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
        dut_facts = self.dut.setup()['ansible_facts']
        self.peer_dev_list = dict()
        self.fake_storm = request.config.getoption("--fake-storm")

        for idx, port in enumerate(self.ports):
             self.storm_hndle = None
             logger.info("")
             logger.info("--- Testing various Pfcwd actions on {} ---".format(port))
             self.setup_test_params(port, setup_info['vlan'], init=not idx)
             self.traffic_inst = SendVerifyTraffic(self.ptf, dut_facts['ansible_eth0']['macaddress'], self.pfc_wd)
             pfc_wd_restore_time_large = request.config.getoption("--restore-time")
             # wait time before we check the logs for the 'restore' signature. 'pfc_wd_restore_time_large' is in ms.
             self.timers['pfc_wd_wait_for_restore_time'] = int(pfc_wd_restore_time_large / 1000 * 2)
             for action in ['dontcare', 'drop', 'forward']:
                 try:
                     self.stats = PfcPktCntrs(self.dut, action)
                     logger.info("{} on port {}".format(WD_ACTION_MSG_PFX[action], port))
                     self.run_test(self.dut, port, action)
                 except Exception as e:
                     pytest.fail(str(e))

                 finally:
                     if self.storm_hndle:
                         logger.info("--- Stop pfc storm on port {}".format(port))
                         self.storm_hndle.stop_storm()
                     else:
                         logger.info("--- Disabling fake storm on port {} queue {}".format(port, self.queue_oid))
                         PfcCmd.set_storm_status(self.dut, self.queue_oid, "disabled")
                     logger.info("--- Stop PFC WD ---")
                     self.dut.command("pfcwd stop")
