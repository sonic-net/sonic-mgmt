import datetime
import logging
import pytest
import time

from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts      # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm
from tests.common.helpers.pfcwd_helper import start_wd_on_ports
from tests.common.helpers.pfcwd_helper import has_neighbor_device
from tests.ptf_runner import ptf_runner
from tests.common import constants
from tests.common.dualtor.dual_tor_utils import is_tunnel_qos_remap_enabled, dualtor_ports # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m # noqa F401, E501
from tests.common.helpers.pfcwd_helper import send_background_traffic, check_pfc_storm_state, parser_show_pfcwd_stat
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology("t0", "t1")
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope='function', autouse=True)
def stop_pfcwd(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that stops PFC Watchdog before each test run

    Args:
        duthost(AnsibleHost) : dut instance
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("--- Stop Pfcwd --")
    duthost.command("pfcwd stop")

    yield
    logger.info("--- Start Pfcwd --")
    duthost.command("pfcwd start_default")


class SetupPfcwdFunc(object):
    def parse_test_port_info(self):
        """
        Parse the test port information into a dict
        {port_id: port_type}
        """
        self.port_id_to_type_map = dict()
        for _, v in self.test_ports_info.items():
            self.port_id_to_type_map[v['test_port_id']] = v['test_port_type']

    """ Test setup per port """
    def setup_test_params(self, port, vlan, init=False, detect=True):
        """
        Sets up test parameters associated with a DUT port

        Args:
            port(string) : DUT port
            vlan(dict) : DUT vlan info
            init(bool) : If the fanout needs to be initialized or not
        """
        logger.info("--- Setting up test params for port {} ---".format(port))
        self.parse_test_port_info()
        self.setup_port_params(port, init=init, detect=detect)
        self.resolve_arp(vlan, self.is_dualtor)
        self.storm_setup(init=init, detect=detect)

    def setup_port_params(self, port, init=False, detect=True):
        """
        Gather all the parameters needed for storm generation and ptf test based off the DUT port

        Args:
            port(string) : DUT port
        """
        self.pfc_wd = dict()
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
        self.pfc_wd['test_port_vlan_id'] = self.ports[port].get('test_port_vlan_id')
        self.pfc_wd['rx_port_vlan_id'] = self.ports[port].get('rx_port_vlan_id')
        self.pfc_wd['port_id_to_type_map'] = self.port_id_to_type_map
        self.queue_oid = self.dut.get_queue_oid(port, self.pfc_wd['queue_index'])

    def update_queue(self, port):
        """
        Switch between queue 3 and 4 during the test

        Args:
            port(string) : DUT port
        """
        if self.pfc_wd['queue_index'] == 4:
            self.pfc_wd['queue_index'] = self.pfc_wd['queue_index'] - 1
        else:
            self.pfc_wd['queue_index'] = self.pfc_wd['queue_index'] + 1
        logger.info("Current queue: {}".format(self.pfc_wd['queue_index']))
        self.queue_oid = self.dut.get_queue_oid(port, self.pfc_wd['queue_index'])

    def resolve_arp(self, vlan, is_dualtor=False):
        """
        Populate ARP info for the DUT vlan port

        Args:
            vlan(dict) : DUT vlan info
        """
        if self.pfc_wd['port_type'] == "vlan":
            self.ptf.script("./scripts/remove_ip.sh")
            ptf_port = 'eth%s' % self.pfc_wd['test_port_id']
            if self.pfc_wd['test_port_vlan_id'] is not None:
                ptf_port += (constants.VLAN_SUB_INTERFACE_SEPARATOR + self.pfc_wd['test_port_vlan_id'])
            self.ptf.command("ip neigh flush all")
            self.ptf.command("ip -6 neigh flush all")
            self.dut.command("ip neigh flush all")
            self.dut.command("ip -6 neigh flush all")
            self.ptf.command("ifconfig {} {}".format(ptf_port, self.pfc_wd['test_neighbor_addr']))
            self.ptf.command("ping {} -c 10".format(vlan['addr']))

            if is_dualtor:
                self.dut.command("docker exec -i swss arping {} -c 5".format(self.pfc_wd['test_neighbor_addr']), module_ignore_errors=True)  # noqa: E501
            else:
                self.dut.command("docker exec -i swss arping {} -c 5".format(self.pfc_wd['test_neighbor_addr']))

    def storm_setup(self, init=False, detect=True):
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

            if self.dut.topo_type == 't2' and self.fanout[self.peer_device].os == 'sonic':
                gen_file = 'pfc_gen_t2.py'
                pfc_send_time = 60
            else:
                gen_file = 'pfc_gen.py'
                pfc_send_time = None

            # get pfc storm handle
            if init and detect:
                self.storm_hndle = PFCStorm(self.dut, self.fanout_info, self.fanout,
                                            pfc_queue_idx=self.pfc_wd['queue_index'],
                                            pfc_frames_number=self.pfc_wd['frames_number'],
                                            pfc_send_period=pfc_send_time,
                                            pfc_gen_file=gen_file,
                                            peer_info=peer_info)
            self.storm_hndle.update_queue_index(self.pfc_wd['queue_index'])
            self.storm_hndle.update_peer_info(peer_info)
            self.storm_hndle.deploy_pfc_gen()

        # peer device already exists. only interface changes
        else:
            peer_info = {'peerdevice': self.peer_device,
                         'hwsku': self.peer_dev_list[self.peer_device],
                         'pfc_fanout_interface': self.neighbors[self.pfc_wd['test_port']]['peerport']
                         }

            self.storm_hndle.update_queue_index(self.pfc_wd['queue_index'])
            self.storm_hndle.update_peer_info(peer_info)


class SendVerifyTraffic():
    """ PTF test """
    def __init__(self, ptf, router_mac, tx_mac, pfc_params, is_dualtor):
        """
        Args:
            ptf(AnsibleHost) : ptf instance
            router_mac(string) : router mac address
            ptf_params(dict) : all PFC test params specific to the DUT port
        """
        self.ptf = ptf
        self.router_mac = router_mac
        self.tx_mac = tx_mac
        self.pfc_queue_index = pfc_params['queue_index']
        self.pfc_wd_test_pkt_count = pfc_params['test_pkt_count']
        self.pfc_wd_rx_port_id = pfc_params['rx_port_id']
        self.pfc_wd_test_port = pfc_params['test_port']
        self.pfc_wd_test_port_id = pfc_params['test_port_id']
        self.pfc_wd_test_port_ids = pfc_params['test_port_ids']
        self.pfc_wd_test_neighbor_addr = pfc_params['test_neighbor_addr']
        self.pfc_wd_rx_neighbor_addr = pfc_params['rx_neighbor_addr']
        self.pfc_wd_test_port_vlan_id = pfc_params['test_port_vlan_id']
        self.pfc_wd_rx_port_vlan_id = pfc_params['rx_port_vlan_id']
        self.port_id_to_type_map = pfc_params['port_id_to_type_map']
        self.port_type = pfc_params['port_type']
        if is_dualtor:
            self.vlan_mac = "00:aa:bb:cc:dd:ee"
        else:
            self.vlan_mac = router_mac

    def send_tx_egress(self, action, verify):
        """
        Send traffic with test port as the egress and verify if the packets get forwarded
        or dropped based on the action

        Args:
            action(string) : PTF test action
        """
        logger.info("Check for egress {} on Tx port {}".format(action, self.pfc_wd_test_port))
        dst_port = "[" + str(self.pfc_wd_test_port_id) + "]"
        if action == "forward" and type(self.pfc_wd_test_port_ids) == list:
            dst_port = "".join(str(self.pfc_wd_test_port_ids)).replace(',', '')
        ptf_params = {'router_mac': self.router_mac,
                      'vlan_mac': self.vlan_mac,
                      'queue_index': self.pfc_queue_index,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_rx_port_id[0],
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_test_neighbor_addr,
                      'port_type': self.port_id_to_type_map[self.pfc_wd_rx_port_id[0]],
                      'wd_action': action if verify else "dontcare"}
        if self.pfc_wd_rx_port_vlan_id is not None:
            ptf_params['port_src_vlan_id'] = self.pfc_wd_rx_port_vlan_id
        if self.pfc_wd_test_port_vlan_id is not None:
            ptf_params['port_dst_vlan_id'] = self.pfc_wd_test_port_vlan_id
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file, is_python3=True)

    def send_rx_ingress(self, action, verify):
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
        ptf_params = {'router_mac': self.tx_mac,
                      'vlan_mac': self.vlan_mac,
                      'queue_index': self.pfc_queue_index,
                      'pkt_count': self.pfc_wd_test_pkt_count,
                      'port_src': self.pfc_wd_test_port_id,
                      'port_dst': dst_port,
                      'ip_dst': self.pfc_wd_rx_neighbor_addr,
                      'port_type': self.port_id_to_type_map[self.pfc_wd_test_port_id],
                      'wd_action': action if verify else "dontcare"}
        if self.pfc_wd_rx_port_vlan_id is not None:
            ptf_params['port_dst_vlan_id'] = self.pfc_wd_rx_port_vlan_id
        if self.pfc_wd_test_port_vlan_id is not None:
            ptf_params['port_src_vlan_id'] = self.pfc_wd_test_port_vlan_id
        log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
        ptf_runner(self.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
                   log_file=log_file, is_python3=True)


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

        selected_test_ports = [self.pfc_wd['rx_port'][0]]
        test_ports_info = {self.pfc_wd['rx_port'][0]: self.pfc_wd}
        queues = [self.storm_hndle.pfc_queue_idx]

        with send_background_traffic(dut, self.ptf, queues, selected_test_ports, test_ports_info):
            if action != "dontcare":
                start_wd_on_ports(dut, port, restore_time, detect_time, action)

            self.storm_hndle.start_storm()

        logger.info("Verify if PFC storm is detected on port {}".format(port))
        pytest_assert(
            wait_until(30, 2, 5, check_pfc_storm_state, dut, port, self.storm_hndle.pfc_queue_idx, "storm"),
            "PFC storm state did not change as expected"
        )

    def storm_restore_path(self, dut, port):
        """
        Storm restoration action and associated verifications

        Args:
            loganalyzer(Loganalyzer) : loganalyzer instance
            port(string) : DUT port
            action(string) : PTF test action
        """

        self.storm_hndle.stop_storm()
        time.sleep(self.timers['pfc_wd_wait_for_restore_time'])
        # storm restore
        logger.info("Verify if PFC storm is restored on port {}".format(port))
        pytest_assert(
            wait_until(30, 2, 5, check_pfc_storm_state, dut, port, self.storm_hndle.pfc_queue_idx, "restore"),
            "PFC storm state did not change as expected"
        )

    def run_test(self, dut, port, action):
        """
        Test method that invokes the storm detection and restoration path which includes the traffic
        test and associated counter verifications

        Args:
            dut(AnsibleHost) : DUT instance
            port(string) : DUT port
            action(string) : PTF test action
        """
        pfcwd_stat = self.dut.show_and_parse('show pfcwd stat')
        logger.info("before storm start: pfcwd_stat {}".format(pfcwd_stat))

        logger.info("--- Storm detection path for port {} ---".format(port))
        self.storm_detect_path(dut, port, action)
        # record the initial state of the DUT
        pfcwd_stat_init = parser_show_pfcwd_stat(dut, port, self.pfc_wd['queue_index'])
        logger.debug("pfcwd_stat_init {}".format(pfcwd_stat_init))

        pytest_assert(("storm" in pfcwd_stat_init[0]['status']), "PFC storm status not detected")
        pytest_assert(
            ((int(pfcwd_stat_init[0]['storm_detect_count']) - int(pfcwd_stat_init[0]['restored_count'])) == 1),
            "PFC storm detect count not correct"
        )

        # send traffic to egress port
        self.traffic_inst.send_tx_egress(self.tx_action, False)
        pfcwd_stat_after_tx = parser_show_pfcwd_stat(dut, port, self.pfc_wd['queue_index'])
        logger.debug("pfcwd_stat_after_tx {}".format(pfcwd_stat_after_tx))
        # check count, drop: tx_drop_count; forward: tx_ok_count
        if self.tx_action == "drop":
            tx_drop_count_init = int(pfcwd_stat_init[0]['tx_drop_count'])
            tx_drop_count_check = int(pfcwd_stat_after_tx[0]['tx_drop_count'])
            logger.info("tx_drop_count {} -> {}".format(tx_drop_count_init, tx_drop_count_check))
            pytest_assert(
                ((tx_drop_count_check - tx_drop_count_init) >= self.pfc_wd['test_pkt_count']),
                "PFC storm Tx ok count not correct"
            )
        elif self.tx_action == "forward":
            tx_ok_count_init = int(pfcwd_stat_init[0]['tx_ok_count'])
            tx_ok_count_check = int(pfcwd_stat_after_tx[0]['tx_ok_count'])
            logger.info("tx_ok_count {} -> {}".format(tx_ok_count_init, tx_ok_count_check))
            pytest_assert(
                ((tx_ok_count_check - tx_ok_count_init) >= self.pfc_wd['test_pkt_count']),
                "PFC storm Tx ok count not correct"
            )

        # send traffic to ingress port
        time.sleep(3)
        self.traffic_inst.send_rx_ingress(self.rx_action, False)
        pfcwd_stat_after_rx = parser_show_pfcwd_stat(dut, port, self.pfc_wd['queue_index'])
        logger.debug("pfcwd_stat_after_rx {}".format(pfcwd_stat_after_rx))
        # check count, drop: rx_drop_count; forward: rx_ok_count
        if self.rx_action == "drop":
            rx_drop_count_init = int(pfcwd_stat_init[0]['rx_drop_count'])
            rx_drop_count_check = int(pfcwd_stat_after_rx[0]['rx_drop_count'])
            logger.info("rx_drop_count {} -> {}".format(rx_drop_count_init, rx_drop_count_check))
            pytest_assert(
                ((rx_drop_count_check - rx_drop_count_init) >= self.pfc_wd['test_pkt_count']),
                "PFC storm Rx drop count not correct"
            )
        elif self.rx_action == "forward":
            rx_ok_count_init = int(pfcwd_stat_init[0]['rx_ok_count'])
            rx_ok_count_check = int(pfcwd_stat_after_rx[0]['rx_ok_count'])
            logger.info("rx_ok_count {} -> {}".format(rx_ok_count_init, rx_ok_count_check))
            pytest_assert(
                ((rx_ok_count_check - rx_ok_count_init) >= self.pfc_wd['test_pkt_count']),
                "PFC storm Rx ok count not correct"
            )

        logger.info("--- Storm restoration path for port {} ---".format(port))
        self.storm_restore_path(dut, port)

    def set_traffic_action(self, duthost, action):
        action = action if action != "dontcare" else "drop"
        if duthost.facts["asic_type"] in ["mellanox", "cisco-8000", "innovium"] or is_tunnel_qos_remap_enabled(duthost):
            self.rx_action = "forward"
        else:
            self.rx_action = action
        self.tx_action = action

    def test_pfcwd_show_stat(self, request, setup_pfc_test, setup_dut_test_params, enum_fanout_graph_facts, ptfhost, # noqa F811
                             duthosts, enum_rand_one_per_hwsku_frontend_hostname, fanouthosts,
                             setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m_unconditionally,
                             toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m): # noqa F811
        """
        PFCwd CLI show pfcwd stats test

        Args:
            request(object) : pytest request object
            setup_pfc_test(fixture) : Module scoped autouse fixture for PFCwd
            enum_fanout_graph_facts(fixture) : fanout graph info
            ptfhost(AnsibleHost) : ptf host instance
            duthost(AnsibleHost) : DUT instance
            fanouthosts(AnsibleHost): fanout instance
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        setup_info = setup_pfc_test
        setup_dut_info = setup_dut_test_params
        self.fanout_info = enum_fanout_graph_facts
        self.ptf = ptfhost
        self.dut = duthost
        self.fanout = fanouthosts
        self.timers = setup_info['pfc_timers']
        self.ports = setup_info['selected_test_ports']
        self.test_ports_info = setup_info['test_ports']
        if self.dut.topo_type == 't2':
            key, value = list(self.ports.items())[0]
            self.ports = {key: value}
        self.neighbors = setup_info['neighbors']
        self.peer_dev_list = dict()
        self.storm_hndle = None
        self.rx_action = None
        self.tx_action = None
        self.is_dualtor = setup_dut_info['basicParams']['is_dualtor']

        # skip the pytest when the device does not have neighbors
        # 'rx_port' being None indicates there are no ports available to receive frames for pfc storm
        if not has_neighbor_device(setup_pfc_test):
            pytest.skip("Test skipped: No neighbors detected as 'rx_port' is None for selected test ports,"
                        " which is necessary for PFCwd test setup.")

        # for idx, port in enumerate(self.ports):
        port = list(self.ports.keys())[0]
        logger.info("--- Testing various Pfcwd actions on {} ---".format(port))
        self.setup_test_params(port, setup_info['vlan'], init=True)
        self.traffic_inst = SendVerifyTraffic(
            self.ptf,
            duthost.get_dut_iface_mac(self.pfc_wd['rx_port'][0]),
            duthost.get_dut_iface_mac(self.pfc_wd['test_port']),
            self.pfc_wd,
            self.is_dualtor)

        pfc_wd_restore_time_large = request.config.getoption("--restore-time")
        # wait time before we check the logs for the 'restore' signature. 'pfc_wd_restore_time_large' is in ms.
        self.timers['pfc_wd_wait_for_restore_time'] = int(pfc_wd_restore_time_large / 1000 * 2)
        actions = ['drop', 'forward']
        for action in actions:
            logger.info("--- Pfcwd port {} set action {} ---".format(port, action))
            try:
                self.set_traffic_action(duthost, action)
                logger.info("Pfcwd action {} on port {}: Tx traffic action {}, Rx traffic action {} ".
                            format(action, port, self.tx_action, self.rx_action))
                self.run_test(self.dut, port, action)
            except Exception as e:
                pytest.fail(str(e))

            finally:
                if self.storm_hndle:
                    logger.info("--- Stop pfc storm on port {}".format(port))
                    self.storm_hndle.stop_storm()
                logger.info("--- Stop PFC WD ---")
                self.dut.command("pfcwd stop")
