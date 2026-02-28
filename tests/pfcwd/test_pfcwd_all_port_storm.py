import logging
import os
import pytest

from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts      # noqa: F401
from tests.common.helpers.pfc_storm import PFCMultiStorm
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.helpers.pfcwd_helper import start_wd_on_ports, update_pfc_poll_interval, \
    start_background_traffic  # noqa: F401
from tests.common.helpers.pfcwd_helper import EXPECT_PFC_WD_DETECT_RE, EXPECT_PFC_WD_RESTORE_RE, \
    fetch_vendor_specific_diagnosis_re, verify_all_ports_pfc_storm_in_expected_state, \
    get_pfc_storm_baseline_counters
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m # noqa F401, E501
from tests.common.helpers.pfcwd_helper import send_background_traffic
from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
FILE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "files")

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="class")
def pfc_queue_idx():
    # Needed for start_background_traffic
    yield 3   # Hardcoded in the testcase as well.


@pytest.fixture(scope='module')
def degrade_pfcwd_detection(duthosts, enum_rand_one_per_hwsku_frontend_hostname, fanouthosts):
    """
    A fixture to degrade PFC Watchdog detection logic.
    It's requried because leaf fanout switch can't generate enough PFC pause to trigger
    PFC storm on all ports.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dut_asic_type = duthost.facts["asic_type"].lower()
    skip_fixture = False
    if dut_asic_type != "mellanox":
        skip_fixture = True
    # The workaround is not applicable for Mellanox leaf-fanout running ONYX or SONiC
    # as we can leverage ASIC to generate PFC pause frames
    for fanouthost in list(fanouthosts.values()):
        fanout_os = fanouthost.get_fanout_os()
        if fanout_os == 'onyx' or fanout_os == 'sonic' and fanouthost.facts['asic_type'] == "mellanox":
            skip_fixture = True
            break
    if skip_fixture:
        yield
        return
    logger.info("--- Degrade PFCWD detection logic --")
    SRC_FILE = FILE_DIR + "/pfc_detect_mellanox.lua"
    DST_FILE = "/usr/share/swss/pfc_detect_mellanox.lua"
    # Backup original PFC Watchdog detection script
    cmd = "docker exec -i swss cp {} {}.bak".format(DST_FILE, DST_FILE)
    duthost.shell(cmd)
    # Copy the new script to DUT
    duthost.copy(src=SRC_FILE, dest='/tmp')
    # Copy the new script to swss container
    cmd = "docker cp /tmp/pfc_detect_mellanox.lua swss:{}".format(DST_FILE)
    duthost.shell(cmd)
    # Reload DUT to apply the new script
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
    yield
    # Restore the original PFC Watchdog detection script
    cmd = "docker exec -i swss cp {}.bak {}".format(DST_FILE, DST_FILE)
    duthost.shell(cmd)
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
    # Cleanup
    duthost.file(path='/tmp/pfc_detect_mellanox.lua', state='absent')


@pytest.fixture(scope='class', autouse=True)
def stop_pfcwd(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that stops PFC Watchdog before each test run

    Args:
        duthost (AnsibleHost): DUT instance
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("--- Stop Pfcwd --")
    duthost.command("pfcwd stop")

    yield

    logger.info("--- Start Pfcwd --")
    duthost.command("pfcwd start_default")


@pytest.fixture(scope='class', autouse=True)
def storm_test_setup_restore(setup_pfc_test, enum_fanout_graph_facts, duthosts,     # noqa: F811
                             enum_rand_one_per_hwsku_frontend_hostname, fanouthosts):
    """
    Fixture that inits the test vars, start PFCwd on ports and cleans up after the test run

    Args:
        setup_pfc_test (fixture): module scoped, autouse PFC fixture
        enum_fanout_graph_facts (fixture): fanout graph info
        duthost (AnsibleHost): DUT instance
        fanouthosts (AnsibleHost): fanout instance

    Yields:
        storm_hndle (PFCStorm): class PFCStorm instance
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_type = duthost.facts['asic_type']
    setup_info = setup_pfc_test
    neighbors = setup_info['neighbors']
    port_list = setup_info['port_list']
    ports = (" ").join(port_list)
    pfc_queue_index = 3
    pfc_frames_number = 10000000
    pfc_wd_detect_time = 200
    pfc_wd_restore_time = 200
    peer_params = populate_peer_info(asic_type, port_list, neighbors, pfc_queue_index, pfc_frames_number)
    storm_hndle = set_storm_params(duthost, enum_fanout_graph_facts, fanouthosts, peer_params)
    update_pfc_poll_interval(duthost, 200)
    start_wd_on_ports(duthost, ports, pfc_wd_restore_time, pfc_wd_detect_time)

    yield storm_hndle

    logger.info("--- Storm test cleanup ---")
    storm_hndle.stop_pfc_storm()


def populate_peer_info(asic_type, port_list, neighbors, q_idx, frames_cnt):
    """
    Build the peer_info map which will be used by the storm generation class

    Args:
        port_list (list): set of ports on which the PFC storm needs to be generated
        neighbors (dict): fanout info for each DUT port
        q_idx (int): queue on which PFC frames need to be generated
        frames_cnt (int): Number of PFC frames to generate

    Returns:
        peer_params (dict): all PFC params needed for each fanout for storm generation
    """
    peer_params = dict()
    if asic_type != 'vs':
        peer_port_map = dict()
        for port in port_list:
            peer_dev = neighbors[port]['peerdevice']
            peer_port = neighbors[port]['peerport']
            peer_port_map.setdefault(peer_dev, []).append(peer_port)

        for peer_dev in peer_port_map:
            peer_port_map[peer_dev] = (',').join(peer_port_map[peer_dev])
            peer_params[peer_dev] = {'pfc_frames_number': frames_cnt,
                                     'pfc_queue_index': q_idx,
                                     'intfs': peer_port_map[peer_dev]
                                     }
    return peer_params


def set_storm_params(duthost, fanout_graph, fanouthosts, peer_params):
    """
    Setup storm parameters

    Args:
        duthost (AnsibleHost): DUT instance
        fanout_graph (fixture): fanout info
        fanouthosts (AnsibleHost): fanout instance
        peer_params (dict): all PFC params needed for each fanout for storm generation

    Returns:
        storm_hndle (PFCMultiStorm): class PFCMultiStorm intance
    """
    storm_hndle = PFCMultiStorm(duthost, fanout_graph, fanouthosts, peer_params)
    storm_hndle.set_storm_params()
    return storm_hndle


def resolve_arp(duthost, ptfhost, test_ports_info, vlan, ip_version):
    """
    Populate ARP info for the DUT vlan port

    Args:
        ptfhost: ptf host instance
        test_ports_info: test ports information
    """
    for port, port_info in test_ports_info.items():
        if port_info['test_port_type'] == 'vlan':
            neighbor_ip = port_info['test_neighbor_addr']
            ptf_port = f"eth{port_info['test_port_id']}"
            if ip_version == "IPv4":
                ptfhost.command(f"ifconfig {ptf_port} {neighbor_ip}")
                duthost.command(f"docker exec -i swss arping {neighbor_ip} -c 5")
            else:
                ptfhost.command(f"ip -6 addr add {neighbor_ip}/{vlan['prefix']} dev {ptf_port}")
                duthost.command(f"docker exec -i swss ping -6 -c 5 {neighbor_ip}")
            break


@pytest.mark.usefixtures('degrade_pfcwd_detection', 'stop_pfcwd', 'storm_test_setup_restore', 'start_background_traffic')  # noqa: E501
class TestPfcwdAllPortStorm(object):
    """ PFC storm test class """
    # Threshold percentage for port storm verification (75% of ports must reach expected state)
    PFC_STORM_THRESHOLD_PERCENTAGE = 75
    # Threshold percentage for restore verification (100% of stormed ports must restore)
    PFC_RESTORE_THRESHOLD_PERCENTAGE = 100

    def run_test(self, duthost, storm_hndle, expect_regex, syslog_marker, action, stormed_ports_list=None):
        """Storm generation/restoration on all ports and verification."""
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=syslog_marker)
        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_pfc_wd_messages")
        reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
        loganalyzer.ignore_regex.extend(reg_exp)

        if duthost.facts['asic_type'] != 'vs':
            loganalyzer.expect_regex = []
            loganalyzer.expect_regex.extend(expect_regex)

        loganalyzer.match_regex = []

        with loganalyzer:
            if action == "storm":
                baseline_counters = get_pfc_storm_baseline_counters(duthost, storm_hndle)
                storm_hndle.start_pfc_storm()
                threshold = self.PFC_STORM_THRESHOLD_PERCENTAGE
            else:  # restore
                baseline_counters = None
                storm_hndle.stop_pfc_storm()
                threshold = self.PFC_RESTORE_THRESHOLD_PERCENTAGE

            port_type = "ports" if action == "storm" else "stormed ports"
            logger.info(f"Waiting for {threshold}% of {port_type} to reach {action} state")

            pytest_assert(
                wait_until(60, 2, 5, verify_all_ports_pfc_storm_in_expected_state, duthost,
                           storm_hndle, action, baseline_counters, threshold, stormed_ports_list),
                f"Not enough ports reached {action} state (threshold: {threshold}%)"
            )

    def test_all_port_storm_restore(
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
            storm_test_setup_restore, setup_pfc_test, ptfhost,
            setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m_unconditionally,     # noqa: F811
            toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m,                  # noqa: F811
            set_pfc_time_cisco_8000):
        """
        Tests PFC storm/restore on all ports

        Args:
            duthost (AnsibleHost): DUT instance
            storm_test_setup_restore (fixture): class scoped autouse setup fixture
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        storm_hndle = storm_test_setup_restore
        logger.info("--- Testing if PFC storm is detected on all ports ---")

        # Track which ports actually enter storm state
        stormed_ports_list = []

        # get all the tested ports
        queues = []
        for peer in storm_hndle.peer_params.keys():
            fanout_intfs = storm_hndle.peer_params[peer]['intfs'].split(',')
            device_conn = storm_hndle.fanout_graph[peer]['device_conn']
            queues.append(storm_hndle.storm_handle[peer].pfc_queue_idx)
        queues = list(set(queues))
        selected_test_ports = []

        if duthost.facts['asic_type'] != 'vs':
            for intf in fanout_intfs:
                test_port = device_conn[intf]['peerport']
                if test_port in setup_pfc_test['test_ports']:
                    selected_test_ports.append(test_port)
        resolve_arp(duthost, ptfhost, setup_pfc_test['test_ports'],
                    setup_pfc_test["vlan"], setup_pfc_test["ip_version"])
        with send_background_traffic(duthost, ptfhost, queues, selected_test_ports, setup_pfc_test['test_ports'],
                                     pkt_count=500):
            self.run_test(duthost,
                          storm_hndle,
                          expect_regex=[EXPECT_PFC_WD_DETECT_RE + fetch_vendor_specific_diagnosis_re(duthost)],
                          syslog_marker="all_port_storm",
                          action="storm",
                          stormed_ports_list=stormed_ports_list)

        logger.info(f"--- {len(stormed_ports_list)} ports entered storm state ---")
        logger.info("--- Testing if PFC storm is restored on stormed ports ---")
        self.run_test(duthost, storm_hndle, expect_regex=[EXPECT_PFC_WD_RESTORE_RE],
                      syslog_marker="all_port_storm_restore", action="restore",
                      stormed_ports_list=stormed_ports_list)
