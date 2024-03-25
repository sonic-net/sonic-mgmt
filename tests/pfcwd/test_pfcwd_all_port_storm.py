import logging
import os
import pytest
import time
import random

from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts      # noqa F401
from tests.common.helpers.pfc_storm import PFCMultiStorm
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from .files.pfcwd_helper import start_wd_on_ports
from .files.pfcwd_helper import EXPECT_PFC_WD_DETECT_RE, EXPECT_PFC_WD_RESTORE_RE, fetch_vendor_specific_diagnosis_re

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


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


@pytest.fixture(scope='class', autouse=True)
def storm_test_setup_restore(setup_pfc_test, enum_fanout_graph_facts, duthosts,     # noqa F811
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
    setup_info = setup_pfc_test
    neighbors = setup_info['neighbors']
    port_list = setup_info['port_list']
    ports = (" ").join(port_list)
    pfc_queue_index = 3
    pfc_frames_number = 10000000
    pfc_wd_detect_time = 200
    pfc_wd_restore_time = 200
    peer_params = populate_peer_info(port_list, neighbors, pfc_queue_index, pfc_frames_number)
    storm_hndle = set_storm_params(duthost, enum_fanout_graph_facts, fanouthosts, peer_params)
    start_wd_on_ports(duthost, ports, pfc_wd_restore_time, pfc_wd_detect_time)

    yield storm_hndle

    logger.info("--- Storm test cleanup ---")
    storm_hndle.stop_pfc_storm()


def populate_peer_info(port_list, neighbors, q_idx, frames_cnt):
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
    peer_port_map = dict()
    for port in port_list:
        peer_dev = neighbors[port]['peerdevice']
        peer_port = neighbors[port]['peerport']
        peer_port_map.setdefault(peer_dev, []).append(peer_port)

    peer_params = dict()
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


@pytest.fixture(scope='class', autouse=True)
def start_background_traffic(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        setup_pfc_test,
        copy_ptftests_directory,
        ptfhost,
        tbinfo
        ):
    """
       This fixutre is to start a background traffic during
       the test. This will start a continuous traffic flow from PTF
       exiting the test port.
    """
    if duthosts[enum_rand_one_per_hwsku_frontend_hostname].facts['asic_type'] != "cisco-8000":
        yield
        return

    # This is needed only for cisco-8000
    program_name = "pfcwd_background_traffic"
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dst_dut_intf = list(setup_pfc_test['test_ports'].keys())[0]
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    vlan_ports = []
    for vlan in mg_facts['minigraph_vlans'].keys():
        vlan_ports.extend(mg_facts['minigraph_vlans'][vlan]['members'])
    all_ip_intfs = mg_facts['minigraph_interfaces'] + mg_facts['minigraph_portchannel_interfaces']
    non_vlan_ports = set(list(setup_pfc_test['test_ports'])) - set(vlan_ports) - set([dst_dut_intf])
    src_dut_intf = random.choice(list(non_vlan_ports))
    dest_mac = dut.get_dut_iface_mac(src_dut_intf)
    # Find out if the selected port is a lag member
    # If so, we need to use the neighbor address of the portchannel.
    # else, we need the neighbor address of the interface itself.
    required_intf = dst_dut_intf
    for intf in mg_facts['minigraph_portchannels']:
        if dst_dut_intf in mg_facts['minigraph_portchannels'][intf]['members']:
            required_intf = intf
            break
    # At this point, required_intf is either a portchannel or Ethernet port.
    # It should have a neibhor address or it is an error.
    dst_ip_addr = None
    for intf_obj in all_ip_intfs:
        if intf_obj['attachto'] == required_intf:
            dst_ip_addr = intf_obj['peer_addr']
            break
    if dst_ip_addr is None:
        raise RuntimeError("Couldnot find the neighbor address for intf:{}".format(required_intf))
    ptf_src_port = mg_facts['minigraph_ptf_indices'][src_dut_intf]
    ptf_dst_port = mg_facts['minigraph_ptf_indices'][dst_dut_intf]
    extra_vars = {
        f'{program_name}_args':
            'dest_mac=u"{}";dst_ip_addr={};ptf_src_port={};ptf_dst_port={};pfc_queue_idx={}'.format(
                dest_mac,
                dst_ip_addr,
                ptf_src_port,
                ptf_dst_port,
                3   # Hardcoded in the testcase as well.
                )}
    try:
        ptfhost.command('supervisorctl stop {}'.format(program_name))
    except BaseException:
        pass

    ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)
    script_args = \
        '''dest_mac=u"{}";dst_ip_addr="{}";ptf_src_port={};ptf_dst_port={};pfc_queue_idx={}'''.format(
                dest_mac,
                dst_ip_addr,
                ptf_src_port,
                ptf_dst_port,
                3)
    supervisor_conf_content = ('''
[program:{program_name}]
command=/root/env-python3/bin/ptf --test-dir /root/ptftests/py3 {program_name}.BG_pkt_sender'''
                               ''' --platform-dir /root/ptftests/ -t'''
                               ''' '{script_args}' --relax  --platform remote
process_name={program_name}
stdout_logfile=/tmp/{program_name}.out.log
stderr_logfile=/tmp/{program_name}.err.log
redirect_stderr=false
autostart=false
autorestart=true
startsecs=1
numprocs=1
'''.format(script_args=script_args, program_name=program_name))
    ptfhost.copy(
        content=supervisor_conf_content,
        dest=f'/etc/supervisor/conf.d/{program_name}.conf')

    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')
    ptfhost.command(f'supervisorctl start {program_name}')

    yield

    try:
        ptfhost.command(f'supervisorctl stop {program_name}')
    except BaseException:
        pass
    ptfhost.command(f'supervisorctl remove {program_name}')


@pytest.mark.usefixtures('stop_pfcwd', 'storm_test_setup_restore')
class TestPfcwdAllPortStorm(object):
    """ PFC storm test class """
    def run_test(self, duthost, storm_hndle, expect_regex, syslog_marker, action):
        """
        Storm generation/restoration on all ports and verification

        Args:
            duthost (AnsibleHost): DUT instance
            storm_hndle (PFCMultiStorm): class PFCMultiStorm intance
            expect_regex (list): list of expect regexs to be matched in the syslog
            syslog_marker (string): marker prefix written to the syslog
            action (string): storm/restore action
        """
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=syslog_marker)
        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_pfc_wd_messages")
        reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
        loganalyzer.ignore_regex.extend(reg_exp)

        loganalyzer.expect_regex = []
        loganalyzer.expect_regex.extend(expect_regex)

        loganalyzer.match_regex = []

        with loganalyzer:
            if action == "storm":
                storm_hndle.start_pfc_storm()
            elif action == "restore":
                storm_hndle.stop_pfc_storm()
            time.sleep(5)

    def test_all_port_storm_restore(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                    storm_test_setup_restore):
        """
        Tests PFC storm/restore on all ports

        Args:
            duthost (AnsibleHost): DUT instance
            storm_test_setup_restore (fixture): class scoped autouse setup fixture
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        storm_hndle = storm_test_setup_restore
        logger.info("--- Testing if PFC storm is detected on all ports ---")
        self.run_test(duthost,
                      storm_hndle,
                      expect_regex=[EXPECT_PFC_WD_DETECT_RE + fetch_vendor_specific_diagnosis_re(duthost)],
                      syslog_marker="all_port_storm",
                      action="storm")

        logger.info("--- Testing if PFC storm is restored on all ports ---")
        self.run_test(duthost, storm_hndle, expect_regex=[EXPECT_PFC_WD_RESTORE_RE],
                      syslog_marker="all_port_storm_restore", action="restore")
