"""
Tests Acl Vlan Outer ID match in SONiC.
"""

import os
import time
import logging
import pytest
import ipaddress
import ptf.testutils as testutils
from ptf import mask
from scapy.all import Ether, IP

from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

from abc import abstractmethod

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

DEFAULT_VLANID = 1000
ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
ACL_ADD_RULES_FILE = "acltb_test_rules_outer_vlan.j2"
ACL_RULES_FILE = 'acl_config.json'
TMP_DIR = '/tmp'
ACTION_FORWARD = 'FORWARD'
ACTION_DROP = 'DROP'
RULE_1, RULE_2 = 'rule_1', 'rule_2'
TEST_VLAN_LIST = [100, 200]
QINQ = 'qinq'
INGRESS = 'ingress'
EGRESS = 'egress'
IPV4 = 'ipv4'
IPV6 = 'ipv6'
# ACL table name, should be something like DATAACL_ingress_ipv4
ACL_TABLE_NAME_TEMPLATE = "DATAACL_{}_{}"

# vlan type (tagged, untagged or both)
TYPE_TAGGED = 'TAGGED' # The interface is in only one vlan, tagged mode 
TYPE_UNTAGGED = 'UNTAGGED' # The interface is in only one vlan, untagged mode
TYPE_COMBINE_TAGGED = 'COMBINE_TAGGED' # The interface is in two vlans
TYPE_COMBINE_UNTAGGED = 'COMBINE_UNTAGGED' # The interface is in two vlans

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"


@pytest.fixture(scope="module", params=[IPV6])
def ip_version(request):
    """
    Parametrize Ip version

    Args:
        request: pytest request object

    Returns:
        Ip version needed for test case
    """
    return request.param


@pytest.fixture(scope="module")
def default_routes_itfs(rand_selected_dut):
    """
    A fixture to retrieve egress interfaces for on DUT
    """

# Todo: Refactor below code to acl test utilities
@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(rand_selected_dut):
    """
    Remove DATAACL to free TCAM resources
    """
    TABLE_NAME = "DATAACL"
    lines = rand_selected_dut.shell(cmd="show acl table {}".format(TABLE_NAME))['stdout_lines']
    data_acl_existing = False
    for line in lines:
        if TABLE_NAME in line:
            data_acl_existing = True
            break
    if not data_acl_existing:
        yield
        return
    # Remove DATAACL
    logger.info("Removing ACL table {}".format(TABLE_NAME))
    rand_selected_dut.shell(cmd="config acl remove table {}".format(TABLE_NAME))
    yield
    # Recover DATAACL
    config_db_json = "/etc/sonic/config_db.json"
    output = rand_selected_dut.shell("sonic-cfggen -j {} --var-json \"ACL_TABLE\"".format(config_db_json))['stdout']
    try:
        entry = json.loads(output)[TABLE_NAME]
        cmd_create_table = "config acl add table {} {} -p {} -s {}".format(TABLE_NAME, entry['type'], \
             ",".join(entry['ports']), entry['stage'])
        logger.info("Restoring ACL table {}".format(TABLE_NAME))
        rand_selected_dut.shell(cmd_create_table)
    except Exception as e:
        pytest.fail(str(e))


@pytest.fixture(scope="module")
def vlan_setup_info(rand_selected_dut, tbinfo):
    """
    Get Vlan setup for test run
    """
    vlan_setup = {}
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    minigraph_vlan = list(mg_facts['minigraph_vlans'].values())[0]
    minigraph_ptf_indices = mg_facts['minigraph_ptf_indices']
    vlan_setup['default_vlan'] = minigraph_vlan['name']
    # 3 interfaces are required to cover all test scenarios
    pytest_require(len(minigraph_vlan['members']) >= 3, "There is no sufficient ports for testing")
    ports_for_test = minigraph_vlan['members'][:3]

    vlan_setup[100] = {
        "vlan_id": 100,
        "vlan_ip": {IPV4: "192.100.0.1/24", IPV6: "fc02:100::1/96"},
        "vlan_mac": rand_selected_dut.facts["router_mac"],
        "tagged_ports": (ports_for_test[0], minigraph_ptf_indices[ports_for_test[0]]),
        "untagged_ports": (ports_for_test[2], minigraph_ptf_indices[ports_for_test[2]]),
    }
    vlan_setup[200] = {
        "vlan_id": 200,
        "vlan_ip": {IPV4: "192.200.0.1/24", IPV6: "fc02:200::1/96"},
        "vlan_mac": rand_selected_dut.facts["router_mac"],
        "tagged_ports": (ports_for_test[2], minigraph_ptf_indices[ports_for_test[2]]),
        "untagged_ports": (ports_for_test[1], minigraph_ptf_indices[ports_for_test[1]])
    }

    return vlan_setup, ports_for_test

def setup_vlan(rand_selected_dut, vlan_setup_info):
    """
    Create vlan 100 and 200 on DUT for testing.
    - Ethernet0 belongs to Vlan100, tagged
    - Ethernet2 belongs to Vlan200, untagged
    - Ethernet4 belongs to both Vlan100 (untagged) and Vlan200 (tagged)
    +-----------+-----------------+-------------+----------------+-----------------------+-------------+
    |   VLAN ID | IP Address      | Ports       | Port Tagging   | DHCP Helper Address   | Proxy ARP   |
    +===========+=================+=============+================+=======================+=============+
    |       100 | 192.100.0.1/24  | Ethernet0   | tagged         |                       | disabled    |
    |           |                 | Ethernet4   | untagged       |                       |             |
    +-----------+-----------------+-------------+----------------+-----------------------+-------------+
    |       200 | 192.200.0.1/24  | Ethernet2   | untagged       |                       | disabled    |
    |           |                 | Ethernet4   | tagged         |                       |             |
    +-----------+-----------------+-------------+----------------+-----------------------+-------------+
    """
    vlan_setup, test_ports = vlan_setup_info
    default_vlan_id = vlan_setup['default_vlan'].replace("Vlan", "")
    # Remove interface from default Vlan
    cmds = []
    for port in test_ports:
        cmds.append('config vlan member del {} {}'.format(default_vlan_id, port))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)

    # Create new vlan 
    cmds = []
    for new_vlan in TEST_VLAN_LIST:
        cmds.append('config vlan add {}'.format(new_vlan))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)

    # Assign IP to Vlan interface
    cmds = []
    for new_vlan in TEST_VLAN_LIST:
        cmds.append('config interface ip add Vlan{} {}'.format(new_vlan, vlan_setup[new_vlan]['vlan_ip'][IPV4]))
        cmds.append('config interface ip add Vlan{} {}'.format(new_vlan, vlan_setup[new_vlan]['vlan_ip'][IPV6]))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)
    
    # Add ports to vlan
    cmds= []
    for new_vlan in TEST_VLAN_LIST:
        tagged_port = vlan_setup[new_vlan].get('tagged_ports', None)
        untagged_port = vlan_setup[new_vlan].get('untagged_ports', None)
        if tagged_port:
            cmds.append("config vlan member add {} {}".format(new_vlan, tagged_port[0]))
        if untagged_port:
            cmds.append("config vlan member add {} {} --untagged".format(new_vlan, untagged_port[0]))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)


def teardown_vlan(rand_selected_dut, vlan_setup_info):
    """
    Remove testing vlan
    """
    vlan_setup, test_ports = vlan_setup_info
    # Remove ports from test vlan
    cmds= []
    for new_vlan in TEST_VLAN_LIST:
        tagged_port = vlan_setup[new_vlan].get('tagged_ports', None)
        untagged_port = vlan_setup[new_vlan].get('untagged_ports', None)
        if tagged_port:
            cmds.append("config vlan member del {} {}".format(new_vlan, tagged_port[0]))
        if untagged_port:
            cmds.append("config vlan member del {} {}".format(new_vlan, untagged_port[0]))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)

    # Remove IP from Vlan interface
    cmds = []
    for new_vlan in TEST_VLAN_LIST:
        cmds.append('config interface ip remove Vlan{} {}'.format(new_vlan, vlan_setup[new_vlan]['vlan_ip'][IPV4]))
        cmds.append('config interface ip remove Vlan{} {}'.format(new_vlan, vlan_setup[new_vlan]['vlan_ip'][IPV6]))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)

    # Remove testing vlan 
    cmds = []
    for new_vlan in TEST_VLAN_LIST:
        cmds.append('config vlan del {}'.format(new_vlan))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)

    default_vlan_id = vlan_setup['default_vlan'].replace("Vlan", "")
    # Add back interface to default Vlan
    cmds = []
    for port in test_ports:
        cmds.append('config vlan member add {} {} --untagged'.format(default_vlan_id, port))
    rand_selected_dut.shell_cmds(cmds=cmds)
    time.sleep(10)


@pytest.fixture(scope='module', autouse=False)
def vlan_setup_teardown(rand_selected_dut, vlan_setup_info):
    try:
        setup_vlan(rand_selected_dut, vlan_setup_info)
        yield
    finally:
        teardown_vlan(rand_selected_dut, vlan_setup_info)


def send_and_verify_traffic(ptfadapter, pkt, exp_pkt, src_port, dst_port, pkt_action=ACTION_FORWARD):
    """
    Send traffic and verify that traffic was received

    Args:
        ptfadapter: PTF adapter
        pkt: Packet that should be sent
        exp_pkt: Expected packet
        src_port: Source port
        dst_port: Destination port
        pkt_action: Packet action (forward or drop)
    """

    ptfadapter.dataplane.flush()
    logger.info("Send packet from port {} to port {}".format(src_port, dst_port))
    testutils.send(ptfadapter, src_port, pkt)

    if pkt_action == ACTION_FORWARD:
        testutils.verify_packet(ptfadapter, exp_pkt, dst_port)
    elif pkt_action == ACTION_DROP:
        testutils.verify_no_packet(ptfadapter, exp_pkt, dst_port)

def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL):
    """
    Get Acl counter packets value

    Args:
        duthost: DUT host object
        table_name: Acl Table name
        rule_name: Acl rule name
        timeout: Timeout for Acl counters to update

    Returns:
        Acl counter value for packets
    """
    cmd = "redis-cli -n 2 hget 'COUNTERS:{}:{}' Packets"
    # Wait for orchagent to update the ACL counters
    time.sleep(timeout)
    result = duthost.shell(cmd.format(table_name, rule_name))['stdout']
    if result == "":
        pytest.fail("Failed to retrieve acl counter for {}|{}".format(table_name, rule_name))
    return int(result)


def craft_packet(src_mac, dst_mac, dst_ip, ip_version, tagged_mode, vlan_id=10, outer_vlan_id=0, pkt_type=None):
    """
    Generate IPV4/IPV6 packets with single or double Vlan Header

    Args:
        src_mac: Source MAC address
        dst_mac: Dest MAC address
        dst_ip: IP address of packet
        ip_version: Ip version of packet that should be generated
        tagged_mode:  TAGGED or UNTAGGED
        vlan_id: Vlan Id number
        dl_vlan_outer: Outer Vlan ID
        pkt_type: packet type to be created, by default UDP

    Returns:
        Simple UDP, QinQ or TCP packet
    """
    if ip_version == IPV4:
        if pkt_type == 'qinq':
            pkt = testutils.simple_qinq_tcp_packet(eth_src=src_mac,
                                                   eth_dst=dst_mac,
                                                   dl_vlan_outer=outer_vlan_id,
                                                   vlan_vid=vlan_id,
                                                   ip_dst=dst_ip)
            if tagged_mode in [TYPE_TAGGED, TYPE_COMBINE_TAGGED]:
                """
                In our test setting, if src_port is tagged, then dst_port is untagged.
                So the egress packet is without vlan tag
                """
                exp_pkt = testutils.simple_tcp_packet(pktlen=96, # Default len (100) - Dot1Q len (4)
                                                    eth_src=src_mac,
                                                    eth_dst=dst_mac,
                                                    dl_vlan_enable=True,
                                                    vlan_vid=vlan_id,
                                                    ip_dst=dst_ip)
            else:
                exp_pkt = pkt
        else:
            pkt = testutils.simple_udp_packet(eth_src=src_mac,
                                            eth_dst=dst_mac,
                                            dl_vlan_enable=True,
                                            vlan_vid=vlan_id,
                                            ip_dst=dst_ip)
            exp_pkt = pkt
        
    else:
        pkt = testutils.simple_tcpv6_packet(eth_src=src_mac,
                                            eth_dst=dst_mac,
                                            dl_vlan_enable=True,
                                            vlan_vid=outer_vlan_id,
                                            ipv6_dst=dst_ip)
        if tagged_mode in [TYPE_TAGGED, TYPE_COMBINE_TAGGED]:
            exp_pkt = testutils.simple_tcpv6_packet(pktlen=96, # Default len (100) - Dot1Q len (4)
                                                    eth_src=src_mac,
                                                    eth_dst=dst_mac,
                                                    ipv6_dst=dst_ip)
        else:
            exp_pkt = pkt

    return pkt, exp_pkt


def check_rule_counters(duthost):
    """
    Check if Acl rule counters initialized

    Args:
        duthost: DUT host object
    Returns:
        Bool value
    """
    res = duthost.shell("aclshow -a")['stdout_lines']
    if len(res) <= 2 or [line for line in res if 'N/A' in line]:
        return False
    else:
        return True

@pytest.fixture(scope="module", autouse=False)
def teardown(duthosts, rand_one_dut_hostname):
    """
    Teardown fixture to clean up DUT to initial state

    Args:
        duthosts: All DUTs objects belonging to the testbed
        rand_one_dut_hostname: Hostname of a random chosen dut to run test
    """
    yield
    duthost = duthosts[rand_one_dut_hostname]
    config_reload(duthost)

class AclVlanOuterTest_Base(object):
    """
    Base class
    """
    def _setup_acl_table(self, duthost, stage, ip_ver, bind_ports):
        table_name = ACL_TABLE_NAME_TEMPLATE.format(stage, ip_ver)
        table_type = "L3" if ip_ver == IPV4 else "L3V6"
        cmd = "config acl add table {} {} -s {} -p {}".format(
            table_name,
            table_type,
            stage,
            ",".join(bind_ports)
        )

        logger.info("Creating ACL table {} for testing".format(table_name))
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="TestAclVlanOuter")
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
        try:
            with loganalyzer:
                duthost.shell(cmd)
        except LogAnalyzerError:
            #Todo: cleanup
            pytest.fail("Failed to create ACL table {}".format(table_name))

    def _remove_acl_table(self, duthost, stage, ip_ver):
        table_name = ACL_TABLE_NAME_TEMPLATE.format(stage, ip_ver)
        cmd = "config acl remove table {}".format(table_name)

        logger.info("Removing ACL table {}".format(table_name))
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="TestAclVlanOuter")
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_REMOVE_RE]

        try:
            with loganalyzer:
                duthost.shell(cmd)
        except LogAnalyzerError:
            #Todo: cleanup
            pytest.fail("Failed to remove ACL table {}".format(table_name))

    def _setup_acl_rules(self, duthost, stage, ip_ver, vlan_id, action):
        table_name = ACL_TABLE_NAME_TEMPLATE.format(stage, ip_ver)

        extra_vars = {
            'table_name': table_name,
            'vlan_id': vlan_id,
            'action': action
            }
        dest_path = os.path.join(TMP_DIR, ACL_RULES_FILE)
        duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
        duthost.file(path=dest_path, state='absent')
        duthost.template(src=os.path.join(TEMPLATES_DIR, ACL_ADD_RULES_FILE), dest=dest_path)
        logger.info("Creating ACL rule matching vlan {} action {}".format(vlan_id, action))
        duthost.shell("config load -y {}".format(dest_path))

        pytest_assert(wait_until(60, 2, check_rule_counters, duthost), "Acl rule counters are not ready")

    def _remove_acl_rules(self, duthost, stage, ip_ver):
        table_name = ACL_TABLE_NAME_TEMPLATE.format(stage, ip_ver)
        duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
        remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
        duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, table_name))
        time.sleep(10)
    
    def _default_route_interfaces(self, mg_facts):
        """
        Return a list including all ptf_idx of portchannel members
        """
        portchannel_member_idx = []
        minigraph_ptf_indices = mg_facts['minigraph_ptf_indices']
        for _, v in mg_facts['minigraph_portchannels'].items():
            for port in v['members']:
                portchannel_member_idx.append(minigraph_ptf_indices[port])
        
        return portchannel_member_idx

    @abstractmethod
    def setup_cfg(self, duthost, tbinfo, vlan_setup, tagged_mode, ip_version):
        """
        Helper function to retrieve dst_ip, tx_port, rx_ports, vlan_id.
        """
        pass

    @abstractmethod
    def pre_running_hook(self, duthost, ip_version, bind_ports):
        """
        Setup before test running
        """
        pass

    @abstractmethod
    def post_running_hook(self, duthost, ip_version):
        """
        Setup post test running
        """
        pass

    @pytest.fixture(scope='class', autouse=True)
    def setup(self, rand_selected_dut, ip_version, vlan_setup_info):
        _, ports = vlan_setup_info
        self.pre_running_hook(rand_selected_dut, ip_version, ports)
        yield
        self.post_running_hook(rand_selected_dut, ip_version)

    def _do_verification(self, ptfadapter, duthost, tbinfo, vlan_setup_info, ip_version, tagged_mode, action):
        vlan_setup, ports = vlan_setup_info
        test_setup_config = self.setup_cfg(duthost, tbinfo, vlan_setup, tagged_mode, ip_version)

        stage = test_setup_config['stage']
        src_port = test_setup_config['src_port']
        dst_port = test_setup_config['dst_port']
        outer_vlan_id = test_setup_config['outer_vlan_id']
        vlan_id = test_setup_config['vlan_id']
        dst_ip = test_setup_config['dst_ip']
        
        logger.info("Verifying scenario tagged={} outer_vlan_id={} vlan_id={} action={}".format(
                    tagged_mode, outer_vlan_id, vlan_id, action))

        pkt_type = QINQ if stage == INGRESS else None
        src_mac = ptfadapter.dataplane.get_mac(0, src_port)
        dst_mac = ptfadapter.dataplane.get_mac(0, dst_port)
        pkt, exp_pkt = craft_packet(src_mac=src_mac,
                                dst_mac=dst_mac,
                                dst_ip=dst_ip,
                                ip_version=ip_version,
                                vlan_id=vlan_id,
                                outer_vlan_id=outer_vlan_id,
                                pkt_type=pkt_type,
                                tagged_mode=tagged_mode)

        table_name = ACL_TABLE_NAME_TEMPLATE.format(stage, ip_version)
        try:
            self._setup_acl_rules(duthost, stage, ip_version, outer_vlan_id, action)
            count_before = get_acl_counter(duthost, table_name, RULE_1, timeout=0)

            send_and_verify_traffic(ptfadapter, pkt, exp_pkt, src_port, dst_port, pkt_action=action)
            count_after = get_acl_counter(duthost, table_name, RULE_1)

            logger.info("Verify Acl counter incremented {} > {}".format(count_after, count_before))
            pytest_assert(count_after >= count_before + 1,
                            "Unexpected results, counter_after {} > counter_before {}".format(count_after, count_before))
        except Exception as e:
            raise(e)
        finally:
            self._remove_acl_rules(duthost, stage, ip_version)

    def test_tagged_forwarded(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is forwarded by ACL rule on tagged interface
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_TAGGED, ACTION_FORWARD)
        
    def test_tagged_dropped(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is dropped by ACL rule on tagged interface
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_TAGGED, ACTION_DROP)

    def test_untagged_forwarded(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is forwarded by ACL rule on untagged interface
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_UNTAGGED, ACTION_FORWARD)

    def test_untagged_dropped(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is dropped by ACL rule on untagged interface
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_UNTAGGED, ACTION_DROP)

    def test_combined_tagged_forwarded(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is forwarded by ACL rule on tagged interface, and the interface belongs to two vlans
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_COMBINE_TAGGED, ACTION_FORWARD)

    def test_combined_tagged_dropped(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is dropped by ACL rule on tagged interface, and the interface belongs to two vlans
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_COMBINE_TAGGED, ACTION_DROP)

    def test_combined_untagged_forwarded(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is forwarded by ACL rule on untagged interface, and the interface belongs to two vlans
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_COMBINE_UNTAGGED, ACTION_FORWARD)

    def test_combined_untagged_dropped(self, ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version):
        """
        Verify packet is dropped by ACL rule on untagged interface, and the interface belongs to two vlans
        """
        self._do_verification(ptfadapter, rand_selected_dut, tbinfo, vlan_setup_info, ip_version, TYPE_COMBINE_UNTAGGED, ACTION_DROP)

class TestAclVlanOuter_Ingress(AclVlanOuterTest_Base):
    """
    Verify ACL rule matching outer vlan id in ingress
    """
    def pre_running_hook(self, duthost, ip_version, bind_ports):
        self._setup_acl_table(duthost, INGRESS, ip_version, bind_ports)

    def post_running_hook(self, duthost, ip_version):
        self._remove_acl_table(duthost, INGRESS, ip_version)
    
    def setup_cfg(self, duthost, tbinfo, vlan_setup, tagged_mode, ip_version):
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        cfg = {}
        cfg['stage'] = INGRESS
        cfg['dst_ip'] = '2.2.2.2' if ip_version == IPV4 else 'fc22:1000::1' # Routed with default routes
        cfg['vlan_id'] = 10 #Dummy inner vlan id

        if TYPE_TAGGED == tagged_mode:
            cfg['src_port'] = vlan_setup[100]['tagged_ports'][1]
            cfg['dst_port'] = vlan_setup[100]['untagged_ports'][1]
            cfg['outer_vlan_id'] = 100
            cfg['vlan_mac'] = vlan_setup[100]['vlan_mac']
        elif TYPE_UNTAGGED == tagged_mode:
            cfg['src_port'] = vlan_setup[200]['untagged_ports'][1]
            cfg['dst_port'] = vlan_setup[200]['tagged_ports'][1]
            cfg['outer_vlan_id'] = 200
            cfg['vlan_mac'] = vlan_setup[200]['vlan_mac']
        elif TYPE_COMBINE_TAGGED == tagged_mode:
            cfg['src_port'] = vlan_setup[200]['tagged_ports'][1]
            cfg['dst_port'] = vlan_setup[200]['untagged_ports'][1]
            cfg['outer_vlan_id'] = 200
            cfg['vlan_mac'] = vlan_setup[200]['vlan_mac']
        else:
            cfg['src_port'] = vlan_setup[100]['untagged_ports'][1]
            cfg['dst_port'] = vlan_setup[100]['tagged_ports'][1]
            cfg['outer_vlan_id'] = 100
            cfg['vlan_mac'] = vlan_setup[100]['vlan_mac']
        
        return cfg

#class TestAclVlanOuter_Egress(AclVlanOuterTest_Base):
    """
    Verify ACL rule matching outer vlan id in egress
    """
    #pass
