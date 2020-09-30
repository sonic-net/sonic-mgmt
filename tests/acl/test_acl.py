import os
import time
import random
import logging
import pprint

from abc import ABCMeta, abstractmethod

import pytest

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common import reboot, port_toggle
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db_module

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.acl,
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('t1')
]

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
FILES_DIR = os.path.join(BASE_DIR, 'files')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')

ACL_TABLE_TEMPLATE = 'acltb_table.j2'
ACL_RULES_FULL_TEMPLATE = 'acltb_test_rules.j2'
ACL_RULES_PART_TEMPLATES = tuple('acltb_test_rules_part_{}.j2'.format(i) for i in xrange(1, 3))
ACL_REMOVE_RULES_FILE = 'acl_rules_del.json'

DST_IP_TOR = '192.168.0.1'
DST_IP_TOR_FORWARDED = '192.168.8.1'
DST_IP_TOR_BLOCKED = '192.168.16.1'
DST_IP_SPINE = '192.168.128.1'
DST_IP_SPINE_FORWARDED = '192.168.136.1'
DST_IP_SPINE_BLOCKED = '192.168.144.1'

LOG_EXPECT_ACL_TABLE_CREATE_RE = '.*Created ACL table.*'
LOG_EXPECT_ACL_TABLE_REMOVE_RE = '.*Successfully deleted ACL table.*'
LOG_EXPECT_ACL_RULE_CREATE_RE = '.*Successfully created ACL rule.*'
LOG_EXPECT_ACL_RULE_REMOVE_RE = '.*Successfully deleted ACL rule.*'


@pytest.fixture(scope='module')
def setup(duthost, tbinfo, ptfadapter):
    """
    setup fixture gathers all test required information from DUT facts and tbinfo
    :param duthost: DUT host object
    :param tbinfo: fixture provides information about testbed
    :return: dictionary with all test required information
    """

    tor_ports = []
    spine_ports = []
    tor_ports_ids = []
    spine_ports_ids = []
    port_channels = []
    acl_table_ports = []

    if tbinfo['topo']['name'] not in ('t1', 't1-lag', 't1-64-lag', 't1-64-lag-clet'):
        pytest.skip('Unsupported topology')

    # gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    # get the list of TOR/SPINE ports
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        port_id = mg_facts['minigraph_port_indices'][dut_port]
        if 'T0' in neigh['name']:
            tor_ports.append(dut_port)
            tor_ports_ids.append(port_id)
        elif 'T2' in neigh['name']:
            spine_ports.append(dut_port)
            spine_ports_ids.append(port_id)

    # get the list of port channels
    port_channels = mg_facts['minigraph_portchannels']

    # get the list of port to be combined to ACL tables
    if tbinfo['topo']['name'] in ('t1', 't1-lag'):
        acl_table_ports += tor_ports

    if tbinfo['topo']['name'] in ('t1-lag', 't1-64-lag', 't1-64-lag-clet'):
        acl_table_ports += port_channels
    else:
        acl_table_ports += spine_ports

    logger.info('creating temporary folder for test {}'.format(DUT_TMP_DIR))
    duthost.command("mkdir -p {}".format(DUT_TMP_DIR))

    host_facts = duthost.setup()['ansible_facts']

    setup_information = {
        'router_mac': host_facts['ansible_Ethernet0']['macaddress'],
        'dut_tmp_dir': DUT_TMP_DIR,
        'tor_ports': tor_ports,
        'spine_ports': spine_ports,
        'tor_ports_ids': tor_ports_ids,
        'spine_ports_ids': spine_ports_ids,
        'port_channels': port_channels,
        'acl_table_ports': acl_table_ports,
        'dst_ip_tor': DST_IP_TOR,
        'dst_ip_tor_forwarded': DST_IP_TOR_FORWARDED,
        'dst_ip_tor_blocked': DST_IP_TOR_BLOCKED,
        'dst_ip_spine': DST_IP_SPINE,
        'dst_ip_spine_forwarded': DST_IP_SPINE_FORWARDED,
        'dst_ip_spine_blocked': DST_IP_SPINE_BLOCKED,
    }

    logger.info('setup variables {}'.format(pprint.pformat(setup_information)))

    # FIXME: There seems to be some issue with the initial setup of the ptfadapter, causing some of the
    # TestBasicAcl tests to fail because the forwarded packets are not being collected. This is an
    # attempt to mitigate that issue while we continue to investigate the root cause.
    #
    # Ref: GitHub Issue #2032
    logger.info("setting up the ptfadapter")
    ptfadapter.reinit()

    yield setup_information

    logger.info('removing {}'.format(DUT_TMP_DIR))
    duthost.command('rm -rf {}'.format(DUT_TMP_DIR))


@pytest.fixture(scope="module", params=["ingress", "egress"])
def stage(request, duthost):
    """
    Parametrize tests for Ingress/Egress stage testing.

    Args:
        request: Pytest request fixture
        duthost: DUT fixture

    Returns:
        str: The ACL stage to be tested.

    """
    if request.param == "egress" and duthost.facts["asic_type"] in ["broadcom"]:
        pytest.skip("Egress ACL stage not currently supported on {} ASIC"
                    .format(duthost.facts["asic_type"]))

    return request.param


@pytest.fixture(scope='module')
def acl_table_config(duthost, setup, stage):
    """
    generate ACL table configuration files and deploy them on DUT;
    after test run cleanup artifacts on DUT
    :param duthost: DUT host object
    :param setup: setup parameters
    :param stage: stage
    :return: dictionary of table name and matching configuration file
    """

    # Initialize data for ACL tables
    tables_map = {
        'ingress': 'DATAINGRESS',
        'egress': 'DATAEGRESS',
    }

    acl_table_name = tables_map[stage]
    tmp_dir = setup['dut_tmp_dir']

    acl_table_vars = {
        'acl_table_name':  acl_table_name,
        'acl_table_ports': setup['acl_table_ports'],
        'acl_table_stage': stage,
        'acl_table_type': 'L3',
    }

    logger.info('extra variables for ACL table:\n{}'.format(pprint.pformat(acl_table_vars)))
    duthost.host.options['variable_manager'].extra_vars.update(acl_table_vars)

    logger.info('generate config for ACL table {}'.format(acl_table_name))
    acl_config = 'acl_table_{}.json'.format(acl_table_name)
    acl_config_path = os.path.join(tmp_dir, acl_config)
    duthost.template(src=os.path.join(TEMPLATE_DIR, ACL_TABLE_TEMPLATE), dest=acl_config_path)

    yield {
        'name': acl_table_name,
        'config_file': acl_config_path,
    }


@pytest.fixture(scope="module")
def acl_table(duthost, acl_table_config, backup_and_restore_config_db_module):
    """
    fixture to apply ACL table configuration and remove after tests
    :param duthost: DUT object
    :param acl_table_config: ACL table configuration dictionary
    :return: forwards acl_table_config
    """

    name = acl_table_config['name']
    conf = acl_table_config['config_file']

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='acl')
    loganalyzer.load_common_config()

    try:
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
        with loganalyzer:
            logger.info('creating ACL table: applying {}'.format(conf))
            # TODO: use sonic config CLI
            duthost.command('sonic-cfggen -j {} --write-to-db'.format(conf))
    except LogAnalyzerError as err:
        # cleanup config DB if create failed
        duthost.command('config acl remove table {}'.format(name))
        raise err

    try:
        yield acl_table_config
    finally:
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_REMOVE_RE]
        with loganalyzer:
            logger.info('removing ACL table {}'.format(name))
            duthost.command('config acl remove table {}'.format(name))


class BaseAclTest(object):
    """
    Base class for ACL rules testing.
    Derivatives have to provide @setup_rules method to prepare DUT for ACL traffic test and
    optionally override @teardown_rules which base implementation is simply applying empty ACL rules
    configuration file
    """
    __metaclass__ = ABCMeta

    ACL_COUNTERS_UPDATE_INTERVAL = 10  # seconds

    @abstractmethod
    def setup_rules(self, dut, setup, acl_table):
        """
        setup rules for test
        :param dut: dut host
        :param setup: setup information
        :param acl_table: acl table creating fixture
        :return:
        """

        pass

    def post_setup_hook(self, dut, localhost):
        """
        perform actions after rules are applied
        :param dut: DUT host object
        :param localhost: localhost object
        :return:
        """

        pass

    def teardown_rules(self, dut, setup):
        """
        teardown ACL rules after test by applying empty configuration
        :param dut: DUT host object
        :param setup: setup information
        :return:
        """

        logger.info('removing all ACL rules')
        # copy rules remove configuration
        dut.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=setup['dut_tmp_dir'])
        remove_rules_dut_path = os.path.join(setup['dut_tmp_dir'], ACL_REMOVE_RULES_FILE)
        # remove rules
        logger.info('applying {}'.format(remove_rules_dut_path))
        dut.command('config acl update full {}'.format(remove_rules_dut_path))

    @pytest.fixture(scope='class', autouse=True)
    def acl_rules(self, duthost, localhost, setup, acl_table):
        """
        setup/teardown ACL rules based on test class requirements
        :param duthost: DUT host object
        :param localhost: localhost object
        :param setup: setup information
        :param acl_table: table creating fixture
        :return:
        """
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='acl_rules')
        loganalyzer.load_common_config()

        try:
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
            with loganalyzer:
                self.setup_rules(duthost, setup, acl_table)
            self.post_setup_hook(duthost, localhost)
        except LogAnalyzerError as err:
            # cleanup config DB in case of log analysis error
            self.teardown_rules(duthost, setup)
            raise err

        try:
            yield
        finally:
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_REMOVE_RE]
            with loganalyzer:
                self.teardown_rules(duthost, setup)

    @pytest.yield_fixture(scope='class', autouse=True)
    def counters_sanity_check(self, duthost, acl_rules, acl_table):
        """
        counters sanity check after traffic test cases.
        This fixture yields python list of rule IDs which test case should extend if
        the RULE is required to check for increased counters.
        After test cases passed the fixture will wait for ACL counters to update
        and check if counters for each rule in the list of rules were increased.
        :param duthost: DUT host object
        :param acl_rules: rules creating fixture
        :param acl_table: table creating fixture
        :return:
        """

        table_name = acl_table['name']
        acl_facts_before_traffic = duthost.acl_facts()['ansible_facts']['ansible_acl_facts'][table_name]['rules']
        rule_list = []
        yield rule_list

        if not rule_list:
            return

        # wait for orchagent to update ACL counters
        time.sleep(self.ACL_COUNTERS_UPDATE_INTERVAL)

        acl_facts_after_traffic = duthost.acl_facts()['ansible_facts']['ansible_acl_facts'][table_name]['rules']

        assert len(acl_facts_after_traffic) == len(acl_facts_before_traffic)

        for rule in rule_list:
            rule = 'RULE_{}'.format(rule)
            counters_after = acl_facts_after_traffic[rule]
            counters_before = acl_facts_before_traffic[rule]
            logger.info('counters for {} before traffic:\n{}'.format(rule, pprint.pformat(counters_before)))
            logger.info('counters for {} after traffic:\n{}'.format(rule, pprint.pformat(counters_after)))
            assert counters_after['packets_count'] > counters_before['packets_count']
            assert counters_after['bytes_count'] > counters_before['bytes_count']

    @pytest.fixture(params=['tor->spine', 'spine->tor'])
    def direction(self, request):
        """
        used to parametrized test cases on direction
        :param request: pytest request object
        :return: direction
        """

        return request.param

    def get_src_port(self, setup, direction):
        """ return source ports based on test case direction """

        src_ports = setup['tor_ports_ids'] if direction == 'tor->spine' else setup['spine_ports_ids']
        return random.choice(src_ports)

    def get_dst_ports(self, setup, direction):
        """ return destination ports based on test case direction """

        return setup['spine_ports_ids'] if direction == 'tor->spine' else setup['tor_ports_ids']

    def get_dst_ip(self, setup, direction):
        """ return allowed destination IP based on test case direction """

        return setup['dst_ip_spine'] if direction == 'tor->spine' else setup['dst_ip_tor']

    def tcp_packet(self, setup, direction, ptfadapter):
        """ create TCP packet for testing """

        return testutils.simple_tcp_packet(
            eth_dst=setup['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=self.get_dst_ip(setup, direction),
            ip_src='20.0.0.1',
            tcp_sport=0x4321,
            tcp_dport=0x51,
            ip_ttl=64,
        )

    def udp_packet(self, setup, direction, ptfadapter):
        """ create UDP packet for testing """

        return testutils.simple_udp_packet(
            eth_dst=setup['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=self.get_dst_ip(setup, direction),
            ip_src='20.0.0.1',
            udp_sport=1234,
            udp_dport=80,
            ip_ttl=64,
        )

    def icmp_packet(self, setup, direction, ptfadapter):
        """ create ICMP packet for testing """

        return testutils.simple_icmp_packet(
            eth_dst=setup['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=self.get_dst_ip(setup, direction),
            ip_src='20.0.0.1',
            icmp_type=8,
            icmp_code=0,
            ip_ttl=64,
        )

    def expected_mask_routed_packet(self, pkt):
        """ return mask for routed packet """

        exp_pkt = pkt.copy()
        exp_pkt['IP'].ttl -= 1
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
        return exp_pkt

    def test_unmatched_blocked(self, setup, direction, ptfadapter):
        """ verify that unmatched packet is dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

    def test_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test source IP matched packet is forwarded """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.2'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(1)

    def test_rules_priority_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test rules priorities, forward rule case """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.7'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(20)

    def test_rules_priority_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test rules priorities, drop rule case """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.3'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(7)

    def test_dest_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test destination IP matched packet forwarded """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].dst = DST_IP_TOR_FORWARDED if direction == 'spine->tor' else DST_IP_SPINE_FORWARDED
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(2 if direction == 'spine->tor' else 3)

    def test_dest_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test destination IP matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].dst = DST_IP_TOR_BLOCKED if direction == 'spine->tor' else DST_IP_SPINE_BLOCKED
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(15 if direction == 'spine->tor' else 16)

    def test_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test source IP matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.6'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(14)

    def test_udp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test UDP source IP matched packet forwarded """

        pkt = self.udp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.4'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(13)

    def test_udp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test UDP destination IP matched packet dropped """

        pkt = self.udp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.8'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(26)

    def test_icmp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test ICMP source IP matched packet dropped """

        pkt = self.icmp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.8'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(25)

    def test_icmp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test ICMP source IP matched packet forwarded """

        pkt = self.icmp_packet(setup, direction, ptfadapter)
        pkt['IP'].src = '20.0.0.4'
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(12)

    def test_l4_dport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 destination port matched packet forwarded """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].dport = 0x1217
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(5)

    def test_l4_sport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 source port matched packet forwarded """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].sport = 0x120D
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(4)

    def test_l4_dport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 destination port range matched packet forwarded """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].dport = 0x123B
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(11)

    def test_l4_sport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 source port range matched packet forwarded """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].sport = 0x123A
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(10)

    def test_l4_dport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 destination port range matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].dport = 0x127B
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(22)

    def test_l4_sport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 source port range matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].sport = 0x1271
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(17)

    def test_ip_proto_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test IP protocol matched packet forwarded"""

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].proto = 0x7E
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(5)

    def test_tcp_flags_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test TCP flags matched packet forwarded """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].flags = 0x1B
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(6)

    def test_l4_dport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 destination port matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].dport = 0x127B
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(22)

    def test_l4_sport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test L4 source port matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].sport = 0x1271
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(10)

    def test_ip_proto_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test IP protocol matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['IP'].proto = 0x7F
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(18)

    def test_tcp_flags_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check):
        """ test TCP flags matched packet dropped """

        pkt = self.tcp_packet(setup, direction, ptfadapter)
        pkt['TCP'].flags = 0x24
        exp_pkt = self.expected_mask_routed_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.get_src_port(setup, direction), pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))

        counters_sanity_check.append(5)


class TestBasicAcl(BaseAclTest):
    """
    Basic ACL rules traffic tests.
    Setup rules using full update, run traffic tests cases.
    """

    def setup_rules(self, dut, setup, acl_table):
        """
        setup rules on DUT
        :param dut: dut host
        :param setup: setup information
        :param acl_table: acl table creating fixture
        :return:
        """
        name = acl_table['name']
        dut_conf_file_path = os.path.join(setup['dut_tmp_dir'], 'acl_rules_{}.json'.format(name))

        logger.info('generating config for ACL rules, ACL table {}'.format(name))
        dut.template(src=os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE),
                     dest=dut_conf_file_path)

        logger.info('applying {}'.format(dut_conf_file_path))
        dut.command('config acl update full {}'.format(dut_conf_file_path))


class TestIncrementalAcl(BaseAclTest):
    """
    Incremental ACL rules configuration traffic tests.
    Setup rules using incremental update in two parts, run traffic tests cases.
    """

    def setup_rules(self, dut, setup, acl_table):
        """
        setup rules on DUT for incremental test
        :param dut: dut host
        :param setup: setup information
        :param acl_table: acl table creating fixture
        :return:
        """
        name = acl_table['name']
        logger.info('generate incremental config for ACL rule ACL table {table_name}'.format(table_name=name))
        for i, conf in enumerate(ACL_RULES_PART_TEMPLATES):
            dut_conf_file_path = os.path.join(setup['dut_tmp_dir'], 'acl_rules_{}_part_{}.json'.format(name, i))
            dut.template(src=os.path.join(TEMPLATE_DIR, conf), dest=dut_conf_file_path)
            logger.info('applying {}'.format(dut_conf_file_path))
            dut.command('config acl update incremental {}'.format(dut_conf_file_path))


@pytest.mark.reboot
class TestAclWithReboot(TestBasicAcl):
    """
    Basic ACL rules traffic tests with reboot.
    Verify that the ACL configurations persist after reboot
    """

    def post_setup_hook(self, dut, localhost):
        """
        save configuration and execute reboot after rules are applied
        :param dut: dut host
        :param localhost: localhost object
        :return:
        """
        dut.command('config save -y')
        reboot(dut, localhost)


@pytest.mark.port_toggle
class TestAclWithPortToggle(TestBasicAcl):
    """
    Basic ACL rules traffic tests with port toggle.
    Toggles ports before traffic tests.
    """

    def post_setup_hook(self, dut, localhost):
        """
        toggle ports after rules are applied
        :param dut: dut host
        :param localhost: localhost object
        :return:
        """
        port_toggle(dut)
