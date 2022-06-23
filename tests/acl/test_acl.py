from tests.common import reboot, port_toggle
import os
import time
import random
import logging
import pprint
import pytest
import json

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from abc import ABCMeta, abstractmethod
from collections import defaultdict

from tests.common import reboot, port_toggle
from tests.common.helpers.assertions import pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.config_reload import config_reload
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py, run_garp_service, change_mac_addresses
from tests.common.utilities import wait_until
from tests.common.dualtor.dual_tor_mock import mock_server_base_ip_addr
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.acl,
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("any"),
]

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = "acl_test_dir"  # Keep it under home dir so it persists through reboot
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

ACL_TABLE_TEMPLATE = "acltb_table.j2"
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"

# TODO: We really shouldn't have two separate templates for v4 and v6, need to combine them somehow
ACL_RULES_FULL_TEMPLATE = {
    "ipv4": "acltb_test_rules.j2",
    "ipv6": "acltb_v6_test_rules.j2"
}
ACL_RULES_PART_TEMPLATES = {
    "ipv4": tuple("acltb_test_rules_part_{}.j2".format(i) for i in xrange(1, 3)),
    "ipv6": tuple("acltb_v6_test_rules_part_{}.j2".format(i) for i in xrange(1, 3))
}

DEFAULT_SRC_IP = {
    "ipv4": "20.0.0.1",
    "ipv6": "60c0:a800::5"
}


# TODO: These routes don't match the VLAN interface from the T0 topology.
# This needs to be addressed before we can enable the v6 tests for T0
DOWNSTREAM_DST_IP = {
    "ipv4": "192.168.0.253",
    "ipv6": "20c0:a800::2"
}
DOWNSTREAM_IP_TO_ALLOW = {
    "ipv4": "192.168.0.252",
    "ipv6": "20c0:a800::4"
}
DOWNSTREAM_IP_TO_BLOCK = {
    "ipv4": "192.168.0.251",
    "ipv6": "20c0:a800::8"
}

DOWNSTREAM_IP_PORT_MAP = {}

UPSTREAM_DST_IP = {
    "ipv4": "192.168.128.1",
    "ipv6": "40c0:a800::2"
}
UPSTREAM_IP_TO_ALLOW = {
    "ipv4": "192.168.136.1",
    "ipv6": "40c0:a800::4"
}
UPSTREAM_IP_TO_BLOCK = {
    "ipv4": "192.168.144.1",
    "ipv6": "40c0:a800::8"
}

VLAN_BASE_MAC_PATTERN = "72060001{:04}"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"
LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"

PACKETS_COUNT = "packets_count"
BYTES_COUNT = "bytes_count"

@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(duthosts):
    """
    Remove DATAACL to free TCAM resources.
    The change is written to configdb as we don't want DATAACL recovered after reboot  
    """
    TABLE_NAME = "DATAACL"
    for duthost in duthosts:
        lines = duthost.shell(cmd="show acl table {}".format(TABLE_NAME))['stdout_lines']
        data_acl_existing = False
        for line in lines:
            if TABLE_NAME in line:
                data_acl_existing = True
                break
        if data_acl_existing:
            # Remove DATAACL
            logger.info("Removing ACL table {}".format(TABLE_NAME))
            cmds = [
                "config acl remove table {}".format(TABLE_NAME),
                "config save -y"
            ]
            duthost.shell_cmds(cmds=cmds)
    yield
    # Recover DUT by reloading minigraph
    for duthost in duthosts:
        config_reload(duthost, config_source="minigraph")

@pytest.fixture(scope="module")
def setup(duthosts, ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter):
    """Gather all required test information from DUT and tbinfo.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        tbinfo: A fixture to gather information about the testbed.

    Yields:
        A Dictionary with required test information.

    """

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]

    vlan_ports = []
    vlan_mac = None

    if topo == "t0":
        vlan_ports = [mg_facts["minigraph_ptf_indices"][ifname]
                      for ifname in mg_facts["minigraph_vlans"].values()[0]["members"]]

        config_facts = rand_selected_dut.get_running_config_facts()
        vlan_table = config_facts["VLAN"]
        vlan_name = list(vlan_table.keys())[0]
        if "mac" in vlan_table[vlan_name]:
            vlan_mac = vlan_table[vlan_name]["mac"]

    # Get the list of upstream/downstream ports
    downstream_ports = defaultdict(list)
    upstream_ports =  defaultdict(list)
    downstream_port_ids = []
    upstream_port_ids = []
    upstream_port_id_to_router_mac_map = {}
    downstream_port_id_to_router_mac_map = {}

    # For T0/dual ToR testbeds, we need to use the VLAN MAC to interact with downstream ports
    # For T1 testbeds, no VLANs are present so using the router MAC is acceptable
    downlink_dst_mac = vlan_mac if vlan_mac is not None else rand_selected_dut.facts["router_mac"]

    for interface, neighbor in mg_facts["minigraph_neighbors"].items():
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t1" and "T0" in neighbor["name"]) or (topo == "t0" and "Server" in neighbor["name"]):
            downstream_ports[neighbor['namespace']].append(interface)
            downstream_port_ids.append(port_id)
            downstream_port_id_to_router_mac_map[port_id] = downlink_dst_mac
        elif (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]):
            upstream_ports[neighbor['namespace']].append(interface)
            upstream_port_ids.append(port_id)
            upstream_port_id_to_router_mac_map[port_id] = rand_selected_dut.facts["router_mac"]

    # stop garp service for single tor
    if 'dualtor' not in tbinfo['topo']['name']:
        logging.info("Stopping GARP service on single tor")
        ptfhost.shell("supervisorctl stop garp_service", module_ignore_errors=True)

    # If running on a dual ToR testbed, any uplink for either ToR is an acceptable
    # source or destination port
    if 'dualtor' in tbinfo['topo']['name'] and rand_unselected_dut is not None:
        peer_mg_facts = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
        for interface, neighbor in peer_mg_facts['minigraph_neighbors'].items():
            if (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]):
                port_id = peer_mg_facts["minigraph_ptf_indices"][interface]
                upstream_port_ids.append(port_id)
                upstream_port_id_to_router_mac_map[port_id] = rand_unselected_dut.facts["router_mac"]

    # Get the list of LAGs
    port_channels = mg_facts["minigraph_portchannels"]

    # TODO: We should make this more robust (i.e. bind all active front-panel ports)
    acl_table_ports =  defaultdict(list)

    if topo == "t0" or tbinfo["topo"]["name"] in ("t1", "t1-lag"):
        for namespace, port in downstream_ports.iteritems():
            acl_table_ports[namespace] += port
            # In multi-asic we need config both in host and namespace.
            if namespace:
                acl_table_ports[''] += port

    if topo == "t0" or tbinfo["topo"]["name"] in ("t1-lag", "t1-64-lag", "t1-64-lag-clet"):
        for k, v in port_channels.iteritems():
            acl_table_ports[v['namespace']].append(k)
            # In multi-asic we need config both in host and namespace.
            if v['namespace']:
                acl_table_ports[''].append(k)
    else:
        for namespace, port in upstream_ports.iteritems():
            acl_table_ports[namespace] += port
            # In multi-asic we need config both in host and namespace.
            if namespace:
                acl_table_ports[''] += port

    dest_mac_mapping = {
        "downlink->uplink": downstream_port_id_to_router_mac_map,
        "uplink->downlink": upstream_port_id_to_router_mac_map
    }

    setup_information = {
        "destination_mac": dest_mac_mapping,
        "downstream_port_ids": downstream_port_ids,
        "upstream_port_ids": upstream_port_ids,
        "acl_table_ports": acl_table_ports,
        "vlan_ports": vlan_ports,
        "topo": topo,
        "vlan_mac": vlan_mac
    }

    logger.info("Gathered variables for ACL test:\n{}".format(pprint.pformat(setup_information)))

    logger.info("Creating temporary folder \"{}\" for ACL test".format(DUT_TMP_DIR))
    for duthost in duthosts:
        duthost.command("mkdir -p {}".format(DUT_TMP_DIR))

    yield setup_information

    logger.info("Removing temporary directory \"{}\"".format(DUT_TMP_DIR))
    for duthost in duthosts:
        duthost.command("rm -rf {}".format(DUT_TMP_DIR))


@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def ip_version(request, tbinfo, duthosts, rand_one_dut_hostname):
    if tbinfo["topo"]["type"] == "t0" and request.param == "ipv6":
        pytest.skip("IPV6 ACL test not currently supported on t0 testbeds")

    return request.param


@pytest.fixture(scope="module")
def populate_vlan_arp_entries(setup, ptfhost, duthosts, rand_one_dut_hostname, ip_version):
    """Set up the ARP responder utility in the PTF container."""
    duthost = duthosts[rand_one_dut_hostname]
    if setup["topo"] != "t0":
        def noop():
            pass

        yield noop

        return  # Don't fall through to t0 case

    addr_list = [DOWNSTREAM_DST_IP[ip_version], DOWNSTREAM_IP_TO_ALLOW[ip_version], DOWNSTREAM_IP_TO_BLOCK[ip_version]]

    vlan_host_map = defaultdict(dict)
    for i in range(len(addr_list)):
        mac = VLAN_BASE_MAC_PATTERN.format(i)
        port = random.choice(setup["vlan_ports"])
        addr = addr_list[i]
        vlan_host_map[port][str(addr)] = mac
        DOWNSTREAM_IP_PORT_MAP[addr] = port

    arp_responder_conf = {}
    for port in vlan_host_map:
        arp_responder_conf['eth{}'.format(port)] = vlan_host_map[port]

    with open("/tmp/from_t1.json", "w") as ar_config:
        json.dump(arp_responder_conf, ar_config)
    ptfhost.copy(src="/tmp/from_t1.json", dest="/tmp/from_t1.json")

    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": "-e"})
    ptfhost.template(src="templates/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread && supervisorctl update")
    ptfhost.shell("supervisorctl restart arp_responder")

    def populate_arp_table():
        for dut in duthosts:
            dut.command("sonic-clear fdb all")
            dut.command("sonic-clear arp")
            # Wait some time to ensure the async call of clear is completed
            time.sleep(20)
            for addr in addr_list:
                dut.command("ping {} -c 3".format(addr), module_ignore_errors=True)

    populate_arp_table()

    yield populate_arp_table

    logging.info("Stopping ARP responder")
    ptfhost.shell("supervisorctl stop arp_responder")

    duthost.command("sonic-clear fdb all")
    duthost.command("sonic-clear arp")


@pytest.fixture(scope="module", params=["ingress", "egress"])
def stage(request, duthosts, rand_one_dut_hostname):
    """Parametrize tests for Ingress/Egress stage testing.

    Args:
        request: A fixture to interact with Pytest data.
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.

    Returns:
        str: The ACL stage to be tested.

    """
    duthost = duthosts[rand_one_dut_hostname]
    pytest_require(
        request.param == "ingress" or duthost.facts["asic_type"] not in ("broadcom"),
        "Egress ACLs are not currently supported on \"{}\" ASICs".format(duthost.facts["asic_type"])
    )

    return request.param

def create_or_remove_acl_table(duthost, acl_table_config, setup, op):
    for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
        namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst, 'namespace') else ''
        if op == "add":
            logger.info("Creating ACL table: \"{}\" in namespace {} on device {}".format(acl_table_config["table_name"], namespace, duthost))
            sonic_host_or_asic_inst.command(
                "config acl add table {} {} -s {} -p {}".format(
                    acl_table_config["table_name"],
                    acl_table_config["table_type"],
                    acl_table_config["table_stage"],
                    ",".join(setup["acl_table_ports"][namespace]),
                )
            )
        else:
            logger.info("Removing ACL table \"{}\" in namespace {} on device {}".format(acl_table_config["table_name"], namespace, duthost))
            sonic_host_or_asic_inst.command("config acl remove table {}".format(acl_table_config["table_name"]))

@pytest.fixture(scope="module")
def acl_table(duthosts, rand_one_dut_hostname, setup, stage, ip_version):
    """Apply ACL table configuration and remove after tests.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        setup: Parameters for the ACL tests.
        stage: The ACL stage under test.
        ip_version: The IP version under test

    Yields:
        The ACL table configuration.

    """
    table_name = "DATA_{}_{}_TEST".format(stage.upper(), ip_version.upper())

    acl_table_config = {
        "table_name": table_name,
        "table_ports": ",".join(setup["acl_table_ports"]['']),
        "table_stage": stage,
        "table_type": "L3" if ip_version == "ipv4" else "L3V6"
    }
    logger.info("Generated ACL table configuration:\n{}".format(pprint.pformat(acl_table_config)))

    dut_to_analyzer_map = {}

    for duthost in duthosts:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl")
        loganalyzer.load_common_config()
        dut_to_analyzer_map[duthost] = loganalyzer

        try:
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
            # Ignore any other errors to reduce noise
            loganalyzer.ignore_regex = [r".*"]
            with loganalyzer:
                create_or_remove_acl_table(duthost, acl_table_config, setup, "add")
        except LogAnalyzerError as err:
            # Cleanup Config DB if table creation failed
            logger.error("ACL table creation failed, attempting to clean-up...")
            create_or_remove_acl_table(duthost, acl_table_config, setup, "remove")
            raise err

    try:
        yield acl_table_config
    finally:
        for duthost, loganalyzer in dut_to_analyzer_map.items():
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_REMOVE_RE]
            with loganalyzer:
                create_or_remove_acl_table(duthost, acl_table_config, setup, "remove")

class BaseAclTest(object):
    """Base class for testing ACL rules.

    Subclasses must provide `setup_rules` method to prepare ACL rules for traffic testing.

    They can optionally override `teardown_rules`, which will otherwise remove the rules by
    applying an empty configuration file.
    """

    __metaclass__ = ABCMeta

    ACL_COUNTERS_UPDATE_INTERVAL_SECS = 10

    @abstractmethod
    def setup_rules(self, dut, acl_table, ip_version):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        pass

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo):
        """Perform actions after rules have been applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A function to populate ARP/FDB tables for VLAN interfaces.

        """
        pass

    def teardown_rules(self, dut):
        """Tear down ACL rules once the tests have completed.

        Args:
            dut: The DUT having ACLs applied.

        """
        logger.info("Finished with tests, removing all ACL rules...")

        # Copy empty rules configuration
        dut.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=DUT_TMP_DIR)
        remove_rules_dut_path = os.path.join(DUT_TMP_DIR, ACL_REMOVE_RULES_FILE)

        # Remove the rules
        logger.info("Applying \"{}\"".format(remove_rules_dut_path))
        dut.command("config acl update full {}".format(remove_rules_dut_path))

    @pytest.fixture(scope="class", autouse=True)
    def acl_rules(self, duthosts, localhost, setup, acl_table, populate_vlan_arp_entries, tbinfo, ip_version):
        """Setup/teardown ACL rules for the current set of tests.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
            localhost: The host from which tests are run.
            setup: Parameters for the ACL tests.
            acl_table: Configuration info for the ACL table.
            populate_vlan_arp_entries: A function to populate ARP/FDB tables for VLAN interfaces.

        """
        dut_to_analyzer_map = {}
        for duthost in duthosts:
            loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl_rules")
            loganalyzer.load_common_config()
            dut_to_analyzer_map[duthost] = loganalyzer

            try:
                loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
                # Ignore any other errors to reduce noise
                loganalyzer.ignore_regex = [r".*"]
                with loganalyzer:
                    self.setup_rules(duthost, acl_table, ip_version)

                self.post_setup_hook(duthost, localhost, populate_vlan_arp_entries, tbinfo)

                assert self.check_rule_counters(duthost), "Rule counters should be ready!"

            except LogAnalyzerError as err:
                # Cleanup Config DB if rule creation failed
                logger.error("ACL rule application failed, attempting to clean-up...")
                self.teardown_rules(duthost)
                raise err

        try:
            yield
        finally:
            for duthost, loganalyzer in dut_to_analyzer_map.items():
                loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_REMOVE_RE]
                with loganalyzer:
                    logger.info("Removing ACL rules")
                    self.teardown_rules(duthost)

    @pytest.yield_fixture(scope="class", autouse=True)
    def counters_sanity_check(self, duthosts, acl_rules, acl_table):
        """Validate that the counters for each rule in the rules list increased as expected.

        This fixture yields a list of rule IDs. The test case should add on to this list if
        it is required to check the rule for increased counters.

        After the test cases pass, the fixture will wait for the ACL counters to update and then
        check if the counters for each rule in the list were increased.

        Args:
            duthosts: All DUTs belong to the testbed.
            rand_one_dut_hostname: hostname of a random chosen dut to run test.
            acl_rules: Fixture that sets up the ACL rules.
            acl_table: Fixture that sets up the ACL table.

        """
        acl_facts = defaultdict(dict)
        table_name = acl_table["table_name"]
        for duthost in duthosts:
            acl_facts[duthost]['before']= duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"][table_name]["rules"]

        rule_list = []
        yield rule_list

        if not rule_list:
            return

        # Wait for orchagent to update the ACL counters
        time.sleep(self.ACL_COUNTERS_UPDATE_INTERVAL_SECS)

        for duthost in duthosts:
            acl_facts[duthost]['after']= duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"][table_name]["rules"]

        for duthost in duthosts:
            assert len(acl_facts[duthost]['before']) == len(acl_facts[duthost]['after'])

        for rule in rule_list:
            rule = "RULE_{}".format(rule)

            counters_before = {
                PACKETS_COUNT: 0,
                BYTES_COUNT: 0
            }
            for duthost in duthosts:
                counters_before[PACKETS_COUNT] += acl_facts[duthost]['before'][rule][PACKETS_COUNT]
                counters_before[BYTES_COUNT] += acl_facts[duthost]['before'][rule][BYTES_COUNT]
            logger.info("Counters for ACL rule \"{}\" before traffic:\n{}"
                        .format(rule, pprint.pformat(counters_before)))

            counters_after = {
                PACKETS_COUNT: 0,
                BYTES_COUNT: 0
            }
            for duthost in duthosts:
                counters_after[PACKETS_COUNT] += acl_facts[duthost]['after'][rule][PACKETS_COUNT]
                counters_after[BYTES_COUNT] += acl_facts[duthost]['after'][rule][BYTES_COUNT]

            logger.info("Counters for ACL rule \"{}\" after traffic:\n{}"
                        .format(rule, pprint.pformat(counters_after)))

            assert counters_after[PACKETS_COUNT] > counters_before[PACKETS_COUNT]
            assert counters_after[BYTES_COUNT] > counters_before[BYTES_COUNT]

    @pytest.fixture(params=["downlink->uplink", "uplink->downlink"])
    def direction(self, request):
        """Parametrize test based on direction of traffic."""
        return request.param

    def check_rule_counters(self, duthost):
        logger.info('Wait all rule counters are ready')

        return wait_until(60, 2, 0, self.check_rule_counters_internal, duthost)

    def check_rule_counters_internal(self, duthost):
        for asic_id in duthost.get_frontend_asic_ids():
            res = duthost.asic_instance(asic_id).command('aclshow -a')

            num_of_lines = len(res['stdout'].split('\n'))

            if num_of_lines <= 2 or 'N/A' in res['stdout']:
                return False

        return True

    @pytest.fixture(autouse=True)
    def get_src_port(self, setup, direction):
        """Get a source port for the current test."""
        src_ports = setup["downstream_port_ids"] if direction == "downlink->uplink" else setup["upstream_port_ids"]
        src_port = random.choice(src_ports)
        logger.info("Selected source port {}".format(src_port))
        self.src_port = src_port

    def get_dst_ports(self, setup, direction):
        """Get the set of possible destination ports for the current test."""
        return setup["upstream_port_ids"] if direction == "downlink->uplink" else setup["downstream_port_ids"]

    def get_dst_ip(self, direction, ip_version):
        """Get the default destination IP for the current test."""
        return UPSTREAM_DST_IP[ip_version] if direction == "downlink->uplink" else DOWNSTREAM_DST_IP[ip_version]

    def tcp_packet(self, setup, direction, ptfadapter, ip_version, src_ip=None, dst_ip=None, proto=None, sport=0x4321, dport=0x51, flags=None):
        """Generate a TCP packet for testing."""
        src_ip = src_ip or DEFAULT_SRC_IP[ip_version]
        dst_ip = dst_ip or self.get_dst_ip(direction, ip_version)
        if ip_version == "ipv4":
            pkt = testutils.simple_tcp_packet(
                eth_dst=setup["destination_mac"][direction][self.src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ip_dst=dst_ip,
                ip_src=src_ip,
                tcp_sport=sport,
                tcp_dport=dport,
                ip_ttl=64
            )

            if proto:
                pkt["IP"].proto = proto
        else:
            pkt = testutils.simple_tcpv6_packet(
                eth_dst=setup["destination_mac"][direction][self.src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ipv6_dst=dst_ip,
                ipv6_src=src_ip,
                tcp_sport=sport,
                tcp_dport=dport,
                ipv6_hlim=64
            )

            if proto:
                pkt["IPv6"].nh = proto

        if flags:
            pkt["TCP"].flags = flags

        return pkt

    def udp_packet(self, setup, direction, ptfadapter, ip_version, src_ip=None, dst_ip=None, sport=1234, dport=80):
        """Generate a UDP packet for testing."""
        src_ip = src_ip or DEFAULT_SRC_IP[ip_version]
        dst_ip = dst_ip or self.get_dst_ip(direction, ip_version)
        if ip_version == "ipv4":
            return testutils.simple_udp_packet(
                eth_dst=setup["destination_mac"][direction][self.src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ip_dst=dst_ip,
                ip_src=src_ip,
                udp_sport=sport,
                udp_dport=dport,
                ip_ttl=64
            )
        else:
            return testutils.simple_udpv6_packet(
                eth_dst=setup["destination_mac"][direction][self.src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ipv6_dst=dst_ip,
                ipv6_src=src_ip,
                udp_sport=sport,
                udp_dport=dport,
                ipv6_hlim=64
            )

    def icmp_packet(self, setup, direction, ptfadapter, ip_version, src_ip=None, dst_ip=None, icmp_type=8, icmp_code=0):
        """Generate an ICMP packet for testing."""
        src_ip = src_ip or DEFAULT_SRC_IP[ip_version]
        dst_ip = dst_ip or self.get_dst_ip(direction, ip_version)
        if ip_version == "ipv4":
            return testutils.simple_icmp_packet(
                eth_dst=setup["destination_mac"][direction][self.src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ip_dst=dst_ip,
                ip_src=src_ip,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                ip_ttl=64,
            )
        else:
            return testutils.simple_icmpv6_packet(
                eth_dst=setup["destination_mac"][direction][self.src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ipv6_dst=dst_ip,
                ipv6_src=src_ip,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                ipv6_hlim=64,
            )

    def expected_mask_routed_packet(self, pkt, ip_version):
        """Generate the expected mask for a routed packet."""
        exp_pkt = pkt.copy()

        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(packet.Ether, "src")

        if ip_version == "ipv4":
            exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
            # In multi-asic we cannot determine this so ignore.
            exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
        else:
            # In multi-asic we cannot determine this so ignore.
            exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')


        return exp_pkt

    def test_ingress_unmatched_blocked(self, setup, direction, ptfadapter, ip_version, stage):
        """Verify that unmatched packets are dropped for ingress."""
        if stage == "egress":
            pytest.skip("Only run for ingress")

        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version)
        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)

    def test_egress_unmatched_forwarded(self, setup, direction, ptfadapter, ip_version, stage):
        """Verify that default egress rule allow all traffics"""
        if stage == "ingress":
            pytest.skip("Only run for egress")

        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version)
        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)

    def test_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward a packet on source IP."""
        src_ip = "20.0.0.2" if ip_version == "ipv4" else "60c0:a800::6"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(1)

    def test_rules_priority_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we respect rule priorites in the forwarding case."""
        src_ip = "20.0.0.7" if ip_version == "ipv4" else "60c0:a800::7"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(20)

    def test_rules_priority_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we respect rule priorites in the drop case."""
        src_ip = "20.0.0.3" if ip_version == "ipv4" else "60c0:a800::4"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(7)

    def test_dest_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward a packet on destination IP."""
        dst_ip = DOWNSTREAM_IP_TO_ALLOW[ip_version] if direction == "uplink->downlink" else UPSTREAM_IP_TO_ALLOW[ip_version]
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dst_ip=dst_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(2 if direction == "uplink->downlink" else 3)

    def test_dest_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop a packet on destination IP."""
        dst_ip = DOWNSTREAM_IP_TO_BLOCK[ip_version] if direction == "uplink->downlink" else UPSTREAM_IP_TO_BLOCK[ip_version]
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dst_ip=dst_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(15 if direction == "uplink->downlink" else 16)

    def test_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop a packet on source IP."""
        src_ip = "20.0.0.6" if ip_version == "ipv4" else "60c0:a800::3"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(14)

    def test_udp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward a UDP packet on source IP."""
        src_ip = "20.0.0.4" if ip_version == "ipv4" else "60c0:a800::8"
        pkt = self.udp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(13)

    def test_udp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop a UDP packet on source IP."""
        src_ip = "20.0.0.8" if ip_version == "ipv4" else "60c0:a800::2"
        pkt = self.udp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(26)

    def test_icmp_source_ip_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop an ICMP packet on source IP."""
        src_ip = "20.0.0.8" if ip_version == "ipv4" else "60c0:a800::2"
        pkt = self.icmp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(25)

    def test_icmp_source_ip_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward an ICMP packet on source IP."""
        src_ip = "20.0.0.4" if ip_version == "ipv4" else "60c0:a800::8"
        pkt = self.icmp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(12)

    def test_l4_dport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward on L4 destination port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=0x1217)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(5)

    def test_l4_sport_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward on L4 source port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=0x120D)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(4)

    def test_l4_dport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward on a range of L4 destination ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=0x123B)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(11)

    def test_l4_sport_range_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward on a range of L4 source ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=0x123A)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(10)

    def test_l4_dport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop on a range of L4 destination ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=0x127B)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(22)

    def test_l4_sport_range_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop on a range of L4 source ports."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=0x1271)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(17)

    def test_ip_proto_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward on the IP protocol."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, proto=0x7E)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(5)

    def test_tcp_flags_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and forward on the TCP flags."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, flags=0x1B)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(6)

    def test_l4_dport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop on L4 destination port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=0x127B)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(22)

    def test_l4_sport_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop on L4 source port."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=0x1271)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(10)

    def test_ip_proto_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop on the IP protocol."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, proto=0x7F)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(18)

    def test_tcp_flags_match_dropped(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop on the TCP flags."""
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, flags=0x24)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        counters_sanity_check.append(5)

    def test_icmp_match_forwarded(self, setup, direction, ptfadapter, counters_sanity_check, ip_version):
        """Verify that we can match and drop on the TCP flags."""
        src_ip = "20.0.0.10" if ip_version == "ipv4" else "60c0:a800::10"
        pkt = self.icmp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip, icmp_type=3, icmp_code=1)

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)
        counters_sanity_check.append(29)

    def _verify_acl_traffic(self, setup, direction, ptfadapter, pkt, dropped, ip_version):
        exp_pkt = self.expected_mask_routed_packet(pkt, ip_version)

        if ip_version == "ipv4":
            downstream_dst_port = DOWNSTREAM_IP_PORT_MAP.get(pkt[packet.IP].dst)
        else:
            downstream_dst_port = DOWNSTREAM_IP_PORT_MAP.get(pkt[packet.IPv6].dst)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.src_port, pkt)
        if direction == "uplink->downlink" and downstream_dst_port:
            if dropped:
                testutils.verify_no_packet(ptfadapter, exp_pkt, downstream_dst_port)
            else:
                testutils.verify_packet(ptfadapter, exp_pkt, downstream_dst_port)
        else:
            if dropped:
                testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))
            else:
                testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction),
                                                 timeout=20)


class TestBasicAcl(BaseAclTest):
    """Test Basic functionality of ACL rules (i.e. setup with full update on a running device)."""

    def setup_rules(self, dut, acl_table, ip_version):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        table_name = acl_table["table_name"]
        dut.host.options["variable_manager"].extra_vars.update({"acl_table_name": table_name})

        logger.info("Generating basic ACL rules config for ACL table \"{}\" on {}".format(table_name, dut))

        dut_conf_file_path = os.path.join(DUT_TMP_DIR, "acl_rules_{}.json".format(table_name))
        dut.template(src=os.path.join(TEMPLATE_DIR, ACL_RULES_FULL_TEMPLATE[ip_version]),
                     dest=dut_conf_file_path)

        logger.info("Applying ACL rules config \"{}\"".format(dut_conf_file_path))
        dut.command("config acl update full {}".format(dut_conf_file_path))


class TestIncrementalAcl(BaseAclTest):
    """Test ACL rule functionality with an incremental configuration.

    Verify that everything still works as expected when an ACL configuration is applied in
    multiple parts.
    """

    def setup_rules(self, dut, acl_table, ip_version):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        table_name = acl_table["table_name"]
        dut.host.options["variable_manager"].extra_vars.update({"acl_table_name": table_name})

        logger.info("Generating incremental ACL rules config for ACL table \"{}\""
                    .format(table_name))

        for part, config_file in enumerate(ACL_RULES_PART_TEMPLATES[ip_version]):
            dut_conf_file_path = os.path.join(DUT_TMP_DIR, "acl_rules_{}_part_{}.json".format(table_name, part))
            dut.template(src=os.path.join(TEMPLATE_DIR, config_file), dest=dut_conf_file_path)

            logger.info("Applying ACL rules config \"{}\"".format(dut_conf_file_path))
            dut.command("config acl update incremental {}".format(dut_conf_file_path))


@pytest.mark.reboot
class TestAclWithReboot(TestBasicAcl):
    """Test ACL rule functionality with a reboot.

    Verify that configuration persists correctly after reboot and is applied properly
    upon startup.
    """

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo):
        """Save configuration and reboot after rules are applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A fixture to populate ARP/FDB tables for VLAN interfaces.

        """
        dut.command("config save -y")
        reboot(dut, localhost, wait=240)
        # We need some additional delay on e1031
        if dut.facts["platform"] == "x86_64-cel_e1031-r0":
            time.sleep(240)
        populate_vlan_arp_entries()


@pytest.mark.port_toggle
class TestAclWithPortToggle(TestBasicAcl):
    """Test ACL rule functionality after toggling ports.

    Verify that ACLs still function as expected after links flap.
    """

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo):
        """Toggle ports after rules are applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A fixture to populate ARP/FDB tables for VLAN interfaces.

        """
        port_toggle(dut, tbinfo)
        populate_vlan_arp_entries()
