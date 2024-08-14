import os
import time
import random
import logging
import pprint
import pytest
import json
import six
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from abc import ABCMeta, abstractmethod
from collections import defaultdict

from tests.common import reboot, port_toggle
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.config_reload import config_reload
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py, run_garp_service, change_mac_addresses   # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test       # noqa F401
from tests.common.dualtor.dual_tor_mock import mock_server_base_ip_addr # noqa F401
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until, get_upstream_neigh_type, get_downstream_neigh_type, check_msg_in_syslog
from tests.common.fixtures.conn_graph_facts import conn_graph_facts # noqa F401
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.interface_utils import check_all_interface_information

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.acl,
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("t0", "t1", "t2", "m0", "mx"),
]

MAX_WAIT_TIME_FOR_INTERFACES = 360

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
    "ipv4": tuple("acltb_test_rules_part_{}.j2".format(i) for i in range(1, 3)),
    "ipv6": tuple("acltb_v6_test_rules_part_{}.j2".format(i) for i in range(1, 3))
}

DEFAULT_SRC_IP = {
    "ipv4": "20.0.0.1",
    "ipv6": "60c0:a800::5"
}


# TODO: These routes don't match the VLAN interface from the T0 topology.
# This needs to be addressed before we can enable the v6 tests for T0
DOWNSTREAM_DST_IP = {
    "ipv4": "192.168.0.253",
    "ipv6": "20c0:a800::14"
}
DOWNSTREAM_IP_TO_ALLOW = {
    "ipv4": "192.168.0.252",
    "ipv6": "20c0:a800::1"
}
DOWNSTREAM_IP_TO_BLOCK = {
    "ipv4": "192.168.0.251",
    "ipv6": "20c0:a800::9"
}

# Below M0_L3 IPs are announced to DUT by annouce_route.py, it point to neighbor mx
DOWNSTREAM_DST_IP_M0_L3 = {
    "ipv4": "192.168.1.65",
    "ipv6": "20c0:a800:0:1::14"
}
DOWNSTREAM_IP_TO_ALLOW_M0_L3 = {
    "ipv4": "192.168.1.66",
    "ipv6": "20c0:a800:0:1::1"
}
DOWNSTREAM_IP_TO_BLOCK_M0_L3 = {
    "ipv4": "192.168.1.67",
    "ipv6": "20c0:a800:0:1::9"
}

# Below M0_VLAN IPs are ip in vlan range
DOWNSTREAM_DST_IP_VLAN = {
    "ipv4": "192.168.0.123",
    "ipv6": "fc02:1000::5"
}
DOWNSTREAM_IP_TO_ALLOW_VLAN = {
    "ipv4": "192.168.0.122",
    "ipv6": "fc02:1000::6"
}
DOWNSTREAM_IP_TO_BLOCK_VLAN = {
    "ipv4": "192.168.0.121",
    "ipv6": "fc02:1000::7"
}

DOWNSTREAM_DST_IP_VLAN2000 = {
    "ipv4": "192.168.0.253",
    "ipv6": "fc02:1000:0:1::5"
}
DOWNSTREAM_IP_TO_ALLOW_VLAN2000 = {
    "ipv4": "192.168.0.252",
    "ipv6": "fc02:1000:0:1::6"
}
DOWNSTREAM_IP_TO_BLOCK_VLAN2000 = {
    "ipv4": "192.168.0.251",
    "ipv6": "fc02:1000:0:1::7"
}

DOWNSTREAM_IP_PORT_MAP = {}

UPSTREAM_DST_IP = {
    "ipv4": "194.50.16.1",
    "ipv6": "20c1:d180::11"
}
UPSTREAM_IP_TO_ALLOW = {
    "ipv4": "193.191.32.1",
    "ipv6": "20c1:cb50::12"
}
UPSTREAM_IP_TO_BLOCK = {
    "ipv4": "193.221.112.1",
    "ipv6": "20c1:e2f0::13"
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


def get_t2_info(duthosts, tbinfo):
    # Get the list of upstream/downstream ports
    downstream_ports, upstream_ports, acl_table_ports_per_dut = defaultdict(list), defaultdict(list), defaultdict(list)
    upstream_port_id_to_router_mac_map, downstream_port_id_to_router_mac_map = {}, {}
    downstream_port_ids, upstream_port_ids = [], []
    port_channels = dict()

    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        upstream_ports_per_dut, downstream_ports_per_dut, acl_table_ports = (defaultdict(list),
                                                                             defaultdict(list), defaultdict(list))

        for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
            namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst, 'namespace') \
                  else DEFAULT_NAMESPACE
            if duthost.sonichost.is_multi_asic and namespace == DEFAULT_NAMESPACE:
                continue
            asic_id = duthost.get_asic_id_from_namespace(namespace)
            router_mac = duthost.asic_instance(asic_id).get_router_mac()
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace)
            for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
                port_id = mg_facts["minigraph_ptf_indices"][interface]
                if "T1" in neighbor["name"]:
                    downstream_ports_per_dut[namespace].append(interface)
                    downstream_port_ids.append(port_id)
                    downstream_port_id_to_router_mac_map[port_id] = router_mac
                elif "T3" in neighbor["name"]:
                    upstream_ports_per_dut[namespace].append(interface)
                    upstream_port_ids.append(port_id)
                    upstream_port_id_to_router_mac_map[port_id] = router_mac
                mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace)

            port_channels[namespace] = mg_facts["minigraph_portchannels"]
            backend_pc = list()
            for k in port_channels[namespace]:
                if duthost.is_backend_portchannel(k, mg_facts):
                    backend_pc.append(k)
            for pc in backend_pc:
                port_channels[namespace].pop(pc)

            upstream_rifs = upstream_ports_per_dut[namespace]
            downstream_rifs = downstream_ports_per_dut[namespace]
            for k, v in list(port_channels[namespace].items()):
                acl_table_ports[namespace].append(k)
                acl_table_ports[''].append(k)
                upstream_rifs = list(set(upstream_rifs) - set(v['members']))
                downstream_rifs = list(set(downstream_rifs) - set(v['members']))
            if len(upstream_rifs):
                for port in upstream_rifs:
                    # This code is commented due to a bug which restricts rif interfaces to
                    # be added to global acl table - https://github.com/sonic-net/sonic-utilities/issues/2185
                    if namespace == DEFAULT_NAMESPACE:
                        acl_table_ports[''].append(port)
                    else:
                        acl_table_ports[namespace].append(port)
            else:
                for port in downstream_rifs:
                    # This code is commented due to a bug which restricts rif interfaces to
                    # be added to global acl table - https://github.com/sonic-net/sonic-utilities/issues/2185
                    if namespace == DEFAULT_NAMESPACE:
                        acl_table_ports[''].append(port)
                    else:
                        acl_table_ports[namespace].append(port)

        acl_table_ports_per_dut[duthost] = acl_table_ports
        downstream_ports[duthost] = downstream_ports_per_dut
        upstream_ports[duthost] = upstream_ports_per_dut

    t2_information = {
        "upstream_port_ids": upstream_port_ids,
        "downstream_port_ids": downstream_port_ids,
        "downstream_port_id_to_router_mac_map": downstream_port_id_to_router_mac_map,
        "upstream_port_id_to_router_mac_map": upstream_port_id_to_router_mac_map,
        "acl_table_ports": acl_table_ports_per_dut
    }

    return t2_information


@pytest.fixture(scope="module")
def setup(duthosts, ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter, topo_scenario, vlan_name):
    """Gather all required test information from DUT and tbinfo.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        tbinfo: A fixture to gather information about the testbed.

    Yields:
        A Dictionary with required test information.

    """

    pytest_assert(vlan_name in ["Vlan1000", "Vlan2000", "no_vlan"], "Invalid vlan name.")
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]

    vlan_ports = []
    vlan_mac = None
    # Need to refresh below constants for two scenarios of M0
    global DOWNSTREAM_DST_IP, DOWNSTREAM_IP_TO_ALLOW, DOWNSTREAM_IP_TO_BLOCK

    if topo == "mx":
        DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_VLAN
        DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_VLAN
        DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_VLAN
    # Announce routes for m0 is something different from t1/t0
    if topo_scenario == "m0_vlan_scenario":
        topo = "m0_vlan"
        if tbinfo["topo"]["name"] == "m0-2vlan":
            DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_VLAN2000 if vlan_name == "Vlan2000" else DOWNSTREAM_DST_IP_VLAN
            DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_VLAN2000 if vlan_name == "Vlan2000" \
                else DOWNSTREAM_IP_TO_ALLOW_VLAN
            DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_VLAN2000 if vlan_name == "Vlan2000" \
                else DOWNSTREAM_IP_TO_BLOCK_VLAN
        else:
            DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_VLAN
            DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_VLAN
            DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_VLAN
    elif topo_scenario == "m0_l3_scenario":
        topo = "m0_l3"
        DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_M0_L3
        DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_M0_L3
        DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_M0_L3
    if topo in ["t0", "mx", "m0_vlan"]:
        vlan_ports = [mg_facts["minigraph_ptf_indices"][ifname]
                      for ifname in mg_facts["minigraph_vlans"][vlan_name]["members"]]

        config_facts = rand_selected_dut.get_running_config_facts()
        vlan_table = config_facts["VLAN"]
        if "mac" in vlan_table[vlan_name]:
            vlan_mac = vlan_table[vlan_name]["mac"]

    # Get the list of upstream/downstream ports
    downstream_ports = defaultdict(list)
    upstream_ports = defaultdict(list)
    downstream_port_ids = []
    upstream_port_ids = []
    upstream_port_id_to_router_mac_map = {}
    downstream_port_id_to_router_mac_map = {}

    # For M0_VLAN/MX/T0/dual ToR scenario, we need to use the VLAN MAC to interact with downstream ports
    # For T1/M0_L3 scenario, no VLANs are present so using the router MAC is acceptable
    downlink_dst_mac = vlan_mac if vlan_mac is not None else rand_selected_dut.facts["router_mac"]
    if topo == "t2":
        t2_info = get_t2_info(duthosts, tbinfo)
        downstream_port_ids = t2_info['downstream_port_ids']
        upstream_port_ids = t2_info['upstream_port_ids']
        downstream_port_id_to_router_mac_map = t2_info['downstream_port_id_to_router_mac_map']
        upstream_port_id_to_router_mac_map = t2_info['upstream_port_id_to_router_mac_map']
    else:
        upstream_neigh_type = get_upstream_neigh_type(topo)
        downstream_neigh_type = get_downstream_neigh_type(topo)
        pytest_require(upstream_neigh_type is not None and downstream_neigh_type is not None,
                       "Cannot get neighbor type for unsupported topo: {}".format(topo))
        mg_vlans = mg_facts["minigraph_vlans"]
        for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
            port_id = mg_facts["minigraph_ptf_indices"][interface]
            if downstream_neigh_type in neighbor["name"].upper():
                if topo in ["t0", "mx", "m0_vlan"]:
                    if interface not in mg_vlans[vlan_name]["members"]:
                        continue

                downstream_ports[neighbor['namespace']].append(interface)
                downstream_port_ids.append(port_id)
                downstream_port_id_to_router_mac_map[port_id] = downlink_dst_mac
            elif upstream_neigh_type in neighbor["name"].upper():
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
        for interface, neighbor in list(peer_mg_facts['minigraph_neighbors'].items()):
            if (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]):
                port_id = peer_mg_facts["minigraph_ptf_indices"][interface]
                upstream_port_ids.append(port_id)
                upstream_port_id_to_router_mac_map[port_id] = rand_unselected_dut.facts["router_mac"]

    # Get the list of LAGs
    port_channels = mg_facts["minigraph_portchannels"]

    # TODO: We should make this more robust (i.e. bind all active front-panel ports)
    acl_table_ports = defaultdict(list)

    if topo in ["t0", "mx", "m0_vlan", "m0_l3"] or tbinfo["topo"]["name"] in ("t1", "t1-lag", "t1-28-lag"):
        for namespace, port in list(downstream_ports.items()):
            acl_table_ports[namespace] += port
            # In multi-asic we need config both in host and namespace.
            if namespace:
                acl_table_ports[''] += port

    if topo in ["t0", "m0_vlan", "m0_l3"] or tbinfo["topo"]["name"] in ("t1-lag", "t1-64-lag", "t1-64-lag-clet",
                                                                        "t1-56-lag", "t1-28-lag", "t1-32-lag"):
        for k, v in list(port_channels.items()):
            acl_table_ports[v['namespace']].append(k)
            # In multi-asic we need config both in host and namespace.
            if v['namespace']:
                acl_table_ports[''].append(k)
    elif topo == "t2":
        acl_table_ports = t2_info['acl_table_ports']
    else:
        for namespace, port in list(upstream_ports.items()):
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
    if tbinfo["topo"]["type"] in ["t0"] and request.param == "ipv6":
        pytest.skip("IPV6 ACL test not currently supported on t0 testbeds")

    return request.param


@pytest.fixture(scope="module")
def populate_vlan_arp_entries(setup, ptfhost, duthosts, rand_one_dut_hostname, ip_version):
    """Set up the ARP responder utility in the PTF container."""
    global DOWNSTREAM_IP_PORT_MAP
    # For m0 topo, need to refresh this constant for two different scenario
    DOWNSTREAM_IP_PORT_MAP = {}
    duthost = duthosts[rand_one_dut_hostname]
    if setup["topo"] not in ["t0", "mx", "m0_vlan"]:
        def noop():
            pass

        yield noop

        return  # Don't fall through to t0/mx/m0_vlan case

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
            dut.command("sonic-clear ndp")
            # Wait some time to ensure the async call of clear is completed
            time.sleep(20)
            for addr in addr_list:
                dut.command("ping {} -c 3".format(addr), module_ignore_errors=True)

    populate_arp_table()

    yield populate_arp_table

    logging.info("Stopping ARP responder")
    ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)

    duthost.command("sonic-clear fdb all")
    duthost.command("sonic-clear arp")
    duthost.command("sonic-clear ndp")


@pytest.fixture(scope="module", params=["ingress", "egress"])
def stage(request, duthosts, rand_one_dut_hostname, tbinfo):
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
        request.param == "ingress" or duthost.facts.get("platform_asic") == "broadcom-dnx"
        or duthost.facts["asic_type"] not in ("broadcom"),
        "Egress ACLs are not currently supported on \"{}\" ASICs".format(duthost.facts["asic_type"])
    )

    return request.param


def create_or_remove_acl_table(duthost, acl_table_config, setup, op, topo):
    for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
        namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst, 'namespace') else ''
        if op == "add":
            logger.info("Creating ACL table: \"{}\" in namespace {} on device {}"
                        .format(acl_table_config["table_name"], namespace, duthost))
            if topo == "t2":
                acl_table_ports = setup["acl_table_ports"]
                acl_table_ports = acl_table_ports[duthost]
                if not len(acl_table_ports[namespace]):
                    continue
            else:
                acl_table_ports = setup["acl_table_ports"]
            sonic_host_or_asic_inst.command(
                "config acl add table {} {} -s {} -p {}".format(
                    acl_table_config["table_name"],
                    acl_table_config["table_type"],
                    acl_table_config["table_stage"],
                    ",".join(acl_table_ports[namespace]),
                )
            )
        else:
            logger.info("Removing ACL table \"{}\" in namespace {} on device {}"
                        .format(acl_table_config["table_name"], namespace, duthost))
            sonic_host_or_asic_inst.command("config acl remove table {}".format(acl_table_config["table_name"]))
    # Give the dut some time for the ACL to be applied and LOG message generated
    time.sleep(30)


@pytest.fixture(scope="module")
def acl_table(duthosts, rand_one_dut_hostname, setup, stage, ip_version, tbinfo):
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
    topo = tbinfo["topo"]["type"]

    acl_table_config = {
        "table_name": table_name,
        "table_ports": ",".join(setup["acl_table_ports"]['']),
        "table_stage": stage,
        "table_type": "L3" if ip_version == "ipv4" else "L3V6"
    }
    logger.info("Generated ACL table configuration:\n{}".format(pprint.pformat(acl_table_config)))

    dut_to_analyzer_map = {}

    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl")
        loganalyzer.load_common_config()
        dut_to_analyzer_map[duthost] = loganalyzer

        try:
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
            # Ignore any other errors to reduce noise
            loganalyzer.ignore_regex = [r".*"]
            with loganalyzer:
                create_or_remove_acl_table(duthost, acl_table_config, setup, "add", topo)
                wait_until(300, 20, 0, check_msg_in_syslog,
                           duthost, LOG_EXPECT_ACL_TABLE_CREATE_RE)
        except LogAnalyzerError as err:
            # Cleanup Config DB if table creation failed
            logger.error("ACL table creation failed, attempting to clean-up...")
            create_or_remove_acl_table(duthost, acl_table_config, setup, "remove", topo)
            raise err

    try:
        yield acl_table_config
    finally:
        for duthost, loganalyzer in list(dut_to_analyzer_map.items()):
            loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_REMOVE_RE]
            with loganalyzer:
                create_or_remove_acl_table(duthost, acl_table_config, setup, "remove", topo)


class BaseAclTest(six.with_metaclass(ABCMeta, object)):
    """Base class for testing ACL rules.

    Subclasses must provide `setup_rules` method to prepare ACL rules for traffic testing.

    They can optionally override `teardown_rules`, which will otherwise remove the rules by
    applying an empty configuration file.
    """

    ACL_COUNTERS_UPDATE_INTERVAL_SECS = 10

    @abstractmethod
    def setup_rules(self, dut, acl_table, ip_version):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        pass

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo, conn_graph_facts):   # noqa F811
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
    def acl_rules(self, request, duthosts, localhost, setup, acl_table, populate_vlan_arp_entries, tbinfo,
                  ip_version, conn_graph_facts):   # noqa F811
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
            if duthost.is_supervisor_node():
                continue
            loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl_rules")
            loganalyzer.load_common_config()
            dut_to_analyzer_map[duthost] = loganalyzer

            try:
                loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
                # Ignore any other errors to reduce noise
                loganalyzer.ignore_regex = [r".*"]
                with loganalyzer:
                    self.setup_rules(duthost, acl_table, ip_version)
                    # Give the dut some time for the ACL rules to be applied and LOG message generated
                    wait_until(300, 20, 0, check_msg_in_syslog,
                               duthost, LOG_EXPECT_ACL_RULE_CREATE_RE)

                self.post_setup_hook(duthost, localhost, populate_vlan_arp_entries, tbinfo, conn_graph_facts)

                assert self.check_rule_counters(duthost), "Rule counters should be ready!"
                asic_db = AsicDbCli(duthost)
                asic_db.get_acl_entries(refresh=True)
                asic_db.get_acl_range_entries(refresh=True)
                request.config.asic_db[duthost.hostname] = asic_db

            except LogAnalyzerError as err:
                # Cleanup Config DB if rule creation failed
                logger.error("ACL rule application failed, attempting to clean-up...")
                self.teardown_rules(duthost)
                raise err

        try:
            yield
        finally:
            for duthost, loganalyzer in list(dut_to_analyzer_map.items()):
                if duthost.is_supervisor_node():
                    continue
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
        skip_byte_accounting = False
        for duthost in duthosts:
            if duthost.is_supervisor_node():
                continue
            acl_facts[duthost]['before'] = \
                duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"][table_name]["rules"]

        rule_list = []
        yield rule_list

        if not rule_list:
            return

        # Wait for orchagent to update the ACL counters
        time.sleep(self.ACL_COUNTERS_UPDATE_INTERVAL_SECS)

        for duthost in duthosts:
            if duthost.facts["asic_type"] == 'vs':
                logger.info('Skip checking rule counters for vs platform')
                return
            if duthost.is_supervisor_node():
                continue
            acl_facts[duthost]['after'] = \
                duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"][table_name]["rules"]

        for duthost in duthosts:
            if duthost.is_supervisor_node():
                continue
            assert len(acl_facts[duthost]['before']) == len(acl_facts[duthost]['after'])

        for rule in rule_list:
            rule = "RULE_{}".format(rule)

            counters_before = {
                PACKETS_COUNT: 0,
                BYTES_COUNT: 0
            }
            for duthost in duthosts:
                if duthost.is_supervisor_node():
                    continue
                counters_before[PACKETS_COUNT] += acl_facts[duthost]['before'][rule][PACKETS_COUNT]
                counters_before[BYTES_COUNT] += acl_facts[duthost]['before'][rule][BYTES_COUNT]
            logger.info("Counters for ACL rule \"{}\" before traffic:\n{}"
                        .format(rule, pprint.pformat(counters_before)))

            counters_after = {
                PACKETS_COUNT: 0,
                BYTES_COUNT: 0
            }
            for duthost in duthosts:
                if duthost.is_supervisor_node():
                    continue
                counters_after[PACKETS_COUNT] += acl_facts[duthost]['after'][rule][PACKETS_COUNT]
                counters_after[BYTES_COUNT] += acl_facts[duthost]['after'][rule][BYTES_COUNT]
                if (duthost.facts["hwsku"] == "Cisco-8111-O64" or
                        duthost.facts["hwsku"] == "Cisco-8111-O32" or
                        duthost.facts["hwsku"] == "Cisco-8111-C32" or
                        duthost.facts["hwsku"] == "Cisco-8111-O62C2"):
                    skip_byte_accounting = True

            logger.info("Counters for ACL rule \"{}\" after traffic:\n{}"
                        .format(rule, pprint.pformat(counters_after)))

            assert counters_after[PACKETS_COUNT] > counters_before[PACKETS_COUNT]
            if not skip_byte_accounting:
                assert counters_after[BYTES_COUNT] > counters_before[BYTES_COUNT]
            else:
                logger.info("No byte counters for this hwsku\n")

    @pytest.fixture(params=["downlink->uplink", "uplink->downlink"])
    def direction(self, request):
        """Parametrize test based on direction of traffic."""
        return request.param

    def check_rule_counters(self, duthost):
        if duthost.facts['asic_type'] == 'vs':
            logger.info('Skip checking rule counters for vs platform')
            return True

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

    def tcp_packet(self, setup, direction, ptfadapter, ip_version,
                   src_ip=None, dst_ip=None, proto=None, sport=0x4321, dport=0x51, flags=None):
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

    def test_ingress_unmatched_blocked(self, setup, direction, ptfadapter, ip_version, stage, skip_traffic_test):   # noqa F811
        """Verify that unmatched packets are dropped for ingress."""
        if stage == "egress":
            pytest.skip("Only run for ingress")

        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version)
        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)

    def test_egress_unmatched_forwarded(self, setup, direction, ptfadapter, ip_version, stage, skip_traffic_test):  # noqa F811
        """Verify that default egress rule allow all traffics"""
        if stage == "ingress":
            pytest.skip("Only run for egress")

        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version)
        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)

    def test_source_ip_match_forwarded(self, request, setup, direction, ptfadapter,
                                       counters_sanity_check, ip_version, skip_traffic_test):   # noqa F811
        """Verify that we can match and forward a packet on source IP."""
        src_ip = "20.0.0.2" if ip_version == "ipv4" else "60c0:a800::6"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has entry that matches source ip with forward action set
        asic_db = next(iter(request.config.asic_db.values()))
        acl_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(1)

    def test_rules_priority_forwarded(self, request, setup, direction, ptfadapter,
                                      counters_sanity_check, ip_version, skip_traffic_test):    # noqa F811
        """Verify that we respect rule priorites in the forwarding case."""
        src_ip = "20.0.0.7" if ip_version == "ipv4" else "60c0:a800::7"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has a higher priority entry with src_ip and FORWARD than src_ip and DROP action
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []
        acl_drop_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []
        assert int(acl_fwd_entry[0]['SAI_ACL_ENTRY_ATTR_PRIORITY']) > \
            int(acl_drop_entry[0]['SAI_ACL_ENTRY_ATTR_PRIORITY'])

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(20)

    def test_rules_priority_dropped(self, request, setup, direction, ptfadapter,
                                    counters_sanity_check, ip_version, skip_traffic_test):      # noqa F811
        """Verify that we respect rule priorites in the drop case."""
        src_ip = "20.0.0.3" if ip_version == "ipv4" else "60c0:a800::4"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has the DROP rule for the src_ip
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(7)

    def test_dest_ip_match_forwarded(self, request, setup, direction, ptfadapter,
                                     counters_sanity_check, ip_version, vlan_name, skip_traffic_test):  # noqa F811
        """Verify that we can match and forward a packet on destination IP."""
        dst_ip = DOWNSTREAM_IP_TO_ALLOW[ip_version] \
            if direction == "uplink->downlink" else UPSTREAM_IP_TO_ALLOW[ip_version]
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dst_ip=dst_ip)

        # verify ASIC DB has the FORWARD rule for the dst_ip
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(dst_ip=dst_ip, packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        # Because m0_l3_scenario use differnet IPs, so need to verify different acl rules.
        if direction == "uplink->downlink":
            if setup["topo"] == "m0_l3":
                if ip_version == "ipv6":
                    rule_id = 32
                else:
                    rule_id = 30
            elif setup["topo"] in ["m0_vlan", "mx"]:
                if ip_version == "ipv6":
                    rule_id = 34 if vlan_name == "Vlan1000" else 36
                else:
                    rule_id = 33 if vlan_name == "Vlan1000" else 2
            else:
                rule_id = 2
        else:
            rule_id = 3
        counters_sanity_check.append(rule_id)

    def test_dest_ip_match_dropped(self, request, setup, direction, ptfadapter,
                                   counters_sanity_check, ip_version, vlan_name, skip_traffic_test):    # noqa F811
        """Verify that we can match and drop a packet on destination IP."""
        dst_ip = DOWNSTREAM_IP_TO_BLOCK[ip_version] \
            if direction == "uplink->downlink" else UPSTREAM_IP_TO_BLOCK[ip_version]
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dst_ip=dst_ip)

        # verify ASIC DB has dst_ip DROP rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(dst_ip=dst_ip, packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        # Because m0_l3_scenario use differnet IPs, so need to verify different acl rules.
        if direction == "uplink->downlink":
            if setup["topo"] == "m0_l3":
                if ip_version == "ipv6":
                    rule_id = 33
                else:
                    rule_id = 31
            elif setup["topo"] in ["m0_vlan", "mx"]:
                if ip_version == "ipv6":
                    rule_id = 35 if vlan_name == "Vlan1000" else 37
                else:
                    rule_id = 32 if vlan_name == "Vlan1000" else 15
            else:
                rule_id = 15
        else:
            rule_id = 16
        counters_sanity_check.append(rule_id)

    def test_source_ip_match_dropped(self, request, setup, direction, ptfadapter,
                                     counters_sanity_check, ip_version, skip_traffic_test):     # noqa F811
        """Verify that we can match and drop a packet on source IP."""
        src_ip = "20.0.0.6" if ip_version == "ipv4" else "60c0:a800::3"
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has src_ip DROP rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(14)

    def test_udp_source_ip_match_forwarded(self, request, setup, direction, ptfadapter,
                                           counters_sanity_check, ip_version, skip_traffic_test):       # noqa F811
        """Verify that we can match and forward a UDP packet on source IP."""
        src_ip = "20.0.0.4" if ip_version == "ipv4" else "60c0:a800::8"
        pkt = self.udp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has src_ip FORWARD action ACL rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(13)

    def test_udp_source_ip_match_dropped(self, request, setup, direction, ptfadapter,
                                         counters_sanity_check, ip_version, skip_traffic_test):     # noqa F811
        """Verify that we can match and drop a UDP packet on source IP."""
        src_ip = "20.0.0.8" if ip_version == "ipv4" else "60c0:a800::2"
        pkt = self.udp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has src_ip DROP action rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(26)

    def test_icmp_source_ip_match_dropped(self, request, setup, direction, ptfadapter,
                                          counters_sanity_check, ip_version, skip_traffic_test):    # noqa F811
        """Verify that we can match and drop an ICMP packet on source IP."""
        src_ip = "20.0.0.8" if ip_version == "ipv4" else "60c0:a800::2"
        pkt = self.icmp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has src_ip DROP action ACL rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(25)

    def test_icmp_source_ip_match_forwarded(self, request, setup, direction, ptfadapter,
                                            counters_sanity_check, ip_version, skip_traffic_test):  # noqa F811
        """Verify that we can match and forward an ICMP packet on source IP."""
        src_ip = "20.0.0.4" if ip_version == "ipv4" else "60c0:a800::8"
        pkt = self.icmp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip)

        # verify ASIC DB has src_ip FORWARD action ACL rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(src_ip=src_ip, packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(12)

    def test_l4_dport_match_forwarded(self, request, setup, direction, ptfadapter,
                                      counters_sanity_check, ip_version, skip_traffic_test):        # noqa F811
        """Verify that we can match and forward on L4 destination port."""
        dst_port = 0x1217
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=dst_port)

        # verify ASIC DB has dst_port FORWARD action ACL rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(l4_dst_port=str(dst_port), packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(9)

    def test_l4_sport_match_forwarded(self, request, setup, direction, ptfadapter,
                                      counters_sanity_check, ip_version, skip_traffic_test):        # noqa F811
        """Verify that we can match and forward on L4 source port."""
        src_port = 0x120D
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=src_port)

        # verify ASIC DB has src_port FORWARD action ACL rule
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(l4_src_port=str(src_port), packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(4)

    def test_l4_dport_range_match_forwarded(self, request, setup, direction, ptfadapter,
                                            counters_sanity_check, ip_version, skip_traffic_test):  # noqa F811
        """Verify that we can match and forward on a range of L4 destination ports."""
        dport = 0x123B
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=dport)

        # verify ASIC DB has FORWARD rule for port in configured range
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(range_type='l4_dst_port', l4_dst_port=str(dport),
                                            packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(11)

    def test_l4_sport_range_match_forwarded(self, request, setup, direction, ptfadapter,
                                            counters_sanity_check, ip_version, skip_traffic_test):  # noqa F811
        """Verify that we can match and forward on a range of L4 source ports."""
        sport = 0x123A
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=sport)

        # verify ASIC DB has FORWARD rule for port in configured range
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(range_type='l4_src_port', l4_src_port=str(sport),
                                            packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(10)

    def test_l4_dport_range_match_dropped(self, request, setup, direction, ptfadapter,
                                          counters_sanity_check, ip_version, skip_traffic_test):    # noqa F811
        """Verify that we can match and drop on a range of L4 destination ports."""
        dport = 0x1285
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=dport)

        # verify ASIC DB has DROP rule for port in configured range
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(range_type='l4_dst_port', l4_dst_port=str(dport),
                                             packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(22)

    def test_l4_sport_range_match_dropped(self, request, setup, direction, ptfadapter,
                                          counters_sanity_check, ip_version, skip_traffic_test):    # noqa F811
        """Verify that we can match and drop on a range of L4 source ports."""
        sport = 0x1298
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=sport)

        # verify ASIC DB has DROP rule for port in configured range
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(range_type='l4_src_port', l4_src_port=str(sport),
                                             packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(17)

    def test_ip_proto_match_forwarded(self, request, setup, direction, ptfadapter,
                                      counters_sanity_check, ip_version, skip_traffic_test):        # noqa F811
        """Verify that we can match and forward on the IP protocol."""
        ip_protocol = 0x7E
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, proto=0x7E)

        # verify ASIC DB has FORWARD rule for IP protocol number
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = []
        if ip_version == "ipv4":
            acl_fwd_entry = asic_db.find_acl_by(ip_protocol=str(ip_protocol),
                                                packet_action='SAI_PACKET_ACTION_FORWARD')
        else:
            acl_fwd_entry = asic_db.find_acl_by(ipv6_next_header=str(ip_protocol),
                                                packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(5)

    def test_tcp_flags_match_forwarded(self, request, setup, direction, ptfadapter,
                                       counters_sanity_check, ip_version, skip_traffic_test):       # noqa F811
        """Verify that we can match and forward on the TCP flags."""
        tcp_flags = 0x1B
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, flags=tcp_flags)

        # verify ASIC DB has FORWARD rule for TCP Flags
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = asic_db.find_acl_by(tcp_flags=str(tcp_flags), packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(6)

    def test_l4_dport_match_dropped(self, request, setup, direction, ptfadapter,
                                    counters_sanity_check, ip_version, skip_traffic_test):          # noqa F811
        """Verify that we can match and drop on L4 destination port."""
        dst_port = 0x127B
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dport=dst_port)

        # verify ASIC DB has DROP rule for dst_port
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(l4_dst_port=str(dst_port), packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(22)

    def test_l4_sport_match_dropped(self, request, setup, direction, ptfadapter,
                                    counters_sanity_check, ip_version, skip_traffic_test):          # noqa F811
        """Verify that we can match and drop on L4 source port."""
        src_port = 0x1271
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, sport=src_port)

        # verify ASIC DB has DROP rule for src_port
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(l4_src_port=str(src_port), packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(17)

    def test_ip_proto_match_dropped(self, request, setup, direction, ptfadapter,
                                    counters_sanity_check, ip_version, skip_traffic_test):          # noqa F811
        """Verify that we can match and drop on the IP protocol."""
        ip_protocol = 0x7F
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, proto=ip_protocol)

        # verify ASIC DB has DROP rule for IP protocol number
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = []
        if ip_version == "ipv4":
            acl_drop_entry = asic_db.find_acl_by(ip_protocol=str(ip_protocol),
                                                 packet_action='SAI_PACKET_ACTION_DROP')
        else:
            acl_drop_entry = asic_db.find_acl_by(ipv6_next_header=str(ip_protocol),
                                                 packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(18)

    def test_tcp_flags_match_dropped(self, request, setup, direction, ptfadapter,
                                     counters_sanity_check, ip_version, skip_traffic_test):         # noqa F811
        """Verify that we can match and drop on the TCP flags."""
        tcp_flags = 0x24
        pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, flags=tcp_flags)

        # verify ASIC DB has DROP rule for matched TCP flags
        asic_db = next(iter(request.config.asic_db.values()))
        acl_drop_entry = asic_db.find_acl_by(tcp_flags=str(tcp_flags), packet_action='SAI_PACKET_ACTION_DROP')
        assert acl_drop_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version, skip_traffic_test)
        counters_sanity_check.append(19)

    def test_icmp_match_forwarded(self, request, setup, direction, ptfadapter,
                                  counters_sanity_check, ip_version, skip_traffic_test):            # noqa F811
        """Verify that we can match and drop on the TCP flags."""
        src_ip = "20.0.0.10" if ip_version == "ipv4" else "60c0:a800::10"
        icmp_type = 3
        icmp_code = 1
        pkt = self.icmp_packet(setup, direction, ptfadapter, ip_version, src_ip=src_ip,
                               icmp_type=icmp_type, icmp_code=icmp_code)

        # verify ASIC DB has FORWARD rule for ICMP packet type and code
        asic_db = next(iter(request.config.asic_db.values()))
        acl_fwd_entry = []
        if ip_version == "ipv4":
            acl_fwd_entry = asic_db.find_acl_by(src_ip=src_ip, icmp_type=str(icmp_type),
                                                icmp_code=str(icmp_code),
                                                packet_action='SAI_PACKET_ACTION_FORWARD')
        else:
            acl_fwd_entry = asic_db.find_acl_by(src_ip=src_ip, icmpv6_type=str(icmp_type),
                                                icmpv6_code=str(icmp_code),
                                                packet_action='SAI_PACKET_ACTION_FORWARD')
        assert acl_fwd_entry != []

        self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version, skip_traffic_test)
        counters_sanity_check.append(29)

    def _verify_acl_traffic(self, setup, direction, ptfadapter, pkt, dropped, ip_version, skip_traffic_test):   # noqa F811
        exp_pkt = self.expected_mask_routed_packet(pkt, ip_version)

        if ip_version == "ipv4":
            downstream_dst_port = DOWNSTREAM_IP_PORT_MAP.get(pkt[packet.IP].dst)
        else:
            downstream_dst_port = DOWNSTREAM_IP_PORT_MAP.get(pkt[packet.IPv6].dst)

        if skip_traffic_test:
            return

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

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo, conn_graph_facts): # noqa F811
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

        # We need additional delay and make sure ports are up for Nokia-IXR7250E-36x400G
        if dut.facts["hwsku"] == "Nokia-IXR7250E-36x400G":
            interfaces = conn_graph_facts["device_conn"][dut.hostname]
            logging.info("Wait until all critical services are fully started")
            wait_critical_processes(dut)

            xcvr_skip_list = {dut.hostname: []}
            result = wait_until(MAX_WAIT_TIME_FOR_INTERFACES, 20, 0, check_all_interface_information, dut, interfaces,
                                xcvr_skip_list)
            assert result, "Not all transceivers are detected or interfaces are up in {} seconds".format(
                MAX_WAIT_TIME_FOR_INTERFACES)

        populate_vlan_arp_entries()


@pytest.mark.port_toggle
class TestAclWithPortToggle(TestBasicAcl):
    """Test ACL rule functionality after toggling ports.

    Verify that ACLs still function as expected after links flap.
    """

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo, conn_graph_facts):  # noqa F811
        """Toggle ports after rules are applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A fixture to populate ARP/FDB tables for VLAN interfaces.

        """
        port_toggle(dut, tbinfo)
        populate_vlan_arp_entries()
