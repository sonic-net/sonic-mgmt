"""Utilities for testing the Everflow feature in SONiC."""
from collections import defaultdict
import os
import logging
import random
import time
import ipaddr
import binascii
import pytest
import yaml
import six

import ptf.testutils as testutils
import ptf.packet as packet

from abc import abstractmethod
from ptf.mask import Mask
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import find_duthost_on_role
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP
import json

# TODO: Add suport for CONFIGLET mode
CONFIG_MODE_CLI = "cli"
CONFIG_MODE_CONFIGLET = "configlet"

TEMPLATE_DIR = "everflow/templates"
EVERFLOW_RULE_CREATE_TEMPLATE = "acl-erspan.json.j2"

FILE_DIR = "everflow/files"
EVERFLOW_V4_RULES = "ipv4_test_rules.yaml"
EVERFLOW_DSCP_RULES = "dscp_test_rules.yaml"

DUT_RUN_DIR = "/tmp/everflow"
EVERFLOW_RULE_CREATE_FILE = "acl-erspan.json"
EVERFLOW_RULE_DELETE_FILE = "acl-remove.json"

STABILITY_BUFFER = 0.05     # 50msec

OUTER_HEADER_SIZE = 38

# This IP is hardcoded into ACL rule
TARGET_SERVER_IP = "192.168.0.2"
# This IP is used as server ip
DEFAULT_SERVER_IP = "192.168.0.3"
VLAN_BASE_MAC_PATTERN = "72060001{:04}"
DOWN_STREAM = "downstream"
UP_STREAM = "upstream"
# Topo that downstream neighbor of DUT are servers
DOWNSTREAM_SERVER_TOPO = ["t0", "m0_vlan"]


def gen_setup_information(dutHost, downStreamDutHost, upStreamDutHost, tbinfo, topo_scenario):
    """
    Generate setup information dictionary for T0 and T1/ T2 topologies.
    """
    topo = tbinfo['topo']['name']

    upstream_ports_namespace_map = defaultdict(list)
    downstream_ports_namespace_map = defaultdict(list)
    upstream_ports_namespace = set()
    downstream_ports_namespace = set()
    upstream_neigh_namespace_map = defaultdict(set)
    downstream_neigh_namespace_map = defaultdict(set)

    mg_facts_list = []

    # Gather test facts
    if downStreamDutHost == upStreamDutHost:
        mg_facts_list.append(downStreamDutHost.get_extended_minigraph_facts(tbinfo))
        downstream_switch_capability_facts = upstream_switch_capability_facts = \
            downStreamDutHost.switch_capabilities_facts()["ansible_facts"]
        downstream_acl_capability_facts = upstream_acl_capability_facts = \
            downStreamDutHost.acl_capabilities_facts()["ansible_facts"]
    else:
        mg_facts_list.append(downStreamDutHost.get_extended_minigraph_facts(tbinfo))
        mg_facts_list.append(upStreamDutHost.get_extended_minigraph_facts(tbinfo))
        downstream_switch_capability_facts = downStreamDutHost.switch_capabilities_facts()["ansible_facts"]
        downstream_acl_capability_facts = downStreamDutHost.acl_capabilities_facts()["ansible_facts"]
        upstream_switch_capability_facts = upStreamDutHost.switch_capabilities_facts()["ansible_facts"]
        upstream_acl_capability_facts = upStreamDutHost.acl_capabilities_facts()["ansible_facts"]

    topo_type = tbinfo["topo"]["type"]
    if topo_type == "m0":
        topo_type = "m0_vlan" if "m0_vlan_scenario" in topo_scenario else "m0_l3"
    # Get the list of T0/T2 ports
    for mg_facts in mg_facts_list:
        for dut_port, neigh in list(mg_facts["minigraph_neighbors"].items()):
            pytest_assert(topo_type in UPSTREAM_NEIGHBOR_MAP and
                          topo_type in DOWNSTREAM_NEIGHBOR_MAP, "Unsupported topo")
            if UPSTREAM_NEIGHBOR_MAP[topo_type] in neigh["name"].lower():
                upstream_ports_namespace_map[neigh['namespace']].append(dut_port)
                upstream_ports_namespace.add(neigh['namespace'])
                upstream_neigh_namespace_map[neigh['namespace']].add(neigh["name"])

            elif DOWNSTREAM_NEIGHBOR_MAP[topo_type] in neigh["name"].lower():
                downstream_ports_namespace_map[neigh['namespace']].append(dut_port)
                downstream_ports_namespace.add(neigh['namespace'])
                downstream_neigh_namespace_map[neigh['namespace']].add(neigh["name"])

    for ns, neigh_set in list(upstream_neigh_namespace_map.items()):
        if len(neigh_set) < 2:
            upstream_ports_namespace.remove(ns)

    for ns, neigh_set in list(downstream_neigh_namespace_map.items()):
        if len(neigh_set) < 2:
            downstream_ports_namespace.remove(ns)

    if not upstream_ports_namespace or not downstream_ports_namespace:
        pytest.skip("Not enough ports for upstream or downstream neighbors to run this test")

    if 't1' in topo:
        # Set of downstream ports only Namespace
        downstream_only_namespace = downstream_ports_namespace.difference(upstream_ports_namespace)
        # Set of upstream ports only Namespace
        upstream_only_namespace = upstream_ports_namespace.difference(downstream_ports_namespace)
        # Randomly choose from downstream_only Namespace if present else just use first one
        downstream_namespace = random.choice(tuple(downstream_only_namespace)) \
            if downstream_only_namespace else random.choice(tuple(downstream_ports_namespace))
        # Randomly choose from upstream_only Namespace if present else just use first one
        upstream_namespace = random.choice(tuple(upstream_only_namespace)) \
            if upstream_only_namespace else random.choice(tuple(upstream_ports_namespace))
    else:
        # Use the default namespace
        downstream_namespace = random.choice(tuple(downstream_ports_namespace))
        upstream_namespace = random.choice(tuple(upstream_ports_namespace))

    downstream_ports = downstream_ports_namespace_map[downstream_namespace]
    upstream_ports = upstream_ports_namespace_map[upstream_namespace]

    random.shuffle(downstream_ports)
    random.shuffle(upstream_ports)

    upstream_switch_capabilities = upstream_switch_capability_facts["switch_capabilities"]["switch"]
    upstream_acl_capabilities = upstream_acl_capability_facts["acl_capabilities"]

    downstream_switch_capabilities = downstream_switch_capability_facts["switch_capabilities"]["switch"]
    downstream_acl_capabilities = downstream_acl_capability_facts["acl_capabilities"]

    test_mirror_v4 = upstream_switch_capabilities["MIRROR"] == "true" \
        and downstream_switch_capabilities["MIRROR"] == "true"
    test_mirror_v6 = upstream_switch_capabilities["MIRRORV6"] == "true" \
        and downstream_switch_capabilities["MIRRORV6"] == "true"

    # NOTE: Older OS versions don't have the ACL_ACTIONS table, and those same devices
    # do not support egress ACLs or egress mirroring. Once we branch out the sonic-mgmt
    # repo we can remove this case.
    if "201811" in downStreamDutHost.os_version or "201811" in upStreamDutHost.os_version:
        test_ingress_mirror_on_ingress_acl = True
        test_ingress_mirror_on_egress_acl = False
        test_egress_mirror_on_egress_acl = False
        test_egress_mirror_on_ingress_acl = False
    elif upstream_acl_capabilities and downstream_acl_capabilities:
        test_ingress_mirror_on_ingress_acl = "MIRROR_INGRESS_ACTION" in \
                                             upstream_acl_capabilities["INGRESS"]["action_list"] and \
                                             "MIRROR_INGRESS_ACTION" in \
                                             downstream_acl_capabilities["INGRESS"]["action_list"]
        test_ingress_mirror_on_egress_acl = "MIRROR_INGRESS_ACTION" in \
                                            upstream_acl_capabilities["EGRESS"]["action_list"] and \
                                            "MIRROR_INGRESS_ACTION" in \
                                            downstream_acl_capabilities["EGRESS"]["action_list"]
        test_egress_mirror_on_egress_acl = "MIRROR_EGRESS_ACTION" in \
                                           upstream_acl_capabilities["EGRESS"]["action_list"] and \
                                           "MIRROR_EGRESS_ACTION" in \
                                           downstream_acl_capabilities["EGRESS"]["action_list"]
        test_egress_mirror_on_ingress_acl = "MIRROR_EGRESS_ACTION" in \
                                            upstream_acl_capabilities["INGRESS"]["action_list"] and \
                                            "MIRROR_EGRESS_ACTION" in \
                                            downstream_acl_capabilities["INGRESS"]["action_list"]
    else:
        logging.info("Fallback to the old source of ACL capabilities (assuming SONiC release is < 202111)")
        test_ingress_mirror_on_ingress_acl = "MIRROR_INGRESS_ACTION" in \
                                             upstream_switch_capabilities["ACL_ACTIONS|INGRESS"] and \
                                             "MIRROR_INGRESS_ACTION" in \
                                             downstream_switch_capabilities["ACL_ACTIONS|INGRESS"]
        test_ingress_mirror_on_egress_acl = "MIRROR_INGRESS_ACTION" in \
                                            upstream_switch_capabilities["ACL_ACTIONS|EGRESS"] and \
                                            "MIRROR_INGRESS_ACTION" in \
                                            downstream_switch_capabilities["ACL_ACTIONS|EGRESS"]
        test_egress_mirror_on_egress_acl = "MIRROR_EGRESS_ACTION" in \
                                           upstream_switch_capabilities["ACL_ACTIONS|EGRESS"] and \
                                           "MIRROR_EGRESS_ACTION" in \
                                           downstream_switch_capabilities["ACL_ACTIONS|EGRESS"]
        test_egress_mirror_on_ingress_acl = "MIRROR_EGRESS_ACTION" in \
                                            upstream_switch_capabilities["ACL_ACTIONS|INGRESS"] and \
                                            "MIRROR_EGRESS_ACTION" in \
                                            downstream_switch_capabilities["ACL_ACTIONS|INGRESS"]
#
    # NOTE: Disable egress mirror test on broadcom platform even SAI claim EGRESS MIRRORING is supported
    # There is a known issue in SAI 7.1 for XGS that SAI claims the capability of EGRESS MIRRORING incorrectly.
    # Hence we override the capability query with below logic. Please remove it after the issue is fixed.
    if (downStreamDutHost.facts["asic_type"] == "broadcom" or
        upStreamDutHost.facts["asic_type"] == "broadcom") and \
        (downStreamDutHost.facts.get("platform_asic") != 'broadcom-dnx'
         and upStreamDutHost.facts.get("platform_asic") != 'broadcom-dnx'):
        test_egress_mirror_on_egress_acl = False
        test_egress_mirror_on_ingress_acl = False

    # Collects a list of interfaces, their port number for PTF, and the LAGs they are members of,
    # if applicable.
    #
    # TODO: Add a namedtuple to make the groupings more explicit
    def get_port_info(in_port_list, out_port_list, out_port_ptf_id_list, out_port_lag_name, mg_facts):
        out_port_exclude_list = []
        for port in in_port_list:
            if port not in out_port_list and port not in out_port_exclude_list and len(out_port_list) < 4:
                ptf_port_id = str(mg_facts["minigraph_ptf_indices"][port])
                out_port_list.append(port)
                if out_port_lag_name is not None:
                    out_port_lag_name.append("Not Applicable")

                for portchannelinfo in list(mg_facts["minigraph_portchannels"].items()):
                    if port in portchannelinfo[1]["members"]:
                        if out_port_lag_name is not None:
                            out_port_lag_name[-1] = portchannelinfo[0]
                        for lag_member in portchannelinfo[1]["members"]:
                            if port == lag_member:
                                continue
                            ptf_port_id += "," + (str(mg_facts["minigraph_ptf_indices"][lag_member]))
                            out_port_exclude_list.append(lag_member)

                out_port_ptf_id_list.append(ptf_port_id)

    asic_id = upStreamDutHost.get_asic_id_from_namespace(upstream_namespace)
    upstream_router_mac = upStreamDutHost.asic_instance(asic_id).get_router_mac()
    asic_id = downStreamDutHost.get_asic_id_from_namespace(downstream_namespace)
    downstream_router_mac = downStreamDutHost.asic_instance(asic_id).get_router_mac()
    if 'dualtor' in topo:
        # On dualtor setup, we need to use the MAC of the VLAN interface
        # as the src MAC of downstream traffic
        downstream_vlan_mac = dutHost.get_dut_iface_mac('Vlan1000')
        upstream_vlan_mac = dutHost.asic_instance().get_router_mac()
    else:
        downstream_vlan_mac = upstream_vlan_mac = None

    setup_information = {
        "test_mirror_v4": test_mirror_v4,
        "test_mirror_v6": test_mirror_v6,
        "ingress": {
            "ingress": test_ingress_mirror_on_ingress_acl,
            "egress": test_egress_mirror_on_ingress_acl
        },
        "egress": {
            "ingress": test_ingress_mirror_on_egress_acl,
            "egress": test_egress_mirror_on_egress_acl
        },
    }
    # Downstream traffic
    downstream_dest_ports = []
    downstream_dest_ports_ptf_id = []
    downstream_dest_lag_name = None if topo_type in DOWNSTREAM_SERVER_TOPO else []
    get_port_info(downstream_ports, downstream_dest_ports, downstream_dest_ports_ptf_id,
                  downstream_dest_lag_name,  mg_facts_list[0])

    # Upstream traffic
    upstream_dest_ports = []
    upstream_dest_ports_ptf_id = []
    upstream_dest_lag_name = []
    get_port_info(upstream_ports, upstream_dest_ports, upstream_dest_ports_ptf_id,
                  upstream_dest_lag_name, mg_facts_list[1] if len(mg_facts_list) == 2 else mg_facts_list[0])

    setup_information.update(
        {
            "topo": topo_type,
            DOWN_STREAM: {
                "remote_dut": downStreamDutHost,
                "everflow_dut": upStreamDutHost,
                "ingress_router_mac": upstream_router_mac,
                "egress_router_mac": downstream_router_mac,
                "vlan_mac": downstream_vlan_mac,
                "src_port": upstream_ports[0],
                "src_port_lag_name": upstream_dest_lag_name[0],
                "src_port_ptf_id": (str(mg_facts_list[1]["minigraph_ptf_indices"][upstream_ports[0]])
                                    if len(mg_facts_list) == 2 else
                                    str(mg_facts_list[0]["minigraph_ptf_indices"][upstream_ports[0]])),
                # For T0 topo, downstream traffic ingress from the first portchannel,
                # and mirror packet egress from other portchannels
                "dest_port": (upstream_dest_ports[1:]
                              if topo_type in DOWNSTREAM_SERVER_TOPO else downstream_dest_ports),
                "dest_port_ptf_id": (upstream_dest_ports_ptf_id[1:]
                                     if topo_type in DOWNSTREAM_SERVER_TOPO else downstream_dest_ports_ptf_id),
                "dest_port_lag_name": (upstream_dest_lag_name[1:]
                                       if topo_type in DOWNSTREAM_SERVER_TOPO else downstream_dest_lag_name),
                "remote_namespace": upstream_namespace if topo_type in DOWNSTREAM_SERVER_TOPO else downstream_namespace,
                "everflow_namespace": upstream_namespace
            },
            UP_STREAM: {
                "remote_dut": upStreamDutHost,
                "everflow_dut": downStreamDutHost,
                "ingress_router_mac": downstream_router_mac,
                "egress_router_mac": upstream_router_mac,
                "vlan_mac": upstream_vlan_mac,
                "src_port": downstream_ports[0],
                # DUT whose downstream are servers doesn't have lag connect to server
                "src_port_lag_name": "Not Applicable" \
                if topo_type in DOWNSTREAM_SERVER_TOPO else downstream_dest_lag_name[0],
                "src_port_ptf_id": str(mg_facts_list[0]["minigraph_ptf_indices"][downstream_ports[0]]),
                "dest_port": upstream_dest_ports,
                "dest_port_ptf_id": upstream_dest_ports_ptf_id,
                "dest_port_lag_name": upstream_dest_lag_name,
                "remote_namespace": upstream_namespace,
                "everflow_namespace": downstream_namespace
            },
        }
    )

    if topo_type in DOWNSTREAM_SERVER_TOPO:
        setup_information.update(
            {
                "server_dest_ports_ptf_id": downstream_dest_ports_ptf_id
            }
        )
    # Update the VLAN MAC for dualtor testbed. The VLAN MAC will be used as dst MAC in upstream traffic
    if 'dualtor' in topo:
        vlan_name = list(mg_facts_list[0]['minigraph_vlans'].keys())[0]
        vlan_mac = downStreamDutHost.get_dut_iface_mac(vlan_name)
        setup_information.update({"dualtor": True})
        setup_information[UP_STREAM]['ingress_router_mac'] = vlan_mac

    return setup_information


def get_t2_duthost(duthosts, tbinfo):
    """
    Generate setup information dictionary for T2 topologies.
    """
    t3_duthost = find_duthost_on_role(duthosts, "T3", tbinfo)
    t1_duthost = find_duthost_on_role(duthosts, "T1", tbinfo)
    return t1_duthost, t3_duthost


@pytest.fixture(scope="module")
def setup_info(duthosts, rand_one_dut_hostname, tbinfo, request, topo_scenario):
    """
    Gather all required test information.

    Args:
        duthost: DUT fixture
        tbinfo: tbinfo fixture

    Returns:
        dict: Required test information

    """
    duthost = None
    topo = tbinfo['topo']['name']
    if 't1' in topo or 't0' in topo or 'm0' in topo or 'mx' in topo or 'dualtor' in topo:
        downstream_duthost = upstream_duthost = duthost = duthosts[rand_one_dut_hostname]
    elif 't2' in topo:
        pytest_assert(len(duthosts) > 1, "Test must run on whole chassis")
        downstream_duthost, upstream_duthost = get_t2_duthost(duthosts, tbinfo)

    setup_information = gen_setup_information(duthost, downstream_duthost, upstream_duthost, tbinfo, topo_scenario)

    # Disable BGP so that we don't keep on bouncing back mirror packets
    # If we send TTL=1 packet we don't need this but in multi-asic TTL > 1

    if 't2' in topo:
        for dut_host in duthosts.frontend_nodes:
            dut_host.command("sudo config bgp shutdown all")
            dut_host.command("mkdir -p {}".format(DUT_RUN_DIR))
    else:
        duthost.command("sudo config bgp shutdown all")
        duthost.command("mkdir -p {}".format(DUT_RUN_DIR))

    time.sleep(60)

    yield setup_information

    # Enable BGP again
    if 't2' in topo:
        for dut_host in duthosts.frontend_nodes:
            dut_host.command("sudo config bgp startup all")
            dut_host.command("rm -rf {}".format(DUT_RUN_DIR))
    else:
        duthost.command("sudo config bgp startup all")
        duthost.command("rm -rf {}".format(DUT_RUN_DIR))
    time.sleep(60)


# TODO: This should be refactored to some common area of sonic-mgmt.
def add_route(duthost, prefix, nexthop, namespace):
    """
    Add a route to the DUT.

    Args:
        duthost: DUT fixture
        prefix: IP prefix for the route
        nexthop: next hop for the route
        namespace: namsespace/asic to add the route

    """
    duthost.shell(duthost.get_vtysh_cmd_for_namespace(
        "vtysh -c \"configure terminal\" -c \"ip route {} {} tag 1\"".format(prefix, nexthop), namespace))


# TODO: This should be refactored to some common area of sonic-mgmt.
def remove_route(duthost, prefix, nexthop, namespace):
    """
    Remove a route from the DUT.

    Args:
        duthost: DUT fixture
        prefix: IP prefix to remove
        nexthop: next hop to remove
        namespace: namsespace/asic to remove the route

    """
    duthost.shell(duthost.get_vtysh_cmd_for_namespace(
        "vtysh -c \"configure terminal\" -c \"no ip route {} {} tag 1\"".format(prefix, nexthop), namespace))


@pytest.fixture(scope='module', autouse=True)
def setup_arp_responder(duthost, ptfhost, setup_info):
    if setup_info['topo'] not in ['t0', 'm0_vlan']:
        yield
        return
    ip_list = [TARGET_SERVER_IP, DEFAULT_SERVER_IP]
    port_list = setup_info["server_dest_ports_ptf_id"][0:2]
    arp_responder_cfg = {}
    for i, ip in enumerate(ip_list):
        iface_name = "eth{}".format(port_list[i])
        mac = VLAN_BASE_MAC_PATTERN.format(i)
        arp_responder_cfg[iface_name] = {ip: mac}

    CFG_FILE = '/tmp/arp_responder.json'
    with open(CFG_FILE, 'w') as file:
        json.dump(arp_responder_cfg, file)

    ptfhost.copy(src=CFG_FILE, dest=CFG_FILE)

    extra_vars = {
            'arp_responder_args': '--conf {}'.format(CFG_FILE)
        }

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src='templates/arp_responder.conf.j2', dest='/etc/supervisor/conf.d/arp_responder.conf')

    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')

    ptfhost.command('supervisorctl start arp_responder')
    time.sleep(10)
    for ip in ip_list:
        duthost.shell("ping -c 1 {}".format(ip), module_ignore_errors=True)

    yield

    ptfhost.command('supervisorctl stop arp_responder', module_ignore_errors=True)
    ptfhost.file(path='/tmp/arp_responder.json', state="absent")
    duthost.command('sonic-clear arp')


# TODO: This should be refactored to some common area of sonic-mgmt.
def get_neighbor_info(duthost, dest_port, tbinfo, resolved=True):
    """
    Get the IP and MAC of the neighbor on the specified destination port.

    Args:
        duthost: DUT fixture
        dest_port: The port for which to gather the neighbor information
        resolved: Whether to return a resolved route or not
    """
    if not resolved:
        return "20.20.20.100"

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for bgp_peer in mg_facts["minigraph_bgp"]:
        if bgp_peer["name"] == mg_facts["minigraph_neighbors"][dest_port]["name"] \
                and ipaddr.IPAddress(bgp_peer["addr"]).version == 4:
            peer_ip = bgp_peer["addr"]
            break

    return peer_ip


# TODO: This can probably be moved to a shared location in a later PR.
def load_acl_rules_config(table_name, rules_file):
    with open(rules_file, "r") as f:
        acl_rules = yaml.safe_load(f)

    rules_config = {"acl_table_name": table_name, "rules": acl_rules}

    return rules_config


class BaseEverflowTest(object):
    """
    Base class for setting up a set of Everflow tests.

    Contains common methods for setting up the mirror session and describing the
    mirror and ACL stage for the tests.
    """
    @pytest.fixture(scope="class", params=[CONFIG_MODE_CLI])
    def config_method(self, request):
        """Get the configuration method for this set of test cases.

        There are multiple ways to configure Everflow on a SONiC device,
        so we need to verify that Everflow functions properly for each method.

        Returns:
            The configuration method to use.
        """
        return request.param

    @staticmethod
    def get_duthost_set(setup_info):
        duthost_set = set()
        duthost_set.add(setup_info[DOWN_STREAM]['everflow_dut'])
        duthost_set.add(setup_info[UP_STREAM]['everflow_dut'])
        return duthost_set

    @pytest.fixture(scope="class")
    def setup_mirror_session(self, config_method, setup_info):
        """
        Set up a mirror session for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.
        """
        duthost_set = BaseEverflowTest.get_duthost_set(setup_info)

        session_info = None

        for duthost in duthost_set:
            if not session_info:
                session_info = BaseEverflowTest.mirror_session_info("test_session_1", duthost.facts["asic_type"])
            BaseEverflowTest.apply_mirror_config(duthost, session_info, config_method)

        yield session_info

        for duthost in duthost_set:
            BaseEverflowTest.remove_mirror_config(duthost, session_info["session_name"], config_method)

    @pytest.fixture(scope="class")
    def policer_mirror_session(self, config_method, setup_info):
        """
        Set up a mirror session with a policer for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.
        """
        duthost_set = BaseEverflowTest.get_duthost_set(setup_info)

        policer = "TEST_POLICER"
        # Create a mirror session with the TEST_POLICER attached
        session_info = {}

        for duthost in duthost_set:
            if not session_info:
                session_info = BaseEverflowTest.mirror_session_info("TEST_POLICER_SESSION", duthost.facts["asic_type"])
            # Create a policer that allows 100 packets/sec through
            self.apply_policer_config(duthost, policer, config_method)
            BaseEverflowTest.apply_mirror_config(duthost, session_info, config_method, policer=policer)

        yield session_info

        # Clean up mirror session and policer
        for duthost in duthost_set:
            BaseEverflowTest.remove_mirror_config(duthost, session_info["session_name"], config_method)
            self.remove_policer_config(duthost, policer, config_method)

    @staticmethod
    def apply_mirror_config(duthost, session_info, config_method=CONFIG_MODE_CLI, policer=None):
        if config_method == CONFIG_MODE_CLI:
            command = "config mirror_session add {} {} {} {} {} {}" \
                        .format(session_info["session_name"],
                                session_info["session_src_ip"],
                                session_info["session_dst_ip"],
                                session_info["session_dscp"],
                                session_info["session_ttl"],
                                session_info["session_gre"])

            if policer:
                command += " --policer {}".format(policer)

        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

    @staticmethod
    def remove_mirror_config(duthost, session_name, config_method=CONFIG_MODE_CLI):
        if config_method == CONFIG_MODE_CLI:
            command = "config mirror_session remove {}".format(session_name)
        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

    def apply_policer_config(self, duthost, policer_name, config_method, rate_limit=100):
        if duthost.facts["asic_type"] == "marvell":
            rate_limit = rate_limit * 1.25
        for namespace in duthost.get_frontend_asic_namespace_list():
            if config_method == CONFIG_MODE_CLI:
                sonic_db_cmd = "sonic-db-cli {}".format("-n " + namespace if namespace else "")
                command = ("{} CONFIG_DB hmset \"POLICER|{}\" "
                           "meter_type packets mode sr_tcm cir {} cbs {} "
                           "red_packet_action drop").format(sonic_db_cmd, policer_name, rate_limit, rate_limit)
            elif config_method == CONFIG_MODE_CONFIGLET:
                pass
            duthost.command(command)

    def remove_policer_config(self, duthost, policer_name, config_method):
        for namespace in duthost.get_frontend_asic_namespace_list():
            if config_method == CONFIG_MODE_CLI:
                sonic_db_cmd = "sonic-db-cli {}".format("-n " + namespace if namespace else "")
                command = "{} CONFIG_DB del \"POLICER|{}\"".format(sonic_db_cmd, policer_name)
            elif config_method == CONFIG_MODE_CONFIGLET:
                pass

            duthost.command(command)

    @pytest.fixture(scope="class", autouse=True)
    def setup_acl_table(self, setup_info, setup_mirror_session, config_method):
        """
        Configure the ACL table for this set of test cases.

        Args:
            duthost: DUT fixture
            setup_info: Fixture with info about the testbed setup
            setup_mirror_session: Fixtue with info about the mirror session
        """

        duthost_set = BaseEverflowTest.get_duthost_set(setup_info)
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("{} ACL w/ {} Mirroring not supported, skipping"
                        .format(self.acl_stage(), self.mirror_type()))

        table_name = "EVERFLOW" if self.acl_stage() == "ingress" else "EVERFLOW_EGRESS"

        # NOTE: We currently assume that the ingress MIRROR tables already exist.
        for duthost in duthost_set:
            if self.acl_stage() == "egress":
                inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
                for inst in inst_list:
                    self.apply_acl_table_config(duthost, table_name, "MIRROR", config_method,
                                                bind_namespace=getattr(inst, 'namespace', None))

            self.apply_acl_rule_config(duthost, table_name, setup_mirror_session["session_name"], config_method)

        yield

        for duthost in duthost_set:
            BaseEverflowTest.remove_acl_rule_config(duthost, table_name, config_method)
            if self.acl_stage() == "egress":
                inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
                for inst in inst_list:
                    self.remove_acl_table_config(duthost, "EVERFLOW_EGRESS", config_method,
                                                 bind_namespace=getattr(inst, 'namespace', None))

    def apply_acl_table_config(self, duthost, table_name, table_type, config_method,
                               bind_ports_list=None, bind_namespace=None):
        if config_method == CONFIG_MODE_CLI:
            command = "config acl add table {} {}".format(table_name, table_type)

            # NOTE: Until the repo branches, we're only applying the flag
            # on egress tables to preserve backwards compatibility.
            if self.acl_stage() == "egress":
                command += " --stage {}".format(self.acl_stage())

            if bind_ports_list:
                command += " -p {}".format(",".join(bind_ports_list))

        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.get_asic_or_sonic_host_from_namespace(bind_namespace).command(command)

    def remove_acl_table_config(self, duthost, table_name, config_method, bind_namespace=None):
        if config_method == CONFIG_MODE_CLI:
            command = "config acl remove table {}".format(table_name)
        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.get_asic_or_sonic_host_from_namespace(bind_namespace).command(command)

    def apply_acl_rule_config(
            self,
            duthost,
            table_name,
            session_name,
            config_method,
            rules=EVERFLOW_V4_RULES
    ):
        rules_config = load_acl_rules_config(table_name, os.path.join(FILE_DIR, rules))
        duthost.host.options["variable_manager"].extra_vars.update(rules_config)

        if config_method == CONFIG_MODE_CLI:
            duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_RULE_CREATE_TEMPLATE),
                             dest=os.path.join(DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE))

            command = "acl-loader update full {} --table_name {} --session_name {}" \
                      .format(os.path.join(DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE),
                              table_name,
                              session_name)

            # NOTE: Until the repo branches, we're only applying the flag
            # on egress mirroring to preserve backwards compatibility.
            if self.mirror_type() == "egress":
                command += " --mirror_stage {}".format(self.mirror_type())

        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)
        time.sleep(2)

    @staticmethod
    def remove_acl_rule_config(duthost, table_name, config_method=CONFIG_MODE_CLI):
        if config_method == CONFIG_MODE_CLI:
            duthost.copy(src=os.path.join(FILE_DIR, EVERFLOW_RULE_DELETE_FILE),
                         dest=DUT_RUN_DIR)
            command = "acl-loader update full {} --table_name {}" \
                .format(os.path.join(DUT_RUN_DIR, EVERFLOW_RULE_DELETE_FILE), table_name)
        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

    @abstractmethod
    def mirror_type(self):
        """
        Get the mirror stage for this set of test cases.

        Used to parametrize test cases based on the mirror stage.
        """
        pass

    @abstractmethod
    def acl_stage(self):
        """
        Get the ACL stage for this set of test cases.

        Used to parametrize test cases based on the ACL stage.
        """
        pass

    def send_and_check_mirror_packets(self,
                                      setup,
                                      mirror_session,
                                      ptfadapter,
                                      duthost,
                                      mirror_packet,
                                      direction,
                                      src_port=None,
                                      dest_ports=None,
                                      expect_recv=True,
                                      valid_across_namespace=True,
                                      skip_traffic_test=False):

        # In Below logic idea is to send traffic in such a way so that mirror traffic
        # will need to go across namespaces and within namespace. If source and mirror destination
        # namespace are different then traffic mirror will go across namespace via (backend asic)
        # else via same namespace(asic)

        src_port_set = set()
        src_port_metadata_map = {}

        if 't2' in setup['topo']:
            if valid_across_namespace is True:
                src_port_set.add(src_port)
                src_port_metadata_map[src_port] = (None, 1)
                if duthost.facts['switch_type'] == "voq":
                    if self.mirror_type() != "egress":  # no egress route on the other node/namespace
                        src_port_set.add(dest_ports[0])
                        src_port_metadata_map[dest_ports[0]] = (setup[direction]["egress_router_mac"], 1)
                else:
                    src_port_set.add(dest_ports[0])
                    src_port_metadata_map[dest_ports[0]] = (setup[direction]["egress_router_mac"], 0)

        else:
            src_port_namespace = setup[direction]["everflow_namespace"]
            dest_ports_namespace = setup[direction]["remote_namespace"]

            if valid_across_namespace is True or src_port_namespace == dest_ports_namespace:
                src_port_set.add(src_port)
                src_port_metadata_map[src_port] = (None, 0)

            # To verify same namespace mirroring we will add destination port also to the Source Port Set
            if src_port_namespace != dest_ports_namespace:
                src_port_set.add(dest_ports[0])
                src_port_metadata_map[dest_ports[0]] = (None, 2)

        if skip_traffic_test is True:
            logging.info("Skipping traffic test")
            return
        # Loop through Source Port Set and send traffic on each source port of the set
        for src_port in src_port_set:
            expected_mirror_packet = BaseEverflowTest.get_expected_mirror_packet(mirror_session,
                                                                                 setup,
                                                                                 duthost,
                                                                                 direction,
                                                                                 mirror_packet,
                                                                                 src_port_metadata_map[src_port][1])
            # Avoid changing the original packet
            mirror_packet_sent = mirror_packet.copy()
            if src_port_metadata_map[src_port][0]:
                mirror_packet_sent[packet.Ether].dst = src_port_metadata_map[src_port][0]

            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, src_port, mirror_packet_sent)

            if expect_recv:
                time.sleep(STABILITY_BUFFER)
                _, received_packet = testutils.verify_packet_any_port(ptfadapter,
                                                                      expected_mirror_packet,
                                                                      ports=dest_ports)

                logging.info("Received packet: %s", packet.Ether(received_packet).summary())

                inner_packet = self._extract_mirror_payload(received_packet, len(mirror_packet_sent))
                logging.info("Received inner packet: %s", inner_packet.summary())

                inner_packet = Mask(inner_packet)

                # For egress mirroring, we expect the DUT to have modified the packet
                # before forwarding it. Specifically:
                #
                # - In L2 the SMAC and DMAC will change.
                # - In L3 the TTL and checksum will change.
                #
                # We know what the TTL and SMAC should be after going through the pipeline,
                # but DMAC and checksum are trickier. For now, update the TTL and SMAC, and
                # mask off the DMAC and IP Checksum to verify the packet contents.
                if self.mirror_type() == "egress":
                    mirror_packet_sent[packet.IP].ttl -= 1
                    if 't2' in setup['topo']:
                        if duthost.facts['switch_type'] == "voq":
                            mirror_packet_sent[packet.Ether].src = setup[direction]["ingress_router_mac"]
                    elif direction == 'downstream' and setup.get("dualtor", False):
                        # On dualtor deployment, the SRC_MAC of the downstream mirror packet is the VLAN MAC
                        mirror_packet_sent[packet.Ether].src = setup[direction]["vlan_mac"]
                    else:
                        mirror_packet_sent[packet.Ether].src = setup[direction]["egress_router_mac"]

                    inner_packet.set_do_not_care_scapy(packet.Ether, "dst")
                    inner_packet.set_do_not_care_scapy(packet.IP, "chksum")

                logging.info("Expected inner packet: %s", mirror_packet_sent.summary())
                pytest_assert(inner_packet.pkt_match(mirror_packet_sent),
                              "Mirror payload does not match received packet")
            else:
                testutils.verify_no_packet_any(ptfadapter, expected_mirror_packet, dest_ports)

    @staticmethod
    def get_expected_mirror_packet(mirror_session, setup, duthost, direction, mirror_packet, ttl_dec):
        payload = mirror_packet.copy()

        # Add vendor specific padding to the packet
        if duthost.facts["asic_type"] in ["mellanox"]:
            if six.PY2:
                payload = binascii.unhexlify("0" * 44) + str(payload)
            else:
                payload = binascii.unhexlify("0" * 44) + bytes(payload)
        if (
            duthost.facts["asic_type"] in ["barefoot", "cisco-8000", "innovium"]
            or duthost.facts.get("platform_asic") in ["broadcom-dnx"]
            or duthost.facts["hwsku"]
            in ["rd98DX35xx", "rd98DX35xx_cn9131", "Nokia-7215-A1"]
        ):
            if six.PY2:
                payload = binascii.unhexlify("0" * 24) + str(payload)
            else:
                payload = binascii.unhexlify("0" * 24) + bytes(payload)

        expected_packet = testutils.simple_gre_packet(
            eth_src=setup[direction]["egress_router_mac"],
            ip_src=mirror_session["session_src_ip"],
            ip_dst=mirror_session["session_dst_ip"],
            ip_dscp=int(mirror_session["session_dscp"]),
            ip_id=0,
            ip_ttl=int(mirror_session["session_ttl"]) - ttl_dec,
            inner_frame=payload
        )

        expected_packet["GRE"].proto = mirror_session["session_gre"]

        expected_packet = Mask(expected_packet)
        expected_packet.set_do_not_care_scapy(packet.Ether, "dst")
        expected_packet.set_do_not_care_scapy(packet.IP, "ihl")
        expected_packet.set_do_not_care_scapy(packet.IP, "len")
        expected_packet.set_do_not_care_scapy(packet.IP, "flags")
        expected_packet.set_do_not_care_scapy(packet.IP, "chksum")
        if duthost.facts["asic_type"] == 'marvell':
            expected_packet.set_do_not_care_scapy(packet.IP, "id")
            expected_packet.set_do_not_care_scapy(packet.GRE, "seqnum_present")
        if duthost.facts["asic_type"] in ["cisco-8000", "innovium"] or \
                duthost.facts.get("platform_asic") in ["broadcom-dnx"]:
            expected_packet.set_do_not_care_scapy(packet.GRE, "seqnum_present")

        # The fanout switch may modify this value en route to the PTF so we should ignore it, even
        # though the session does have a DSCP specified.
        expected_packet.set_do_not_care_scapy(packet.IP, "tos")

        # Mask off the payload (we check it later)
        expected_packet.set_do_not_care(OUTER_HEADER_SIZE * 8, len(payload) * 8)

        return expected_packet

    def _extract_mirror_payload(self, encapsulated_packet, payload_size):
        pytest_assert(len(encapsulated_packet) >= OUTER_HEADER_SIZE,
                      "Incomplete packet, expected at least {} header bytes".format(OUTER_HEADER_SIZE))

        inner_frame = encapsulated_packet[-payload_size:]
        return packet.Ether(inner_frame)

    @staticmethod
    def mirror_session_info(session_name, asic_type):
        session_src_ip = "1.1.1.1"
        session_dst_ip = "2.2.2.2"
        session_dscp = "8"
        session_ttl = "4"

        if "mellanox" == asic_type:
            session_gre = 0x8949
        elif "barefoot" == asic_type:
            session_gre = 0x22EB
        else:
            session_gre = 0x88BE

        session_prefix_lens = ["24", "32"]
        session_prefixes = []
        for prefix_len in session_prefix_lens:
            session_prefixes.append(str(ipaddr.IPNetwork(session_dst_ip + "/" + prefix_len).network) + "/" + prefix_len)

        return {
            "session_name": session_name,
            "session_src_ip": session_src_ip,
            "session_dst_ip": session_dst_ip,
            "session_dscp": session_dscp,
            "session_ttl": session_ttl,
            "session_gre": session_gre,
            "session_prefixes": session_prefixes
        }

    @staticmethod
    def _get_tx_port_id_list(tx_ports):
        tx_port_ids = []
        for port in tx_ports:
            members = port.split(',')
            for member in members:
                tx_port_ids.append(int(member))
        return tx_port_ids
