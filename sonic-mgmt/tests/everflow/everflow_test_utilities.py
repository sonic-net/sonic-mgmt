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
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.packet import Raw

from abc import abstractmethod
from ptf.mask import Mask
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, check_msg_in_syslog
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import find_duthost_on_role
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP
from tests.common.macsec.macsec_helper import MACSEC_INFO
from tests.common.dualtor.dual_tor_common import mux_config              # noqa: F401
from tests.common.helpers.sonic_db import AsicDbCli
import json

# TODO: Add suport for CONFIGLET mode
CONFIG_MODE_CLI = "cli"
CONFIG_MODE_CONFIGLET = "configlet"

TEMPLATE_DIR = "everflow/templates"
EVERFLOW_RULE_CREATE_TEMPLATE = "acl-erspan.json.j2"

FILE_DIR = "everflow/files"
EVERFLOW_V4_RULES = "ipv4_test_rules.yaml"
EVERFLOW_DSCP_RULES = "dscp_test_rules.yaml"
IP_TYPE_RULE_V6 = "test_rules_ip_type_v6.json"

DUT_RUN_DIR = "/tmp/everflow"
EVERFLOW_RULE_CREATE_FILE = "acl-erspan.json"
EVERFLOW_RULE_DELETE_FILE = "acl-remove.json"
EVERFLOW_NOT_OPENCONFIG_CREATE_FILE = 'acl_config.json'

STABILITY_BUFFER = 0.05     # 50msec

OUTER_HEADER_SIZE = len(packet.Ether()) + len(packet.IP()) + len(packet.GRE())
OUTER_HEADER_SIZE_V6 = len(packet.Ether()) + len(packet.IPv6()) + len(packet.GRE())

LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"

# This IP is hardcoded into ACL rule
TARGET_SERVER_IP = "192.168.0.2"
# This IP is used as server ip
DEFAULT_SERVER_IP = "192.168.0.3"
VLAN_BASE_MAC_PATTERN = "72060001{:04}"
DOWN_STREAM = "downstream"
UP_STREAM = "upstream"
# Topo that downstream neighbor of DUT are servers
DOWNSTREAM_SERVER_TOPO = ["t0", "m0_vlan"]


def get_default_server_ip(mux_config, avoidList):      # noqa F811
    """
    Get default server IP
    """
    for _, port_config in list(mux_config.items()):
        if (server_ip := port_config["SERVER"]["IPv4"].split('/')[0]) not in avoidList:
            return server_ip
    return DEFAULT_SERVER_IP


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
            else:
                for item in DOWNSTREAM_NEIGHBOR_MAP[topo_type].replace(" ", "").split(','):
                    if item in neigh["name"].lower():
                        downstream_ports_namespace_map[neigh['namespace']].append(dut_port)
                        downstream_ports_namespace.add(neigh['namespace'])
                        downstream_neigh_namespace_map[neigh['namespace']].add(neigh["name"])
    # For FT2, we just copy the upstream ports to downstream ports
    if "ft2" in topo:
        downstream_ports_namespace = upstream_ports_namespace.copy()
        downstream_ports_namespace_map = upstream_ports_namespace_map.copy()

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


@pytest.fixture(scope="module", params=[4, 6], ids=["erspan_ipv4", "erspan_ipv6"])
def erspan_ip_ver(request):
    """
    IP version of the outer IP header in a GRE packet
    """
    return request.param


def clear_queue_counters(duthost, asic_ns):
    """
    @summary: Clear the queue counters for the host
    """
    if asic_ns is not None and duthost.sonichost.is_multi_asic:
        asic_id = duthost.get_asic_id_from_namespace(asic_ns)
        asichost = duthost.asic_instance(asic_id)
        asichost.command("sonic-clear queuecounters")
    else:
        duthost.command("sonic-clear queuecounters")


def check_queue_counters(dut, asic_ns, port, queue, pkt_count):
    """
    @summary: Determine whether queue counter value increased or not
    """
    output = get_queue_counters(dut, asic_ns, port, queue)
    return output == pkt_count


def get_queue_counters(dut, asic_ns, port, queue):
    """
    @summary: Return the counter for a given queue in given port
    """
    if dut.sonichost.is_multi_asic and asic_ns is not None:
        cmd = "show queue counters -n {} {}".format(asic_ns, port)
    else:
        cmd = "show queue counters {}".format(port)

    output = dut.command(cmd)['stdout_lines']
    txq = "UC{}".format(queue)
    for line in output:
        fields = line.split()
        if fields[1] == txq:
            return int(fields[2].replace(',', ''))
    return -1


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
    if 't2' in topo:
        if len(duthosts) == 1:
            downstream_duthost = upstream_duthost = duthost = duthosts[rand_one_dut_hostname]
        else:
            pytest_assert(len(duthosts) > 2, "Test must run on whole chassis")
            downstream_duthost, upstream_duthost = get_t2_duthost(duthosts, tbinfo)
    else:
        downstream_duthost = upstream_duthost = duthost = duthosts[rand_one_dut_hostname]

    setup_information = gen_setup_information(duthost, downstream_duthost, upstream_duthost, tbinfo, topo_scenario)

    # Disable BGP so that we don't keep on bouncing back mirror packets
    # If we send TTL=1 packet we don't need this but in multi-asic TTL > 1

    if 't2' in topo and 'lt2' not in topo and 'ft2' not in topo:
        for dut_host in duthosts.frontend_nodes:
            dut_host.command("sudo config bgp shutdown all")
            dut_host.command("mkdir -p {}".format(DUT_RUN_DIR))
    else:
        duthost.command("sudo config bgp shutdown all")
        duthost.command("mkdir -p {}".format(DUT_RUN_DIR))

    time.sleep(60)

    yield setup_information

    # Enable BGP again
    if 't2' in topo and 'lt2' not in topo and 'ft2' not in topo:
        for dut_host in duthosts.frontend_nodes:
            dut_host.command("sudo config bgp startup all")
            dut_host.command("rm -rf {}".format(DUT_RUN_DIR))
    else:
        duthost.command("sudo config bgp startup all")
        duthost.command("rm -rf {}".format(DUT_RUN_DIR))
    time.sleep(60)


@pytest.fixture(scope="module", autouse=True)
def skip_ipv6_everflow_tests(setup_info, erspan_ip_ver):
    """
    Skip IPv6 Everflow tests if the DUT is a virtual switch.
    """
    if erspan_ip_ver == 6 and setup_info[UP_STREAM]["everflow_dut"].facts["asic_type"] == "vs":
        pytest.skip("Skipping IPv6 Everflow tests to speed up PR test execution.")


def validate_asic_route(duthost, prefix):
    """
    Check if a route exists in the routing table of the asic.
    """
    asicdb = AsicDbCli(duthost)
    route_table = asicdb.dump("ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY")
    if prefix in str(route_table):
        return True
    return False


def validate_mirror_session_up(duthost, session_name):
    """
    Check if a mirror session is up.
    """
    cmd = f'sonic-db-cli STATE_DB HGET \"MIRROR_SESSION_TABLE|{session_name}\" status'
    mirror_status = duthost.command(cmd)['stdout']
    if 'active' in mirror_status:
        return True
    return False


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
def setup_arp_responder(duthost, ptfhost, setup_info, mux_config):      # noqa F811
    if setup_info['topo'] not in ['t0', 'm0_vlan']:
        yield
        return
    ip_list = [TARGET_SERVER_IP, get_default_server_ip(mux_config, [TARGET_SERVER_IP])]
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
def get_neighbor_info(duthost, dest_port, tbinfo, resolved=True, ip_version=4):
    """
    Get the IP and MAC of the neighbor on the specified destination port.

    Args:
        duthost: DUT fixture
        dest_port: The port for which to gather the neighbor information
        resolved: Whether to return a resolved route or not
    """
    if not resolved:
        return "20.20.20.100" if ip_version == 4 else "2020::20:20:20:100"

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for bgp_peer in mg_facts["minigraph_bgp"]:
        if bgp_peer["name"] == mg_facts["minigraph_neighbors"][dest_port]["name"] \
                and ipaddr.IPAddress(bgp_peer["addr"]).version == ip_version:
            peer_ip = bgp_peer["addr"]
            break

    return peer_ip


# TODO: This can probably be moved to a shared location in a later PR.
def load_acl_rules_config(table_name, rules_file):
    with open(rules_file, "r") as f:
        acl_rules = yaml.safe_load(f)

    rules_config = {"acl_table_name": table_name, "rules": acl_rules}

    return rules_config


def verify_mirror_packets_on_recircle_port(self, ptfadapter, setup, mirror_session, duthost, rx_port,
                                           tx_ports, direction, queue, asic_ns, recircle_port,
                                           erspan_ip_ver, expect_recv=True, valid_across_namespace=True):
    tx_port_ids = self._get_tx_port_id_list(tx_ports)
    default_ip = self.DEFAULT_DST_IP
    router_mac = setup[direction]["ingress_router_mac"]
    pkt = self._base_tcp_packet(ptfadapter, setup, router_mac, src_ip="20.0.0.10", dst_ip=default_ip)
    # Number of packets to send
    packet_count = {"iteration-1": 10, "iteration-2": 50, "iteration-3": 100}
    for iteration, count in list(packet_count.items()):
        clear_queue_counters(duthost, asic_ns)
        for i in range(1, count + 1):
            logging.info("Sending packet {} to DUT for {}".format(i, iteration))
            self.send_and_check_mirror_packets(
                setup,
                mirror_session,
                ptfadapter,
                duthost,
                pkt,
                direction,
                src_port=rx_port,
                dest_ports=tx_port_ids,
                expect_recv=expect_recv,
                valid_across_namespace=valid_across_namespace,
                erspan_ip_ver=erspan_ip_ver
            )

        # Assert the specific asic recircle port's queue
        # Make sure mirrored packets are sent via specific queue configured
        for q in range(1, 8):
            if str(q) == queue:
                assert wait_until(30, 1, 0, check_queue_counters, duthost, asic_ns, recircle_port, q, count), \
                    "Recircle port {} queue{} counter value is not same as packets sent".format(recircle_port, q)
            else:
                assert (get_queue_counters(duthost, asic_ns, recircle_port, q) == 0)


def check_rule_creation_on_dut(duthost, command):
    if duthost.is_supervisor_node():
        return
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="acl-rule")
    loganalyzer.load_common_config()
    try:
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
        # Ignore any other errors to reduce noise
        loganalyzer.ignore_regex = [r".*"]
        with loganalyzer:
            duthost.command(command)
            wait_until(60, 5, 0, check_msg_in_syslog,
                       duthost, LOG_EXPECT_ACL_RULE_CREATE_RE)
    except LogAnalyzerError as err:
        logging.error("ACL Rule creation on {} failed.".format(duthost))
        raise err


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
    def setup_mirror_session(self, config_method, setup_info, erspan_ip_ver):
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
            # Skip IPv6 mirror session due to issue #19096
            if duthost.facts['platform'] in ('x86_64-arista_7260cx3_64', 'x86_64-arista_7060_cx32s') and erspan_ip_ver == 6: # noqa E501
                pytest.skip("Skip IPv6 mirror session on unsupported platforms")

            BaseEverflowTest.apply_mirror_config(duthost, session_info, config_method, erspan_ip_ver=erspan_ip_ver)

        yield session_info

        for duthost in duthost_set:
            BaseEverflowTest.remove_mirror_config(duthost, session_info["session_name"], config_method)

    @pytest.fixture(scope="class")
    def policer_mirror_session(self, config_method, setup_info, erspan_ip_ver):
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
            BaseEverflowTest.apply_mirror_config(duthost, session_info, config_method, policer=policer,
                                                 erspan_ip_ver=erspan_ip_ver)

        yield session_info

        # Clean up mirror session and policer
        for duthost in duthost_set:
            BaseEverflowTest.remove_mirror_config(duthost, session_info["session_name"], config_method)
            self.remove_policer_config(duthost, policer, config_method)

    @staticmethod
    def apply_mirror_config(duthost, session_info, config_method=CONFIG_MODE_CLI, policer=None,
                            erspan_ip_ver=4, queue_num=None):
        commands_list = list()
        if config_method == CONFIG_MODE_CLI:
            if erspan_ip_ver == 4:
                command = f"config mirror_session add {session_info['session_name']} \
                            {session_info['session_src_ip']} {session_info['session_dst_ip']} \
                            {session_info['session_dscp']} {session_info['session_ttl']} \
                            {session_info['session_gre']}"
                if queue_num:
                    command += f" {queue_num}"
                if policer:
                    command += f" --policer {policer}"
                commands_list.append(command)
            else:
                for asic_index in duthost.get_frontend_asic_ids():
                    # Adding IPv6 ERSPAN sessions for each asic, from the CLI is currently not supported.
                    if asic_index is not None:
                        command = f"sonic-db-cli -n asic{asic_index} "
                    else:
                        command = "sonic-db-cli "
                    command += (
                        f"CONFIG_DB HSET 'MIRROR_SESSION|{session_info['session_name']}' "
                        f"'dscp' '{session_info['session_dscp']}' "
                        f"'dst_ip' '{session_info['session_dst_ipv6']}' "
                        f"'gre_type' '{session_info['session_gre']}' "
                        f"'type' '{session_info['session_type']}' "
                        f"'src_ip' '{session_info['session_src_ipv6']}' "
                        f"'ttl' '{session_info['session_ttl']}'"
                    )
                    if queue_num:
                        command += f" 'queue' {queue_num}"
                    if policer:
                        command += f" 'policer' {policer}"
                    commands_list.append(command)

        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        for command in commands_list:
            duthost.command(command)

    @staticmethod
    def remove_mirror_config(duthost, session_name, config_method=CONFIG_MODE_CLI):
        if config_method == CONFIG_MODE_CLI:
            command = "config mirror_session remove {}".format(session_name)
        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

    def apply_policer_config(self, duthost, policer_name, config_method, rate_limit=100):
        if duthost.facts["asic_type"] in ["marvell-prestera", "marvell"]:
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
        if MACSEC_INFO and self.mirror_type() == "egress":
            pytest.skip("With MACSEC {} ACL w/ {} Mirroring not supported, skipping"
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
                filtered_ports = [p for p in bind_ports_list if p and p != "Not Applicable"]
                if filtered_ports:
                    command += " -p {}".format(",".join(filtered_ports))

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
        time.sleep(2)

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

    def remove_outer_ip(self, packet_data):
        """
        The mirror packet from IP in IP tunnel would take an external IP header.
        Remove the outer IP header from the IPinIP packet and keeps the original Ethernet header.

        Args:
            packet_data: Original IPinIP packet

        Returns:
            scapy.Ether: Original Ethernet header + Inner IP header + payload
        """
        if isinstance(packet_data, bytes):
            outer_pkt = Ether(packet_data)
        else:
            outer_pkt = packet_data

        if not outer_pkt.haslayer(IP):
            return None

        outer_ip = outer_pkt[IP]

        if outer_ip.proto != 4:
            return None

        # Extract the original Ethernet header
        original_eth = outer_pkt[Ether]
        eth_dst = original_eth.dst
        eth_src = original_eth.src
        eth_type = 0x0800

        inner_payload = outer_ip.payload

        # If the payload is Raw type, we need to re-parse it as IP
        if isinstance(inner_payload, Raw):
            inner_ip_packet = IP(bytes(inner_payload))
        else:
            inner_ip_packet = inner_payload
        new_packet = Ether(dst=eth_dst, src=eth_src, type=eth_type) / inner_ip_packet

        return new_packet

    def check_rule_active(self, duthost, table_name):
        """
        Check if Acl rule initialized

        Args:
            duthost: DUT host object
        Returns:
            Bool value
        """
        res = duthost.shell(f"show acl rule {table_name}")['stdout_lines']
        if "Status" not in res[0]:
            return False
        status_index = res[0].index("Status")
        for line in res[2:]:
            if len(line) < status_index:
                continue
            if line[status_index:] != 'Active':
                return False
        return True

    def apply_non_openconfig_acl_rule(self, duthost, extra_vars, rule_file, table_name):
        """
        Not all ACL match groups are valid in openconfig-acl format used in rest of these
        tests. Instead we must load these uing SONiC-style acl jsons.

        Args:
            duthost: Device under test
            extra_vars: Variables needed to fill template in `rule_file`
            rule_file: File with rule template to stage on `duthost`
        """
        dest_path = os.path.join(DUT_RUN_DIR, EVERFLOW_NOT_OPENCONFIG_CREATE_FILE)
        duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
        duthost.file(path=dest_path, state='absent')
        duthost.template(src=os.path.join(FILE_DIR, rule_file), dest=dest_path)
        duthost.shell("config load -y {}".format(dest_path))

        if duthost.facts['asic_type'] != 'vs':
            pytest_assert(wait_until(60, 2, 0, self.check_rule_active, duthost, table_name),
                          "Acl rule counters are not ready")

    def apply_ip_type_rule(self, duthost, ip_version):
        """
        Applies rule to match SAI-defined IP_TYPE. This has to be done separately as the openconfig-acl
        definition does not cover ip_type. Requires also matching on another attribute as otherwise
        unwanted traffic is also mirrored.

        Args:
            duthost: Device under test
            table_name: Which Everflow table to add this rule to
            ip_version: 4 for ipv4 and 6 for ipv6
        """
        if ip_version == 4:
            pytest.skip("IP_TYPE Matching test has not been written for IPv4")
        else:
            rule_file = IP_TYPE_RULE_V6
        table_name = "EVERFLOWV6" if self.acl_stage() == "ingress" else "EVERFLOW_EGRESSV6"
        action = "MIRROR_INGRESS_ACTION" if self.acl_stage() == "ingress" else "MIRROR_EGRESS_ACTION"
        extra_vars = {
            'table_name': table_name,
            'action': action
        }
        self.apply_non_openconfig_acl_rule(duthost, extra_vars, rule_file, table_name)

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
                                      erspan_ip_ver=4,
                                      multi_binding_acl=False):

        # In Below logic idea is to send traffic in such a way so that mirror traffic
        # will need to go across namespaces and within namespace. If source and mirror destination
        # namespace are different then traffic mirror will go across namespace via (backend asic)
        # else via same namespace(asic)

        src_port_set = set()
        src_port_metadata_map = {}

        if 't2' in setup['topo'] and 'lt2' not in setup['topo'] and 'ft2' not in setup['topo']:
            if valid_across_namespace is True:
                src_port_set.add(src_port)
                src_port_metadata_map[src_port] = (None, 1)
                # Add the dest_port to src_port_set only in non MACSEC testbed scenarios
                if not MACSEC_INFO:
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

        # Loop through Source Port Set and send traffic on each source port of the set
        for src_port in src_port_set:
            expected_mirror_packet = BaseEverflowTest.get_expected_mirror_packet(mirror_session,
                                                                                 setup,
                                                                                 duthost,
                                                                                 direction,
                                                                                 mirror_packet,
                                                                                 src_port_metadata_map[src_port][1],
                                                                                 erspan_ip_ver,
                                                                                 multi_binding_acl=multi_binding_acl)
            # Avoid changing the original packet
            mirror_packet_sent = mirror_packet.copy()
            if src_port_metadata_map[src_port][0]:
                mirror_packet_sent[packet.Ether].dst = src_port_metadata_map[src_port][0]
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, src_port, mirror_packet_sent)

            if expect_recv:
                time.sleep(STABILITY_BUFFER)
                result = testutils.verify_packet_any_port(ptfadapter,
                                                          expected_mirror_packet,
                                                          ports=dest_ports)

                if isinstance(result, bool):
                    logging.info("Using dummy testutils to skip traffic test, skip following checks")
                    return

                _, received_packet = result
                logging.info("Received packet: %s", packet.Ether(received_packet).summary())

                inner_packet = self._extract_mirror_payload(received_packet, len(mirror_packet_sent), erspan_ip_ver,
                                                            multi_binding_acl=multi_binding_acl)
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
                    inner_packet.set_do_not_care_scapy(packet.Ether, "dst")

                    if self.acl_ip_version() == 4:
                        mirror_packet_sent[packet.IP].ttl -= 1
                        inner_packet.set_do_not_care_scapy(packet.IP, "chksum")
                    else:
                        mirror_packet_sent[packet.IPv6].hlim -= 1

                    if 't2' in setup['topo']:
                        if duthost.facts['switch_type'] == "voq":
                            mirror_packet_sent[packet.Ether].src = setup[direction]["ingress_router_mac"]
                    elif direction == 'downstream' and setup.get("dualtor", False):
                        # On dualtor deployment, the SRC_MAC of the downstream mirror packet is the VLAN MAC
                        mirror_packet_sent[packet.Ether].src = setup[direction]["vlan_mac"]
                    else:
                        mirror_packet_sent[packet.Ether].src = setup[direction]["egress_router_mac"]

                if multi_binding_acl:
                    inner_packet.set_do_not_care_scapy(packet.Ether, "dst")
                    inner_packet.set_do_not_care_scapy(packet.Ether, "src")
                    inner_packet.set_do_not_care_scapy(packet.IP, "chksum")
                    inner_packet.set_do_not_care_scapy(packet.IP, "ttl")

                logging.info("Expected inner packet: %s", mirror_packet_sent.summary())
                pytest_assert(inner_packet.pkt_match(mirror_packet_sent),
                              "Mirror payload does not match received packet")
            else:
                testutils.verify_no_packet_any(ptfadapter, expected_mirror_packet, dest_ports)

    @staticmethod
    def copy_and_pad(pkt, asic_type, platform_asic, hwsku, multi_binding_acl=False):
        padded = pkt.copy()

        # Add vendor specific padding to the packet
        if asic_type == "mellanox":
            if six.PY2:
                if multi_binding_acl:
                    padded = binascii.unhexlify("0" * 44) + str(padded)[:24] + binascii.unhexlify("0" * 40) + \
                        str(padded)[24:]
                else:
                    padded = binascii.unhexlify("0" * 44) + str(padded)
            else:
                if multi_binding_acl:
                    padded = binascii.unhexlify("0" * 44) + bytes(padded)[:24] + binascii.unhexlify("0" * 40) + \
                        bytes(padded)[24:]
                else:
                    padded = binascii.unhexlify("0" * 44) + bytes(padded)
        if asic_type in ["barefoot", "cisco-8000", "marvell-teralynx"] \
           or platform_asic == "broadcom-dnx" \
           or hwsku in ["rd98DX35xx", "rd98DX35xx_cn9131"] \
           or hwsku.startswith("Nokia-7215-A1"):
            if six.PY2:
                padded = binascii.unhexlify("0" * 24) + str(padded)
            else:
                padded = binascii.unhexlify("0" * 24) + bytes(padded)
        return padded

    @staticmethod
    def get_expected_mirror_packet_ipv4(mirror_session, setup, duthost, direction, mirror_packet, ttl_dec,
                                        multi_binding_acl=False):
        asic_type = duthost.facts["asic_type"]
        platform_asic = duthost.facts.get("platform_asic")
        hwsku = duthost.facts["hwsku"]
        payload = BaseEverflowTest.copy_and_pad(mirror_packet, asic_type, platform_asic, hwsku,
                                                multi_binding_acl=multi_binding_acl)

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
        expected_packet.set_do_not_care_packet(packet.Ether, "dst")
        expected_packet.set_do_not_care_packet(packet.IP, "ihl")
        expected_packet.set_do_not_care_packet(packet.IP, "len")
        expected_packet.set_do_not_care_packet(packet.IP, "flags")
        expected_packet.set_do_not_care_packet(packet.IP, "chksum")
        if duthost.facts["asic_type"] in ["marvell-prestera", "marvell"]:
            expected_packet.set_do_not_care_packet(packet.IP, "id")
        if asic_type in ["marvell", "cisco-8000", "marvell-teralynx", "marvell-prestera"] or \
           platform_asic == "broadcom-dnx":
            expected_packet.set_do_not_care_packet(packet.GRE, "seqnum_present")

        # The fanout switch may modify this value en route to the PTF so we should ignore it, even
        # though the session does have a DSCP specified.
        expected_packet.set_do_not_care_packet(packet.IP, "tos")

        # Mask off the payload (we check it later)
        expected_packet.set_do_not_care(OUTER_HEADER_SIZE * 8, len(payload) * 8)

        return expected_packet

    @staticmethod
    def get_expected_mirror_packet_ipv6(mirror_session, setup, duthost, direction, mirror_packet, hlim_dec,
                                        multi_binding_acl=False):
        asic_type = duthost.facts["asic_type"]
        platform_asic = duthost.facts.get("platform_asic")
        hwsku = duthost.facts["hwsku"]
        payload = BaseEverflowTest.copy_and_pad(mirror_packet, asic_type, platform_asic, hwsku,
                                                multi_binding_acl=multi_binding_acl)

        expected_packet = testutils.simple_grev6_packet(
            eth_src=setup[direction]["egress_router_mac"],
            ipv6_src=mirror_session["session_src_ipv6"],
            ipv6_dst=mirror_session["session_dst_ipv6"],
            ipv6_dscp=int(mirror_session["session_dscp"]),
            ipv6_hlim=int(mirror_session["session_ttl"]) - hlim_dec,
            inner_frame=payload
        )

        expected_packet["GRE"].proto = mirror_session["session_gre"]

        expected_packet = Mask(expected_packet)
        expected_packet.set_do_not_care_packet(packet.Ether, "dst")
        expected_packet.set_do_not_care_packet(packet.IPv6, "plen")
        expected_packet.set_do_not_care_packet(packet.IPv6, "fl")
        if (asic_type in ["marvell", "cisco-8000", "marvell-teralynx", "marvell-prestera"] or
                platform_asic == "broadcom-dnx"):
            expected_packet.set_do_not_care_packet(packet.GRE, "seqnum_present")
        # The fanout switch may modify this value en route to the PTF so we should ignore it, even
        # though the session does have a DSCP specified.
        expected_packet.set_do_not_care_packet(packet.IPv6, "tc")

        # Mask off the payload (we check it later)
        expected_packet.set_do_not_care(OUTER_HEADER_SIZE_V6 * 8, len(payload) * 8)

        return expected_packet

    @staticmethod
    def get_expected_mirror_packet(mirror_session, setup, duthost, direction, mirror_packet, ttl_dec, erspan_ip_ver=4,
                                   multi_binding_acl=False):
        if erspan_ip_ver == 4:
            return BaseEverflowTest.get_expected_mirror_packet_ipv4(mirror_session, setup, duthost,
                                                                    direction, mirror_packet, ttl_dec,
                                                                    multi_binding_acl=multi_binding_acl)
        else:
            return BaseEverflowTest.get_expected_mirror_packet_ipv6(mirror_session, setup, duthost,
                                                                    direction, mirror_packet, ttl_dec,
                                                                    multi_binding_acl=multi_binding_acl)

    def _extract_mirror_payload(self, encapsulated_packet, payload_size, erspan_ip_ver=4, multi_binding_acl=False):
        outer_header_size = OUTER_HEADER_SIZE if erspan_ip_ver == 4 else OUTER_HEADER_SIZE_V6
        if multi_binding_acl:
            outer_header_size += 20
        pytest_assert(len(encapsulated_packet) >= outer_header_size,
                      f"Incomplete packet, expected at least {outer_header_size} header bytes")

        inner_frame = encapsulated_packet[-payload_size:]
        if multi_binding_acl:
            inner_frame = encapsulated_packet[-(payload_size + 20):]
            inner_frame = self.remove_outer_ip(inner_frame)
            return inner_frame

        return packet.Ether(inner_frame)

    @staticmethod
    def mirror_session_info(session_name, asic_type):
        session_src_ip = "1.1.1.1"
        session_src_ipv6 = "1111::1:1:1:1"
        session_dst_ip = "2.2.2.2"
        session_dst_ipv6 = "2222::2:2:2:2"
        session_dscp = "8"
        session_ttl = "4"
        session_type = "ERSPAN"

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

        session_prefix_lens_ipv6 = ["64", "128"]
        session_prefixes_ipv6 = []
        for prefix_len in session_prefix_lens_ipv6:
            session_prefixes_ipv6.append(str(ipaddr.IPNetwork(session_dst_ipv6 + "/" + prefix_len).network)
                                         + "/" + prefix_len)

        return {
            "session_name": session_name,
            "session_src_ip": session_src_ip,
            "session_src_ipv6": session_src_ipv6,
            "session_dst_ip": session_dst_ip,
            "session_dst_ipv6": session_dst_ipv6,
            "session_dscp": session_dscp,
            "session_ttl": session_ttl,
            "session_gre": session_gre,
            "session_type": session_type,
            "session_prefixes": session_prefixes,
            "session_prefixes_ipv6": session_prefixes_ipv6
        }

    @staticmethod
    def _get_tx_port_id_list(tx_ports):
        tx_port_ids = []
        for port in tx_ports:
            members = port.split(',')
            for member in members:
                tx_port_ids.append(int(member))
        return tx_port_ids
