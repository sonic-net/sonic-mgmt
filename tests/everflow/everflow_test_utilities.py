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

import ptf.testutils as testutils
import ptf.packet as packet

from abc import abstractmethod
from ptf.mask import Mask
from tests.common.helpers.assertions import pytest_assert
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

STABILITY_BUFFER = 0.05 #50msec

OUTER_HEADER_SIZE = 38

# This IP is hardcoded into ACL rule
TARGET_SERVER_IP = "192.168.0.2"
# This IP is used as server ip
DEFAULT_SERVER_IP = "192.168.0.3"
VLAN_BASE_MAC_PATTERN = "72060001{:04}"
DOWN_STREAM = "downstream"
UP_STREAM = "upstream"


def gen_t1t0_setup_information(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Generate setup information dictionary for T0 and T1 topologies.
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo = tbinfo['topo']['name']

    # {namespace: [server ports]}
    server_ports_namespace_map = defaultdict(list)
    # {namespace: [T1 ports]}
    t1_ports_namespace_map = defaultdict(list)
    # { namespace : [tor ports] }
    tor_ports_namespace_map = defaultdict(list)
    # { namespace : [spine ports] }
    spine_ports_namespace_map = defaultdict(list)

    # { set of namespace server ports belong }
    server_ports_namespace = set()
    # { set of namespace t1 ports belong}
    t1_ports_namespace = set()
    # { set of namespace tor ports belongs }
    tor_ports_namespace = set()
    # { set of namespace spine ports belongs }
    spine_ports_namespace = set()

    # Gather test facts
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    switch_capability_facts = duthost.switch_capabilities_facts()["ansible_facts"]
    acl_capability_facts = duthost.acl_capabilities_facts()["ansible_facts"]

    # Get the list of T0/T2 ports
    for dut_port, neigh in mg_facts["minigraph_neighbors"].items():
        if "t1" in topo:
            # Get the list of T0/T2 ports
            if "t0" in neigh["name"].lower():
                # Add Tor ports to namespace
                tor_ports_namespace_map[neigh['namespace']].append(dut_port)
                tor_ports_namespace.add(neigh['namespace'])
            elif "t2" in neigh["name"].lower():
                # Add Spine ports to namespace
                spine_ports_namespace_map[neigh['namespace']].append(dut_port)
                spine_ports_namespace.add(neigh['namespace'])
        elif "t0" in topo:
            # Get the list of Server/T1 ports
            if "server" in neigh["name"].lower():
                # Add Server ports to namespace
                server_ports_namespace_map[neigh['namespace']].append(dut_port)
                server_ports_namespace.add(neigh['namespace'])
            elif "t1" in neigh["name"].lower():
                # Add T1 ports to namespace
                t1_ports_namespace_map[neigh['namespace']].append(dut_port)
                t1_ports_namespace.add(neigh['namespace'])
        else:
            # Todo: Support dualtor testbed
            pytest.skip("Unsupported topo")

    if 't1' in topo:
        # Set of TOR ports only Namespace 
        tor_only_namespace = tor_ports_namespace.difference(spine_ports_namespace)
        # Set of Spine ports only Namespace 
        spine_only_namespace = spine_ports_namespace.difference(tor_ports_namespace)
        # Randomly choose from TOR_only Namespace if present else just use first one 
        tor_namespace = random.choice(tuple(tor_only_namespace)) if tor_only_namespace else tuple(tor_ports_namespace)[0]
        # Randomly choose from Spine_only Namespace if present else just use first one 
        spine_namespace = random.choice(tuple(spine_only_namespace)) if spine_only_namespace else tuple(spine_ports_namespace)[0]
        tor_ports = tor_ports_namespace_map[tor_namespace]
        spine_ports = spine_ports_namespace_map[spine_namespace]

    else:
        # Use the default namespace for Server and T1
        server_namespace = tuple(server_ports_namespace)[0]
        t1_namespace = tuple(t1_ports_namespace)[0]
        server_ports = server_ports_namespace_map[server_namespace]
        t1_ports = t1_ports_namespace_map[t1_namespace]

    switch_capabilities = switch_capability_facts["switch_capabilities"]["switch"]
    acl_capabilities = acl_capability_facts["acl_capabilities"]

    test_mirror_v4 = switch_capabilities["MIRROR"] == "true"
    test_mirror_v6 = switch_capabilities["MIRRORV6"] == "true"

    # NOTE: Older OS versions don't have the ACL_ACTIONS table, and those same devices
    # do not support egress ACLs or egress mirroring. Once we branch out the sonic-mgmt
    # repo we can remove this case.
    if "201811" in duthost.os_version:
        test_ingress_mirror_on_ingress_acl = True
        test_ingress_mirror_on_egress_acl = False
        test_egress_mirror_on_egress_acl = False
        test_egress_mirror_on_ingress_acl = False
    elif acl_capabilities:
        test_ingress_mirror_on_ingress_acl = "MIRROR_INGRESS_ACTION" in acl_capabilities["INGRESS"]["action_list"]
        test_ingress_mirror_on_egress_acl = "MIRROR_INGRESS_ACTION" in acl_capabilities["EGRESS"]["action_list"]
        test_egress_mirror_on_egress_acl = "MIRROR_EGRESS_ACTION" in acl_capabilities["EGRESS"]["action_list"]
        test_egress_mirror_on_ingress_acl = "MIRROR_EGRESS_ACTION" in acl_capabilities["INGRESS"]["action_list"]
    else:
        logging.info("Fallback to the old source of ACL capabilities (assuming SONiC release is < 202111)")
        test_ingress_mirror_on_ingress_acl = "MIRROR_INGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|INGRESS"]
        test_ingress_mirror_on_egress_acl = "MIRROR_INGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|EGRESS"]
        test_egress_mirror_on_egress_acl = "MIRROR_EGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|EGRESS"]
        test_egress_mirror_on_ingress_acl = "MIRROR_EGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|INGRESS"]

    # NOTE: Disable egress mirror test on broadcom platform even SAI claim EGRESS MIRRORING is supported
    # There is a known issue in SAI 7.1 for XGS that SAI claims the capability of EGRESS MIRRORING incorrectly.
    # Hence we override the capability query with below logic. Please remove it after the issue is fixed.
    if duthost.facts["asic_type"] == "broadcom" and duthost.facts.get("platform_asic") != 'broadcom-dnx':
        test_egress_mirror_on_egress_acl = False
        test_egress_mirror_on_ingress_acl = False

    # Collects a list of interfaces, their port number for PTF, and the LAGs they are members of,
    # if applicable.
    #
    # TODO: Add a namedtuple to make the groupings more explicit
    def get_port_info(in_port_list, out_port_list, out_port_ptf_id_list, out_port_lag_name):
        out_port_exclude_list = []
        for port in in_port_list:
            if port not in out_port_list and port not in out_port_exclude_list and len(out_port_list) < 4:
                ptf_port_id = str(mg_facts["minigraph_ptf_indices"][port])
                out_port_list.append(port)
                if out_port_lag_name != None:
                    out_port_lag_name.append("Not Applicable")

                for portchannelinfo in mg_facts["minigraph_portchannels"].items():
                    if port in portchannelinfo[1]["members"]:
                        if out_port_lag_name != None:
                            out_port_lag_name[-1] = portchannelinfo[0]
                        for lag_member in portchannelinfo[1]["members"]:
                            if port == lag_member:
                                continue
                            ptf_port_id += "," + (str(mg_facts["minigraph_ptf_indices"][lag_member]))
                            out_port_exclude_list.append(lag_member)

                out_port_ptf_id_list.append(ptf_port_id)

    setup_information = {
        "router_mac": duthost.facts["router_mac"],
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
        "port_index_map": {
            k: v
            for k, v in mg_facts["minigraph_ptf_indices"].items()
            if k in mg_facts["minigraph_ports"]
        },
        # { ptf_port_id : namespace }
        "port_index_namespace_map" : {
           v: mg_facts["minigraph_neighbors"][k]['namespace']
           for k, v in mg_facts["minigraph_ptf_indices"].items()
           if k in mg_facts["minigraph_ports"]
        }
    }

    if 't0' in topo:
        # Downstream traffic (T0 -> Server)
        server_dest_ports = []
        server_dest_ports_ptf_id = []
        get_port_info(server_ports, server_dest_ports, server_dest_ports_ptf_id, None)

        # Upstream traffic (Server -> T0)
        t1_dest_ports = []
        t1_dest_ports_ptf_id = []
        t1_dest_lag_name = []
        get_port_info(t1_ports, t1_dest_ports, t1_dest_ports_ptf_id, t1_dest_lag_name)

        setup_information.update(
            {
                "topo": "t0",
                "server_ports": server_ports,
                "server_dest_ports_ptf_id": server_dest_ports_ptf_id,
                "t1_ports": t1_ports,
                DOWN_STREAM: {
                    "src_port": t1_ports[0],
                    "src_port_lag_name":t1_dest_lag_name[0],
                    "src_port_ptf_id": str(mg_facts["minigraph_ptf_indices"][t1_ports[0]]),
                    # Downstream traffic ingress from the first portchannel,
                    # and mirror packet egress from other portchannels
                    "dest_port": t1_dest_ports[1:],
                    "dest_port_ptf_id": t1_dest_ports_ptf_id[1:],
                    "dest_port_lag_name": t1_dest_lag_name[1:],
                    "namespace": server_namespace
                },
                UP_STREAM: {
                    "src_port": server_ports[0],
                    "src_port_lag_name":"Not Applicable",
                    "src_port_ptf_id": str(mg_facts["minigraph_ptf_indices"][server_ports[0]]),
                    "dest_port": t1_dest_ports,
                    "dest_port_ptf_id": t1_dest_ports_ptf_id,
                    "dest_port_lag_name": t1_dest_lag_name,
                    "namespace": t1_namespace
                },
            }
        )
    elif 't1' in topo:
        # Downstream traffic (T1 -> T0)
        tor_dest_ports = []
        tor_dest_ports_ptf_id = []
        tor_dest_lag_name = []
        get_port_info(tor_ports, tor_dest_ports, tor_dest_ports_ptf_id, tor_dest_lag_name)

        # Upstream traffic (T0 -> T1)
        spine_dest_ports = []
        spine_dest_ports_ptf_id = []
        spine_dest_lag_name = []
        get_port_info(spine_ports, spine_dest_ports, spine_dest_ports_ptf_id, spine_dest_lag_name)

        setup_information.update(
            {
                "topo": "t1",
                "tor_ports": tor_ports,
                "spine_ports": spine_ports,
                DOWN_STREAM: {
                    "src_port": spine_ports[0],
                    "src_port_lag_name":spine_dest_lag_name[0],
                    "src_port_ptf_id": str(mg_facts["minigraph_ptf_indices"][spine_ports[0]]),
                    "dest_port": tor_dest_ports,
                    "dest_port_ptf_id": tor_dest_ports_ptf_id,
                    "dest_port_lag_name": tor_dest_lag_name,
                    "namespace": tor_namespace
                    },
                UP_STREAM: {
                    "src_port": tor_ports[0],
                    "src_port_lag_name":tor_dest_lag_name[0],
                    "src_port_ptf_id": str(mg_facts["minigraph_ptf_indices"][tor_ports[0]]),
                    "dest_port": spine_dest_ports,
                    "dest_port_ptf_id": spine_dest_ports_ptf_id,
                    "dest_port_lag_name": spine_dest_lag_name,
                    "namespace": spine_namespace
                }
            }
        )
    return setup_information


def find_host_role(duthosts, role, tbinfo, hwsku=None):
    """Find linecard connecting to T3 or T1 VMS."""
    logging.info("Find host with role: %s, hwsku: %s", role, hwsku)
    role_set = False

    for duthost in duthosts:
        if role_set:
            break
        if duthost.is_supervisor_node():
            continue

        for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
            namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst, 'namespace') else ''
            if namespace == '':
                continue
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace)
            for interface, neighbor in mg_facts["minigraph_neighbors"].items():
                if hwsku is None:
                    if role in neighbor["name"]:
                        role_host = duthost
                        role_set = True
                else:
                    if role in neighbor["name"] and duthost.facts['hwsku'] == hwsku:
                        role_host = duthost
                        role_set = True
    return role_host


def gen_t2_setup_information(duthosts, tbinfo):
    """
    Generate setup information dictionary for T2 topologies.
    """
    setup_information = {}

    def find_role_ports(duthost, role):
        """
        Grab ports and portchannels for the T1 facing or T3 facing linecards.
        """
        role_interfaces = []
        role_portids = []
        role_pc_names = []
        for asic in duthost.asics:
            mg_facts = asic.get_extended_minigraph_facts(tbinfo)
            pc_members = []
            for pc in mg_facts["minigraph_portchannels"]:
                pc_members.extend(mg_facts["minigraph_portchannels"][pc]['members'])

            # Find routed ports on asic and add to interface list.
            for interface, neighbor in mg_facts["minigraph_neighbors"].items():
                port_id = mg_facts["minigraph_ptf_indices"][interface]
                if role in neighbor["name"]:
                    if interface not in pc_members:
                        if len(role_interfaces) >= 4:
                            continue
                        role_interfaces.append(interface)
                        role_portids.append(str(port_id))
                        role_pc_names.append("Not Applicable")

            # Find portchannels on asic and add to interface list.
            for pc in mg_facts['minigraph_portchannels']:
                pc_member = mg_facts["minigraph_portchannels"][pc]['members'][0]
                if len(role_interfaces) >= 4:
                    break
                role_interfaces.append(pc_member)
                role_pc_names.append(pc)
                portids = str(mg_facts["minigraph_ptf_indices"][pc_member])
                for pc_member in mg_facts["minigraph_portchannels"][pc]['members'][1:]:
                    portids += ",%s" % str(mg_facts["minigraph_ptf_indices"][pc_member])
                role_portids.append(portids)

        return {'interfaces': role_interfaces,
                'portids': role_portids,
                'mgfacts': duthost.get_extended_minigraph_facts(tbinfo),
                'pc_names': role_pc_names}

    t3_duthost = find_host_role(duthosts, "T3", tbinfo)
    t1_duthost = find_host_role(duthosts, "T1", tbinfo, hwsku=t3_duthost.facts['hwsku'])

    t3_info = find_role_ports(t3_duthost, "T3")
    t1_info = find_role_ports(t1_duthost, "T1")

    mg_facts = t3_duthost.get_extended_minigraph_facts(tbinfo)
    acl_capability_facts = t3_duthost.acl_capabilities_facts()["ansible_facts"]

    acl_capabilities = acl_capability_facts["acl_capabilities"]

    test_ingress_mirror_on_ingress_acl = "MIRROR_INGRESS_ACTION" in acl_capabilities["INGRESS"]["action_list"]
    test_ingress_mirror_on_egress_acl = "MIRROR_INGRESS_ACTION" in acl_capabilities["EGRESS"]["action_list"]
    test_egress_mirror_on_egress_acl = "MIRROR_EGRESS_ACTION" in acl_capabilities["EGRESS"]["action_list"]
    test_egress_mirror_on_ingress_acl = "MIRROR_EGRESS_ACTION" in acl_capabilities["INGRESS"]["action_list"]

    setup_information.update(
        {
            "topo": "t2",
            "ingress": {
                "ingress": test_ingress_mirror_on_ingress_acl,
                "egress": test_egress_mirror_on_ingress_acl
            },
            "egress": {
                "ingress": test_ingress_mirror_on_egress_acl,
                "egress": test_egress_mirror_on_egress_acl
            },
            "port_index_map": {
                k: v
                for k, v in mg_facts["minigraph_ptf_indices"].items()
                if k in mg_facts["minigraph_ports"]
            },
            "port_index_namespace_map": {},
            DOWN_STREAM: {},
            UP_STREAM: {},
        }
    )

    setup_information['port_index_namespace_map'].update({v: mg_facts["minigraph_neighbors"][k]['namespace']
                                                          for k, v in mg_facts["minigraph_ptf_indices"].items()
                                                          if k in mg_facts["minigraph_ports"]})
    t1_mg_facts = t1_duthost.get_extended_minigraph_facts(tbinfo)
    setup_information['port_index_namespace_map'].update({v: t1_mg_facts["minigraph_neighbors"][k]['namespace']
                                                          for k, v in t1_mg_facts["minigraph_ptf_indices"].items()
                                                          if k in t1_mg_facts["minigraph_ports"]})
    setup_information['intf_to_namespace_map'] = {k: mg_facts["minigraph_neighbors"][k]['namespace']
                                                  for k, v in mg_facts["minigraph_ptf_indices"].items()
                                                  if k in mg_facts["minigraph_ports"]}
    setup_information['intf_to_namespace_map'].update({k: t1_mg_facts["minigraph_neighbors"][k]['namespace']
                                                       for k, v in t1_mg_facts["minigraph_ptf_indices"].items()
                                                       if k in t1_mg_facts["minigraph_ports"]})

    downstream_block = {
        'everflow_dut': t3_duthost,
        'remote_dut': t1_duthost,
        "router_mac": t3_duthost.facts["router_mac"],
        "src_port": t3_info['interfaces'][0],
        "src_port_lag_name": t3_info['pc_names'][0],
        "src_port_ptf_id": str(t3_info['mgfacts']["minigraph_ptf_indices"][t3_info['interfaces'][0]]),
        "dest_port": t1_info['interfaces'],
        "dest_port_ptf_id": t1_info['portids'],
        "dest_port_lag_name": t1_info['pc_names'],
    }
    upstream_block = {
        'everflow_dut': t1_duthost,
        'remote_dut': t3_duthost,
        "router_mac": t1_duthost.facts["router_mac"],
        "src_port": t1_info['interfaces'][-1],
        "src_port_lag_name": t1_info['pc_names'][-1],
        "src_port_ptf_id": str(t1_info['mgfacts']["minigraph_ptf_indices"][t1_info['interfaces'][0]]),
        "dest_port": list(reversed(t3_info['interfaces'])),
        "dest_port_ptf_id": list(reversed(t3_info['portids'])),
        "dest_port_lag_name": list(reversed(t3_info['pc_names'])),
    }
    setup_information[UP_STREAM].update(upstream_block)
    setup_information[DOWN_STREAM].update(downstream_block)

    return setup_information


@pytest.fixture(scope="module")
def setup_info(duthosts, rand_one_dut_hostname, tbinfo, request):
    """
    Gather all required test information.

    Args:
        duthost: DUT fixture
        tbinfo: tbinfo fixture

    Returns:
        dict: Required test information

    """
    topo = tbinfo['topo']['name']
    if 't1' in topo or 't0' in topo:
        setup_information = gen_t1t0_setup_information(duthosts, rand_one_dut_hostname, tbinfo)
        duthost = duthosts[rand_one_dut_hostname]

    if 't2' in topo:
        setup_information = gen_t2_setup_information(duthosts, tbinfo)

    # Disable BGP so that we don't keep on bouncing back mirror packets
    # If we send TTL=1 packet we don't need this but in multi-asic TTL > 1

    if 't2' in topo:
        for duthost in duthosts.frontend_nodes:
            duthost.command("mkdir -p {}".format(DUT_RUN_DIR))
            duthost.command("sudo config bgp shutdown all")
    else:
        duthost.command("sudo config bgp shutdown all")
        duthost.command("mkdir -p {}".format(DUT_RUN_DIR))

    time.sleep(60)

    yield setup_information

    # Enable BGP again
    if 't2' in topo:
        for duthost in duthosts.frontend_nodes:
            duthost.command("sudo config bgp startup all")
            duthost.command("rm -rf {}".format(DUT_RUN_DIR))
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
    duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"ip route {} {}\"".format(prefix, nexthop), namespace))


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
    duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"no ip route {} {}\"".format(prefix, nexthop), namespace))


@pytest.fixture(scope='module', autouse=True)
def setup_arp_responder(duthost, ptfhost, setup_info):
    if setup_info['topo'] != 't0':
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

    ptfhost.command('supervisorctl stop arp_responder')
    ptfhost.file(path='/tmp/arp_responder.json', state="absent")
    duthost.command('sonic-clear arp')


# TODO: This should be refactored to some common area of sonic-mgmt.
def get_neighbor_info(duthost, dest_port, tbinfo, resolved=True, ipver=4):
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
        if bgp_peer["name"] == mg_facts["minigraph_neighbors"][dest_port]["name"] and ipaddr.IPAddress(bgp_peer["addr"]).version == ipver:
            peer_ip = bgp_peer["addr"]
            break

    return peer_ip


# TODO: This can probably be moved to a shared location in a later PR.
def load_acl_rules_config(table_name, rules_file):
    with open(rules_file, "r") as f:
        acl_rules = yaml.safe_load(f)

    rules_config = {"acl_table_name": table_name, "rules": acl_rules}

    return rules_config


def get_intf_namespace(setup_info, dest_port_type, port):
    """
    Return the namespace of a port via the namespace table if present in the setup_info structure or via
    the namespace key in the T0/T1 dictionary.
    
    Args:
        setup_info: The setup_info fixture.
        dest_port_type: UPSTREAM or DOWNSTREAM.
        port: The name of the port to lookup (Ethernet8)
    
    Returns:
        namespace as a string.
    """
    if 'intf_to_namespace_map' in setup_info:
        return setup_info['intf_to_namespace_map'][port]
    else:
        return setup_info[dest_port_type]['namespace']


class BaseEverflowTest(object):
    """
    Base class for setting up a set of Everflow tests.

    Contains common methods for setting up the mirror session and describing the
    mirror and ACL stage for the tests.
    """
    @pytest.fixture(scope="class", autouse=True)
    def skip_on_dualtor(self, tbinfo):
        """
        Skip dualtor topo for now
        """
        if 'dualtor' in tbinfo['topo']['name']:
            pytest.skip("Dualtor testbed is not supported yet")

        self.is_t0 = False
        if 't0' in tbinfo['topo']['name']:
            self.is_t0 = True

    @pytest.fixture(scope="class", params=[CONFIG_MODE_CLI])
    def config_method(self, request):
        """Get the configuration method for this set of test cases.

        There are multiple ways to configure Everflow on a SONiC device,
        so we need to verify that Everflow functions properly for each method.

        Returns:
            The configuration method to use.
        """
        return request.param

    @pytest.fixture(scope="class")
    def setup_mirror_session(self, duthosts, rand_one_dut_hostname, config_method, setup_info):
        """
        Set up a mirror session for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.
        """
        if setup_info['topo'] == 't2':
            duthost_list = [setup_info[DOWN_STREAM]['everflow_dut']]
            if setup_info[UP_STREAM]['everflow_dut'] != setup_info[DOWN_STREAM]['everflow_dut']:
                duthost_list.append(setup_info[UP_STREAM]['everflow_dut'])
        else:
            duthost_list = [duthosts[rand_one_dut_hostname]]

        for duthost in duthost_list:
            session_info = BaseEverflowTest.mirror_session_info("test_session_1", duthost.facts["asic_type"])
            BaseEverflowTest.apply_mirror_config(duthost, session_info, config_method)

        yield session_info

        for duthost in duthost_list:
            BaseEverflowTest.remove_mirror_config(duthost, session_info["session_name"], config_method)

    @pytest.fixture(scope="class")
    def policer_mirror_session(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, config_method, setup_info):
        """
        Set up a mirror session with a policer for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        vendor = duthost.facts["asic_type"]
        hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
        # relocated because of sonic-buildimage issue #11826, leaving skip logic in testcase causes
        # this fixture to run causing crash.
        for asic in self.MIRROR_POLICER_UNSUPPORTED_ASIC_LIST:
            vendorAsic = "{0}_{1}_hwskus".format(vendor, asic)
            if vendorAsic in hostvars.keys() and duthost.facts['hwsku'] in hostvars[vendorAsic]:
                pytest.skip("Skipping test since mirror policing is not supported on {0} {1} platforms".format(vendor, asic))
        policer = "TEST_POLICER"

        # Create a policer that allows 100 packets/sec through
        self.apply_policer_config(duthost, policer, config_method)

        # Create a mirror session with the TEST_POLICER attached
        session_info = BaseEverflowTest.mirror_session_info("TEST_POLICER_SESSION", duthost.facts["asic_type"])
        BaseEverflowTest.apply_mirror_config(duthost, session_info, config_method, policer=policer)

        yield session_info

        # Clean up mirror session and policer
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
    def setup_acl_table(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session, config_method):
        """
        Configure the ACL table for this set of test cases.

        Args:
            duthost: DUT fixture
            setup_info: Fixture with info about the testbed setup
            setup_mirror_session: Fixtue with info about the mirror session
        """
        if setup_info['topo'] == 't2':
            duthost_list = [setup_info[DOWN_STREAM]['everflow_dut']]
            if setup_info[UP_STREAM]['everflow_dut'] != setup_info[DOWN_STREAM]['everflow_dut']:
                duthost_list.append(setup_info[UP_STREAM]['everflow_dut'])
        else:
            duthost_list = [duthosts[rand_one_dut_hostname]]
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("{} ACL w/ {} Mirroring not supported, skipping"
                        .format(self.acl_stage(), self.mirror_type()))

        table_name = "EVERFLOW" if self.acl_stage() == "ingress" else "EVERFLOW_EGRESS"

        # NOTE: We currently assume that the ingress MIRROR tables already exist.
        for duthost in duthost_list:
            if self.acl_stage() == "egress":
                inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
                for inst in inst_list:
                    self.apply_acl_table_config(duthost, table_name, "MIRROR", config_method, bind_namespace=getattr(inst, 'namespace', None))

            self.apply_acl_rule_config(duthost, table_name, setup_mirror_session["session_name"], config_method)

        yield

        for duthost in duthost_list:
            BaseEverflowTest.remove_acl_rule_config(duthost, table_name, config_method)
            if self.acl_stage() == "egress":
                inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
                for inst in inst_list:
                    self.remove_acl_table_config(duthost, "EVERFLOW_EGRESS", config_method, bind_namespace=getattr(inst, 'namespace', None))

    def apply_acl_table_config(self, duthost, table_name, table_type, config_method, bind_ports_list=None, bind_namespace=None):
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
                                      src_port=None,
                                      dest_ports=None,
                                      expect_recv=True,
                                      valid_across_namespace=True,
                                      gre_pkt_src_mac=None,
                                      gre_pkt_dst_mac=None,
                                      egress_mirror_src_mac=None):
        if not src_port:
            src_port = self._get_random_src_port(setup)

        if not dest_ports:
            dest_ports = [self._get_monitor_port(setup, mirror_session, duthost)]

        if gre_pkt_src_mac is None:
            gre_pkt_src_mac = setup['router_mac']
        if egress_mirror_src_mac is None:
            egress_mirror_src_mac = setup['router_mac']
        # In Below logic idea is to send traffic in such a way so that mirror traffic
        # will need to go across namespaces and within namespace. If source and mirror destination
        # namespace are different then traffic mirror will go across namespace via (backend asic)
        # else via same namespace(asic)

        src_port_namespace = self._get_port_namespace(setup, int(src_port))
        dest_ports_namespace = self._get_port_namespace(setup, int(dest_ports[0]))

        src_port_set = set()

        if 't2' in setup['topo']:
            # dest ports are on another card, so can't quite do this namespace logic like on T1.
            src_port_set.add(src_port)
        else:
            # Some of test scenario are not valid across namespaces so test will explicltly pass
            # valid_across_namespace as False (default is True)
            if valid_across_namespace is True or src_port_namespace == dest_ports_namespace:
                src_port_set.add(src_port)

            # To verify same namespace mirroring we will add destination port also to the Source Port Set
            if src_port_namespace != dest_ports_namespace:
                src_port_set.add(dest_ports[0])

        expected_mirror_packet_with_ttl = BaseEverflowTest.get_expected_mirror_packet(mirror_session,
                                                                                      setup,
                                                                                      duthost,
                                                                                      mirror_packet,
                                                                                      True,
                                                                                      router_mac=gre_pkt_src_mac)
        expected_mirror_packet_without_ttl = BaseEverflowTest.get_expected_mirror_packet(mirror_session,
                                                                                         setup,
                                                                                         duthost,
                                                                                         mirror_packet,
                                                                                         False,
                                                                                         router_mac=gre_pkt_src_mac)

        # Loop through Source Port Set and send traffic on each source port of the set
        for src_port in src_port_set:
            expected_mirror_packet = expected_mirror_packet_with_ttl \
                if self._get_port_namespace(setup, int(src_port)) == dest_ports_namespace else expected_mirror_packet_without_ttl

            if 't2' in setup['topo']:
                # T2 with recycle port means ttl will get changed depending on route through the chassis.
                expected_mirror_packet = expected_mirror_packet_without_ttl
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, src_port, mirror_packet)

            if expect_recv:
                time.sleep(STABILITY_BUFFER)
                _, received_packet = testutils.verify_packet_any_port(
                    ptfadapter,
                    expected_mirror_packet,
                    ports=dest_ports
                )
                logging.info("Received packet: %s", packet.Ether(received_packet).summary())

                if gre_pkt_dst_mac is not None:
                    pytest_assert(packet.Ether(received_packet)[packet.Ether].dst == gre_pkt_dst_mac,
                                  "Mirror destination MAC does not match neighbor MAC")
                inner_packet = self._extract_mirror_payload(received_packet, len(mirror_packet))
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
                    if packet.IPv6 in mirror_packet:
                        mirror_packet[packet.IPv6].hlim -= 1
                    else:
                        mirror_packet[packet.IP].ttl -= 1
                    inner_packet.set_do_not_care_scapy(packet.IP, "chksum")
                    mirror_packet[packet.Ether].src = egress_mirror_src_mac
                    inner_packet.set_do_not_care_scapy(packet.Ether, "dst")

                logging.info("Expected inner packet: %s", mirror_packet.summary())
                pytest_assert(inner_packet.pkt_match(mirror_packet), "Mirror payload does not match received packet")
            else:
                testutils.verify_no_packet_any(ptfadapter, expected_mirror_packet, dest_ports)

    @staticmethod
    def get_expected_mirror_packet(mirror_session, setup, duthost, mirror_packet, check_ttl, router_mac=None):
        payload = mirror_packet.copy()
        if router_mac is None:
            router_mac = setup["router_mac"]

        # Add vendor specific padding to the packet
        if duthost.facts["asic_type"] in ["mellanox"]:
            payload = binascii.unhexlify("0" * 44) + str(payload)

        if duthost.facts["asic_type"] in ["barefoot", "cisco-8000", "innovium", "broadcom"]:
            payload = binascii.unhexlify("0" * 24) + str(payload)

        expected_packet = testutils.simple_gre_packet(
            eth_src=router_mac,
            ip_src=mirror_session["session_src_ip"],
            ip_dst=mirror_session["session_dst_ip"],
            ip_dscp=int(mirror_session["session_dscp"]),
            ip_id=0,
            ip_ttl=int(mirror_session["session_ttl"]),
            inner_frame=payload
        )

        expected_packet["GRE"].proto = mirror_session["session_gre"]

        expected_packet = Mask(expected_packet)
        expected_packet.set_do_not_care_scapy(packet.Ether, "dst")
        expected_packet.set_do_not_care_scapy(packet.IP, "ihl")
        expected_packet.set_do_not_care_scapy(packet.IP, "len")
        expected_packet.set_do_not_care_scapy(packet.IP, "flags")
        expected_packet.set_do_not_care_scapy(packet.IP, "chksum")
        if duthost.facts["asic_type"] in ["cisco-8000", "innovium", "broadcom"]:
            expected_packet.set_do_not_care_scapy(packet.GRE, "seqnum_present")
        if not check_ttl:
            expected_packet.set_do_not_care_scapy(packet.IP, "ttl")

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

    def _get_port_namespace(self, setup, port):
        return setup["port_index_namespace_map"][port]

    def _get_random_src_port(self, setup):
        return setup["port_index_map"][random.choice(setup["port_index_map"].keys())]

    def _get_monitor_port_string(self, setup, mirror_session, duthost):
        mirror_output = duthost.command("show mirror_session")

        pytest_assert(mirror_session["session_name"] in mirror_output["stdout"],
                      "Test mirror session {} not found".format(mirror_session["session_name"]))

        lines = mirror_output["stdout_lines"]

        if "201911" in duthost.os_version:
            # Because this line is not in the output in 201911, we need to add it so that the
            # parser is consistent between 201911 and future versions.
            lines = ["ERSPAN Sessions"] + lines

        sessions = self._parse_mirror_session_running_config(lines)

        session = [x for x in sessions["ERSPAN Sessions"]["data"] if x["Name"] == mirror_session["session_name"]]
        pytest_assert(0 < len(session))

        monitor_port = session[0]["Monitor Port"]
        return monitor_port, mirror_output

    def get_monitor_port_info(self, setup, mirror_session, duthost):
        """
        Get the current monitor port information from show mirror_session.

        Args:
            setup: Fixture with setup_info about the testbed setup
            mirror_session: setup_mirror_session fixture with info about the mirror session configured.
            duthost: DUT fixture to run show command on.

        Returns:
            dict with asic name as keys and monitor port as value.
        """
        monitor_port_str, mirror_out = self._get_monitor_port_string(setup, mirror_session, duthost)
        if monitor_port_str.startswith("{"):
            return json.loads(monitor_port_str.replace("'", "\""))
        else:
            return {'asic0': monitor_port_str}

    def _get_monitor_port(self, setup, mirror_session, duthost):
        monitor_port, mirror_output = self._get_monitor_port_string(setup, mirror_session, duthost)

        pytest_assert(monitor_port in setup["port_index_map"],
                      "Invalid monitor port:\n{}".format(mirror_output["stdout"]))
        logging.info("Selected monitor interface %s (port=%s)", monitor_port, setup["port_index_map"][monitor_port])

        return setup["port_index_map"][monitor_port]

    def _parse_mirror_session_running_config(self, lines):
        sessions = {}
        while True:
            session_group, lines = self._parse_mirror_session_group(lines)
            if session_group is None:
                break
            sessions[session_group["name"]] = session_group

        return sessions

    def _parse_mirror_session_group(self, lines):
        while len(lines) and lines[0].strip() == "":
            lines.pop(0)

        if len(lines) < 3:
            return None, lines

        table_name = lines[0]
        separator_line = lines[2]
        header = lines[1]

        session_group = {
            "name": table_name,
            "data": []
        }

        separators = separator_line.split()

        lines = lines[3:]
        for ln in lines[:]:
            lines.pop(0)
            if ln.strip() == "":
                break

            index = 0
            data = {}
            for s in separators:
                end = index + len(s)
                name = header[index:end].strip()
                value = ln[index:end].strip()
                index = index + len(s) + 2
                data[name] = value

            session_group["data"].append(data)

        return session_group, lines

    def _get_tx_port_id_list(self, tx_ports):
        tx_port_ids = []
        for port in tx_ports:
            members = port.split(',')
            for member in members:
                tx_port_ids.append(int(member))
        return tx_port_ids
