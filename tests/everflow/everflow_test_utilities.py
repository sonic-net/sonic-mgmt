"""Utilities for testing the Everflow feature in SONiC."""
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

@pytest.fixture(scope="module")
def setup_info(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Gather all required test information.

    Args:
        duthost: DUT fixture
        tbinfo: tbinfo fixture

    Returns:
        dict: Required test information

    """
    duthost = duthosts[rand_one_dut_hostname]

    # { namespace : [tor ports] }
    tor_ports_namespace_map = defaultdict(list)
    # { namespace : [spine ports] }
    spine_ports_namespace_map = defaultdict(list)

    # { set of namespace tor ports belongs }
    tor_ports_namespace = set()
    # { set of namespace spine ports belongs }
    spine_ports_namespace = set()


    # Gather test facts
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    switch_capability_facts = duthost.switch_capabilities_facts()["ansible_facts"]

    # Get the list of T0/T2 ports
    # TODO: The ACL tests do something really similar, I imagine we could refactor this bit.
    for dut_port, neigh in mg_facts["minigraph_neighbors"].items():
        if "T0" in neigh["name"]:
            # Add Tor ports to namespace
            tor_ports_namespace_map[neigh['namespace']].append(dut_port)
            tor_ports_namespace.add(neigh['namespace'])
        elif "T2" in neigh["name"]:
            # Add Spine ports to namespace
            spine_ports_namespace_map[neigh['namespace']].append(dut_port)
            spine_ports_namespace.add(neigh['namespace'])

    # Set of TOR ports only Namespace 
    tor_only_namespace = tor_ports_namespace.difference(spine_ports_namespace)
    # Set of Spine ports only Namespace 
    spine_only_namespace = spine_ports_namespace.difference(tor_ports_namespace)
 
    # Randomly choose from TOR_only Namespace if present else just use first one 
    tor_namespace = random.choice(tuple(tor_only_namespace)) if tor_only_namespace else tuple(tor_ports_namespace)[0]
    # Randomly choose from Spine_only Namespace if present else just use first one 
    spine_namespace = random.choice(tuple(spine_only_namespace)) if spine_only_namespace else tuple(spine_ports_namespace)[0]

    # Get the corresponding namespace ports
    tor_ports = tor_ports_namespace_map[tor_namespace]
    spine_ports = spine_ports_namespace_map[spine_namespace]
         

    switch_capabilities = switch_capability_facts["switch_capabilities"]["switch"]

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
    else:
        test_ingress_mirror_on_ingress_acl = "MIRROR_INGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|INGRESS"]
        test_ingress_mirror_on_egress_acl = "MIRROR_INGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|EGRESS"]
        test_egress_mirror_on_egress_acl = "MIRROR_EGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|EGRESS"]
        test_egress_mirror_on_ingress_acl = "MIRROR_EGRESS_ACTION" in switch_capabilities["ACL_ACTIONS|INGRESS"]

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
                out_port_lag_name.append("Not Applicable")

                for portchannelinfo in mg_facts["minigraph_portchannels"].items():
                    if port in portchannelinfo[1]["members"]:
                        out_port_lag_name[-1] = portchannelinfo[0]
                        for lag_member in portchannelinfo[1]["members"]:
                            if port == lag_member:
                                continue
                            ptf_port_id += "," + (str(mg_facts["minigraph_ptf_indices"][lag_member]))
                            out_port_exclude_list.append(lag_member)

                out_port_ptf_id_list.append(ptf_port_id)

    tor_dest_ports = []
    tor_dest_ports_ptf_id = []
    tor_dest_lag_name = []
    get_port_info(tor_ports, tor_dest_ports, tor_dest_ports_ptf_id, tor_dest_lag_name)

    spine_dest_ports = []
    spine_dest_ports_ptf_id = []
    spine_dest_lag_name = []
    get_port_info(spine_ports, spine_dest_ports, spine_dest_ports_ptf_id, spine_dest_lag_name)

    # TODO: Some of this can probably be tailored to the specific set of test cases (e.g.
    # we don't need spine v. tor info to check match types).
    #
    # Also given how much info is here it probably makes sense to make a data object/named
    # tuple to help with the typing.
    setup_information = {
        "router_mac": duthost.facts["router_mac"],
        "tor_ports": tor_ports,
        "spine_ports": spine_ports,
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
        "tor": {
            "src_port": spine_ports[0],
            "src_port_ptf_id": str(mg_facts["minigraph_ptf_indices"][spine_ports[0]]),
            "dest_port": tor_dest_ports,
            "dest_port_ptf_id": tor_dest_ports_ptf_id,
            "dest_port_lag_name": tor_dest_lag_name,
            "namespace": tor_namespace
        },
        "spine": {
            "src_port": tor_ports[0],
            "src_port_ptf_id": str(mg_facts["minigraph_ptf_indices"][tor_ports[0]]),
            "dest_port": spine_dest_ports,
            "dest_port_ptf_id": spine_dest_ports_ptf_id,
            "dest_port_lag_name": spine_dest_lag_name,
            "namespace": spine_namespace
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

    # Disable BGP so that we don't keep on bouncing back mirror packets
    # If we send TTL=1 packet we don't need this but in multi-asic TTL > 1
    duthost.command("sudo config bgp shutdown all")
    time.sleep(60)
    duthost.command("mkdir -p {}".format(DUT_RUN_DIR))
    
    yield setup_information
    
    # Enable BGP again 
    duthost.command("sudo config bgp startup all")
    time.sleep(60)
    duthost.command("rm -rf {}".format(DUT_RUN_DIR))
 

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
        if bgp_peer["name"] == mg_facts["minigraph_neighbors"][dest_port]["name"] and ipaddr.IPAddress(bgp_peer["addr"]).version == 4:
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

    OUTER_HEADER_SIZE = 38

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
    def setup_mirror_session(self, duthosts, rand_one_dut_hostname, config_method):
        """
        Set up a mirror session for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.
        """
        duthost = duthosts[rand_one_dut_hostname]
        session_info = self._mirror_session_info("test_session_1", duthost.facts["asic_type"])

        self.apply_mirror_config(duthost, session_info, config_method)

        yield session_info

        self.remove_mirror_config(duthost, session_info["session_name"], config_method)

    @pytest.fixture(scope="class")
    def policer_mirror_session(self, duthosts, rand_one_dut_hostname, config_method):
        """
        Set up a mirror session with a policer for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.
        """
        duthost = duthosts[rand_one_dut_hostname]
        policer = "TEST_POLICER"

        # Create a policer that allows 100 packets/sec through
        self.apply_policer_config(duthost, policer, config_method)

        # Create a mirror session with the TEST_POLICER attached
        session_info = self._mirror_session_info("TEST_POLICER_SESSION", duthost.facts["asic_type"])
        self.apply_mirror_config(duthost, session_info, config_method, policer=policer)

        yield session_info

        # Clean up mirror session and policer
        self.remove_mirror_config(duthost, session_info["session_name"], config_method)
        self.remove_policer_config(duthost, policer, config_method)

    def apply_mirror_config(self, duthost, session_info, config_method, policer=None):
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

    def remove_mirror_config(self, duthost, session_name, config_method):
        if config_method == CONFIG_MODE_CLI:
            command = "config mirror_session remove {}".format(session_name)
        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

    def apply_policer_config(self, duthost, policer_name, config_method, rate_limit=100):
        if config_method == CONFIG_MODE_CLI:
            command = ("redis-cli -n 4 hmset \"POLICER|{}\" "
                       "meter_type packets mode sr_tcm cir {} cbs {} "
                       "red_packet_action drop").format(policer_name, rate_limit, rate_limit)
        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

    def remove_policer_config(self, duthost, policer_name, config_method):
        if config_method == CONFIG_MODE_CLI:
            command = "redis-cli -n 4 del \"POLICER|{}\"".format(policer_name)
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
        duthost = duthosts[rand_one_dut_hostname]
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("{} ACL w/ {} Mirroring not supported, skipping"
                        .format(self.acl_stage(), self.mirror_type()))

        table_name = "EVERFLOW" if self.acl_stage() == "ingress" else "EVERFLOW_EGRESS"

        # NOTE: We currently assume that the ingress MIRROR tables already exist.
        if self.acl_stage() == "egress":
            self.apply_acl_table_config(duthost, table_name, "MIRROR", config_method)

        self.apply_acl_rule_config(duthost, table_name, setup_mirror_session["session_name"], config_method)

        yield

        self.remove_acl_rule_config(duthost, table_name, config_method)

        if self.acl_stage() == "egress":
            self.remove_acl_table_config(duthost, "EVERFLOW_EGRESS", config_method)

    def apply_acl_table_config(self, duthost, table_name, table_type, config_method):
        if config_method == CONFIG_MODE_CLI:
            command = "config acl add table {} {}".format(table_name, table_type)

            # NOTE: Until the repo branches, we're only applying the flag
            # on egress tables to preserve backwards compatibility.
            if self.acl_stage() == "egress":
                command += " --stage {}".format(self.acl_stage())

        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

    def remove_acl_table_config(self, duthost, table_name, config_method):
        if config_method == CONFIG_MODE_CLI:
            command = "config acl remove table {}".format(table_name)
        elif config_method == CONFIG_MODE_CONFIGLET:
            pass

        duthost.command(command)

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

    def remove_acl_rule_config(self, duthost, table_name, config_method):
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
                                      valid_across_namespace=True):
        expected_mirror_packet = self._get_expected_mirror_packet(mirror_session,
                                                                  setup,
                                                                  duthost,
                                                                  mirror_packet)

        if not src_port:
            src_port = self._get_random_src_port(setup)

        if not dest_ports:
            dest_ports = [self._get_monitor_port(setup, mirror_session, duthost)]

        # In Below logic idea is to send traffic in such a way so that mirror traffic
        # will need to go across namespaces and within namespace. If source and mirror destination
        # namespace are different then traffic mirror will go across namespace via (backend asic)
        # else via same namespace(asic)

        src_port_namespace = self._get_port_namespace(setup, int(src_port))
        dest_ports_namespace = self._get_port_namespace(setup,int (dest_ports[0]))

        src_port_set =  set()
        
        # Some of test scenario are not valid across namespaces so test will explicltly pass 
        # valid_across_namespace as False (default is True)
        if valid_across_namespace == True or src_port_namespace == dest_ports_namespace:
            src_port_set.add(src_port)
        
        # To verify same namespace mirroring we will add destination port also to the Source Port Set
        if src_port_namespace != dest_ports_namespace:
            src_port_set.add(dest_ports[0])

        # Loop through Source Port Set and send traffic on each source port of the set
        for src_port in src_port_set:
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
                    mirror_packet[packet.IP].ttl -= 1
                    mirror_packet[packet.Ether].src = setup["router_mac"]

                    inner_packet.set_do_not_care_scapy(packet.Ether, "dst")
                    inner_packet.set_do_not_care_scapy(packet.IP, "chksum")

                logging.info("Expected inner packet: %s", mirror_packet.summary())
                pytest_assert(inner_packet.pkt_match(mirror_packet), "Mirror payload does not match received packet")
            else:
                testutils.verify_no_packet_any(ptfadapter, expected_mirror_packet, dest_ports)

    def _get_expected_mirror_packet(self, mirror_session, setup, duthost, mirror_packet):
        payload = mirror_packet.copy()

        # Add vendor specific padding to the packet
        if duthost.facts["asic_type"] in ["mellanox"]:
            payload = binascii.unhexlify("0" * 44) + str(payload)

        if duthost.facts["asic_type"] in ["barefoot"]:
            payload = binascii.unhexlify("0" * 24) + str(payload)

        expected_packet = testutils.simple_gre_packet(
            eth_src=setup["router_mac"],
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
        expected_packet.set_do_not_care_scapy(packet.IP, "ttl")

        # The fanout switch may modify this value en route to the PTF so we should ignore it, even
        # though the session does have a DSCP specified.
        expected_packet.set_do_not_care_scapy(packet.IP, "tos")

        # Mask off the payload (we check it later)
        expected_packet.set_do_not_care(self.OUTER_HEADER_SIZE * 8, len(payload) * 8)

        return expected_packet

    def _extract_mirror_payload(self, encapsulated_packet, payload_size):
        pytest_assert(len(encapsulated_packet) >= self.OUTER_HEADER_SIZE,
                      "Incomplete packet, expected at least {} header bytes".format(self.OUTER_HEADER_SIZE))

        inner_frame = encapsulated_packet[-payload_size:]
        return packet.Ether(inner_frame)

    def _mirror_session_info(self, session_name, asic_type):
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
    
    def _get_port_namespace(self,setup, port):
        return setup["port_index_namespace_map"][port]

    def _get_random_src_port(self, setup):
        return setup["port_index_map"][random.choice(setup["port_index_map"].keys())]

    def _get_monitor_port(self, setup, mirror_session, duthost):
        mirror_output = duthost.command("show mirror_session")
        logging.info("Running mirror session configuration:\n%s", mirror_output["stdout"])

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
