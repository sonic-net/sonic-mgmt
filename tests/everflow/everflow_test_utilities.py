"""Utilities for testing the Everflow feature in SONiC."""

import pytest
import ipaddr

from abc import abstractmethod


@pytest.fixture(scope="module")
def setup_info(duthost, testbed):
    """
    Gather all required test information.

    Args:
        duthost: DUT fixture
        testbed: testbed fixture

    Returns:
        dict: Required test information

    """
    # TODO: Support all T1 and T0 topos in these tests.
    if testbed["topo"]["name"] not in ("t1", "t1-lag", "t1-64-lag", "t1-64-lag-clet"):
        pytest.skip("Unsupported topology")

    tor_ports = []
    spine_ports = []
    # TODO: I don't think this is actually used anywhere but I'll save this for another PR.
    port_channels = []

    # Gather test facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    switch_capability_facts = duthost.switch_capabilities_facts()["ansible_facts"]
    host_facts = duthost.setup()["ansible_facts"]

    # Get the list of T0/T2 ports
    # TODO: The ACL tests do something really similar, I imagine we could refactor this bit.
    for dut_port, neigh in mg_facts["minigraph_neighbors"].items():
        if "T0" in neigh["name"]:
            tor_ports.append(dut_port)
        elif "T2" in neigh["name"]:
            spine_ports.append(dut_port)

    # Get the list of port channels
    port_channels = mg_facts["minigraph_portchannels"]

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
        ptf_port_id = ""
        out_port_exclude_list = []

        for port in in_port_list:
            if port not in out_port_list and port not in out_port_exclude_list and len(out_port_list) < 4:
                ptf_port_id += (str(mg_facts["minigraph_port_indices"][port]))
                out_port_list.append(port)
                out_port_lag_name.append("Not Applicable")

                for portchannelinfo in mg_facts["minigraph_portchannels"].items():
                    if port in portchannelinfo[1]["members"]:
                        out_port_lag_name[-1] = portchannelinfo[0]
                        for lag_member in portchannelinfo[1]["members"]:
                            if port == lag_member:
                                continue
                            ptf_port_id += "," + (str(mg_facts["minigraph_port_indices"][lag_member]))
                            out_port_exclude_list.append(lag_member)

                out_port_ptf_id_list.append(ptf_port_id)
                ptf_port_id = ""

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
        "router_mac": host_facts["ansible_Ethernet0"]["macaddress"],
        "tor_ports": tor_ports,
        "spine_ports": spine_ports,
        "port_channels": port_channels,
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
            "src_port_ptf_id": str(mg_facts["minigraph_port_indices"][spine_ports[0]]),
            "dest_port": tor_dest_ports,
            "dest_port_ptf_id": tor_dest_ports_ptf_id,
            "dest_port_lag_name": tor_dest_lag_name
        },
        "spine": {
            "src_port": tor_ports[0],
            "src_port_ptf_id": str(mg_facts["minigraph_port_indices"][tor_ports[0]]),
            "dest_port": spine_dest_ports,
            "dest_port_ptf_id": spine_dest_ports_ptf_id,
            "dest_port_lag_name": spine_dest_lag_name
        },
        "port_index_map": {
            k: v
            for k, v in mg_facts["minigraph_port_indices"].items()
            if k in mg_facts["minigraph_ports"]
        }
    }

    # NOTE: This is important to add since for the Policer test case regular packets
    # and mirror packets can go to same interface, which causes tail drop of
    # police packets and impacts test case cir/cbs calculation.
    #
    # We are making sure regular traffic has a dedicated route and does not use
    # the default route.

    peer_ip, _ = get_neighbor_info(duthost, spine_dest_ports[3])

    add_route(duthost, "30.0.0.1/24", peer_ip)

    yield setup_information

    remove_route(duthost, "30.0.0.1/24", peer_ip)


# TODO: This should be refactored to some common area of sonic-mgmt.
def add_route(duthost, prefix, nexthop):
    """
    Add a route to the DUT.

    Args:
        duthost: DUT fixture
        prefix: IP prefix for the route
        nexthop: next hop for the route

    """
    duthost.shell("vtysh -c \"configure terminal\" -c \"ip route {} {}\"".format(prefix, nexthop))


# TODO: This should be refactored to some common area of sonic-mgmt.
def remove_route(duthost, prefix, nexthop):
    """
    Remove a route from the DUT.

    Args:
        duthost: DUT fixture
        prefix: IP prefix to remove
        nexthop: next hop to remove

    """
    duthost.shell("vtysh -c \"configure terminal\" -c \"no ip route {} {}\"".format(prefix, nexthop))


# TODO: This should be refactored to some common area of sonic-mgmt.
def get_neighbor_info(duthost, dest_port, resolved=True):
    """
    Get the IP and MAC of the neighbor on the specified destination port.

    Args:
        duthost: DUT fixture
        dest_port: The port for which to gather the neighbor information
        resolved: Whether to return a resolved route or not

    """
    if not resolved:
        return "20.20.20.100", None

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]

    for bgp_peer in mg_facts["minigraph_bgp"]:
        if bgp_peer["name"] == mg_facts["minigraph_neighbors"][dest_port]["name"] and ipaddr.IPAddress(bgp_peer["addr"]).version == 4:
            peer_ip = bgp_peer["addr"]
            break

    return peer_ip, duthost.shell("ip neigh show {} | awk -F\" \" \"{{print $5}}\"".format(peer_ip))["stdout"]


class BaseEverflowTest(object):
    """
    Base class for setting up a set of Everflow tests.

    Contains common methods for setting up the mirror session and describing the
    mirror and ACL stage for the tests.
    """

    @pytest.fixture(scope="class")
    def setup_mirror_session(self, duthost):
        """
        Set up a mirror session for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.

        """
        session_info = self._mirror_session_info("test_session_1", duthost.facts["asic_type"])

        duthost.command("config mirror_session add {} {} {} {} {} {}"
                        .format(session_info["session_name"],
                                session_info["session_src_ip"],
                                session_info["session_dst_ip"],
                                session_info["session_dscp"],
                                session_info["session_ttl"],
                                session_info["session_gre"]))

        yield session_info

        duthost.command("config mirror_session remove {}".format(session_info["session_name"]))

    @pytest.fixture(scope="class")
    def policer_mirror_session(self, duthost):
        """
        Set up a mirror session with a policer for Everflow.

        Args:
            duthost: DUT fixture

        Yields:
            dict: Information about the mirror session configuration.

        """

        # Create a policer that allows 100 packets/sec through
        duthost.command("redis-cli -n 4 hmset \"POLICER|TEST_POLICER\" meter_type packets \
                         mode sr_tcm cir 100 cbs 100 red_packet_action drop")

        # Create a mirror session with the TEST_POLICER attached
        session_info = self._mirror_session_info("TEST_POLICER_SESSION", duthost.facts["asic_type"])
        duthost.command("config mirror_session add {} {} {} {} {} {} --policer TEST_POLICER"
                        .format(session_info["session_name"],
                                session_info["session_src_ip"],
                                session_info["session_dst_ip"],
                                session_info["session_dscp"],
                                session_info["session_ttl"],
                                session_info["session_gre"]))

        yield session_info

        # Clean up mirror session and policer
        duthost.command("config mirror_session remove {}".format(session_info["session_name"]))
        duthost.command("redis-cli -n 4 del \"POLICER|TEST_POLICER\"")

    @abstractmethod
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        """
        Configure the ACL table for this set of test cases.

        Args:
            duthost: DUT fixture
            setup_info: Fixture with info about the testbed setup
            setup_mirror_session: Fixtue with info about the mirror session

        """
        pass

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

    def _mirror_session_info(self, session_name, asic_type):
        session_src_ip = "1.1.1.1"
        session_dst_ip = "2.2.2.2"
        session_dscp = "8"
        session_ttl = "1"

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
