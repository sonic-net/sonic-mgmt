import pytest
import time
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                             # noqa: F401
from tests.vxlan.test_vxlan_ecmp import Test_VxLAN, fixture_encap_type, _ignore_route_sync_errlogs  # noqa: F401
from tests.vxlan.test_vxlan_ecmp import fixture_setUp, _reset_test_routes, ecmp_utils               # noqa: F401
from tests.vxlan.test_vxlan_ecmp import default_routes, routes_for_cleanup                          # noqa: F401


Logger = logging.getLogger(__name__)

pytestmark = [
    # This script supports any T1 topology: t1, t1-64-lag, t1-56-lag, t1-lag.
    pytest.mark.topology("t1", "t1-64-lag", "t1-56-lag", "t1-lag")
]


class Test_VxLAN_underlay_ecmp(Test_VxLAN):
    '''
        Class for all test cases that modify the underlay default route.
    '''
    @pytest.mark.parametrize("ecmp_path_count", [1, 2])
    def test_vxlan_modify_underlay_default(self, setUp, minigraph_facts, encap_type, ecmp_path_count):
        '''
            tc12: modify the underlay default route nexthop/s. send packets to
            route 3's prefix dst.
        '''
        self.vxlan_test_setup = setUp
        '''
        First step: pick one or two of the interfaces connected to t2, and
        bring them down. verify that the encap is still working, and ptf
        receives the traffic.  Bring them back up.
        After that, bring down all the other t2 interfaces, other than
        the ones used in the first step. This will force a modification
        to the underlay default routes nexthops.
        '''

        all_t2_intfs = list(ecmp_utils.get_portchannels_to_neighbors(
            self.vxlan_test_setup['duthost'],
            "T2",
            minigraph_facts))

        if not all_t2_intfs:
            all_t2_intfs = ecmp_utils.get_ethernet_to_neighbors(
                "T2",
                minigraph_facts)
        Logger.info("Dumping T2 link info: %s", all_t2_intfs)
        if not all_t2_intfs:
            raise RuntimeError(
                "No interface found connected to t2 neighbors. "
                "pls check the testbed, aborting.")

        # Keep a copy of the internal housekeeping list of t2 ports.
        # This is the full list of DUT ports connected to T2 neighbors.
        # It is one of the arguments to the ptf code.
        all_t2_ports = list(self.vxlan_test_setup[encap_type]['t2_ports'])

        # A distinction in this script between ports and interfaces:
        # Ports are physical (Ethernet) only.
        # Interfaces have IP address(Ethernet or PortChannel).
        try:
            selected_intfs = []
            # Choose some intfs based on the parameter ecmp_path_count.
            # when ecmp_path_count == 1, it is non-ecmp. The switching
            # happens between ecmp and non-ecmp. Otherwise, the switching
            # happens within ecmp only.
            for i in range(ecmp_path_count):
                selected_intfs.append(all_t2_intfs[i])

            for intf in selected_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))
            downed_ports = ecmp_utils.get_corresponding_ports(
                selected_intfs,
                minigraph_facts)
            self.vxlan_test_setup[encap_type]['t2_ports'] = \
                list(set(all_t2_ports) - set(downed_ports))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(
                selected_intfs, minigraph_facts)
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost'],
                    down_list=downed_bgp_neighbors),
                "BGP neighbors didn't come up after all "
                "interfaces have been brought up.")
            time.sleep(10)
            self.dump_self_info_and_run_ptf(
                "tc12",
                encap_type,
                True,
                packet_count=10000,
                check_underlay_ecmp=True)

            Logger.info(
                "Reverse the action: bring up the selected_intfs"
                " and shutdown others.")
            for intf in selected_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            Logger.info("Shutdown other interfaces.")
            remaining_interfaces = list(
                set(all_t2_intfs) - set(selected_intfs))
            for intf in remaining_interfaces:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(
                remaining_interfaces,
                minigraph_facts)
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost'],
                    down_list=downed_bgp_neighbors),
                "BGP neighbors didn't come up after all interfaces have been"
                "brought up.")
            self.vxlan_test_setup[encap_type]['t2_ports'] = \
                ecmp_utils.get_corresponding_ports(
                    selected_intfs,
                    minigraph_facts)

            '''
            Need to update the bfd_responder to listen only on the sub-set of
            T2 ports that are active. If we still receive packets on the
            downed ports, we have a problem!
            '''
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf(
                "tc12",
                encap_type,
                True,
                packet_count=10000,
                check_underlay_ecmp=True)

            Logger.info("Recovery. Bring all up, and verify traffic works.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            Logger.info("Wait for all bgp is up.")
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after "
                "all interfaces have been brought up.")
            Logger.info("Verify traffic flows after recovery.")
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf(
                "tc12",
                encap_type,
                True,
                packet_count=10000,
                check_underlay_ecmp=True)

        except Exception:
            # If anything goes wrong in the try block, atleast bring the intf
            # back up.
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after all interfaces "
                "have been brought up.")
            raise

    def test_vxlan_remove_add_underlay_default(self,
                                               setUp,
                                               minigraph_facts,
                                               encap_type):
        '''
           tc13: remove the underlay default route.
           tc14: add the underlay default route.
        '''
        self.vxlan_test_setup = setUp
        Logger.info(
            "Find all the underlay default routes' interfaces. This means all "
            "T2 interfaces.")
        all_t2_intfs = list(ecmp_utils.get_portchannels_to_neighbors(
            self.vxlan_test_setup['duthost'],
            "T2",
            minigraph_facts))
        if not all_t2_intfs:
            all_t2_intfs = ecmp_utils.get_ethernet_to_neighbors(
                "T2",
                minigraph_facts)
        Logger.info("Dumping T2 link info: %s", all_t2_intfs)
        if not all_t2_intfs:
            raise RuntimeError(
                "No interface found connected to t2 neighbors."
                "Pls check the testbed, aborting.")
        try:
            Logger.info("Bring down the T2 interfaces.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(
                all_t2_intfs,
                minigraph_facts)
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost'],
                    down_list=downed_bgp_neighbors),
                "BGP neighbors have not reached the required state after "
                "T2 intf are shutdown.")
            Logger.info("Verify that traffic is not flowing through.")
            self.dump_self_info_and_run_ptf("tc13", encap_type, False, check_underlay_ecmp=True)

            # tc14: Re-add the underlay default route.
            Logger.info("Bring up the T2 interfaces.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            Logger.info("Wait for all bgp is up.")
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after all interfaces"
                " have been brought up.")
            Logger.info("Verify the traffic is flowing through, again.")
            self.dump_self_info_and_run_ptf(
                "tc14",
                encap_type,
                True,
                packet_count=10000,
                check_underlay_ecmp=True)
        except Exception:
            Logger.info(
                "If anything goes wrong in the try block,"
                " atleast bring the intf back up.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after all"
                " interfaces have been brought up.")
            raise

    def test_underlay_specific_route(self, setUp, minigraph_facts, encap_type):
        '''
            Create a more specific underlay route to c1.
            Verify c1 packets are received only on the c1's nexthop interface
        '''
        self.vxlan_test_setup = setUp
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        endpoint_nhmap = self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet]
        backup_t2_ports = self.vxlan_test_setup[encap_type]['t2_ports']
        # Gathering all T2 Neighbors
        all_t2_neighbors = ecmp_utils.get_all_bgp_neighbors(
            minigraph_facts,
            "T2")

        # Choosing a specific T2 Neighbor to add static route
        t2_neighbor = list(all_t2_neighbors.keys())[0]

        # Gathering PTF indices corresponding to specific T2 Neighbor
        ret_list = ecmp_utils.gather_ptf_indices_t2_neighbor(
            minigraph_facts,
            all_t2_neighbors,
            t2_neighbor,
            encap_type)
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
        '''
            Addition & Modification of static routes - endpoint_nhmap will be
            prefix to endpoint mapping. Static routes are added towards
            endpoint with T2 VM's ip as nexthop
        '''
        gateway = all_t2_neighbors[t2_neighbor][outer_layer_version].lower()
        for _, nexthops in list(endpoint_nhmap.items()):
            for nexthop in nexthops:
                if outer_layer_version == "v6":
                    vtysh_config_commands = []
                    vtysh_config_commands.append("ipv6 route {}/{} {}".format(
                        nexthop,
                        "64",
                        gateway))
                    vtysh_config_commands.append("ipv6 route {}/{} {}".format(
                        nexthop,
                        "68",
                        gateway))
                    self.vxlan_test_setup['duthost'].copy(
                        content="\n".join(vtysh_config_commands),
                        dest="/tmp/specific_route_v6.txt")
                    self.vxlan_test_setup['duthost'].command(
                        "docker cp /tmp/specific_route_v6.txt bgp:/")
                    self.vxlan_test_setup['duthost'].command(
                        "vtysh -f /specific_route_v6.txt")
                elif outer_layer_version == "v4":
                    static_route = []
                    static_route.append(
                        "sudo config route add prefix {}/{} nexthop {}".format(
                            ".".join(nexthop.split(".")[:-1])+".0", "24",
                            gateway))
                    static_route.append(
                        "sudo config route add prefix {}/{} nexthop {}".format(
                            nexthop,
                            ecmp_utils.HOST_MASK[outer_layer_version],
                            gateway))

                    self.vxlan_test_setup['duthost'].shell_cmds(cmds=static_route)
        self.vxlan_test_setup[encap_type]['t2_ports'] = ret_list

        '''
            Traffic verification to see if specific route is preferred before
            deletion of static route
        '''
        self.dump_self_info_and_run_ptf(
            "underlay_specific_route",
            encap_type,
            True,
            check_underlay_ecmp=True)
        # Deletion of all static routes
        gateway = all_t2_neighbors[t2_neighbor][outer_layer_version].lower()
        for _, nexthops in list(endpoint_nhmap.items()):
            for nexthop in nexthops:
                if ecmp_utils.get_outer_layer_version(encap_type) == "v6":
                    vtysh_config_commands = []
                    vtysh_config_commands.append(
                        "no ipv6 route {}/{} {}".format(
                            nexthop, "64", gateway))
                    vtysh_config_commands.append(
                        "no ipv6 route {}/{} {}".format(
                            nexthop, "68", gateway))
                    self.vxlan_test_setup['duthost'].copy(
                        content="\n".join(vtysh_config_commands),
                        dest="/tmp/specific_route_v6.txt")
                    self.vxlan_test_setup['duthost'].command(
                        "docker cp /tmp/specific_route_v6.txt bgp:/")
                    self.vxlan_test_setup['duthost'].command(
                        "vtysh -f /specific_route_v6.txt")

                elif ecmp_utils.get_outer_layer_version(encap_type) == "v4":
                    static_route = []
                    static_route.append(
                        "sudo config route del prefix {}/{} nexthop {}".format(
                            ".".join(
                                nexthop.split(".")[:-1])+".0", "24", gateway))
                    static_route.append(
                        "sudo config route del prefix {}/{} nexthop {}".format(
                            nexthop,
                            ecmp_utils.HOST_MASK[outer_layer_version],
                            gateway))

                    self.vxlan_test_setup['duthost'].shell_cmds(cmds=static_route)
        self.vxlan_test_setup[encap_type]['t2_ports'] = backup_t2_ports

        Logger.info(
            "Allow some time for recovery of default route"
            " after deleting the specific route.")
        time.sleep(10)

        '''
        Traffic verification to see if default route is preferred after
        deletion of static route
        '''
        self.dump_self_info_and_run_ptf(
            "underlay_specific_route",
            encap_type,
            True,
            check_underlay_ecmp=True)

    def test_underlay_portchannel_shutdown(self,
                                           setUp,
                                           minigraph_facts,
                                           encap_type):
        '''
            Bring down one of the port-channels.
            Packets are equally recieved at c1, c2 or c3
        '''
        self.vxlan_test_setup = setUp

        # Verification of traffic before shutting down port channel
        self.dump_self_info_and_run_ptf("tc12", encap_type, True, check_underlay_ecmp=True)

        # Gathering all portchannels
        all_t2_portchannel_intfs = \
            list(ecmp_utils.get_portchannels_to_neighbors(
                self.vxlan_test_setup['duthost'],
                "T2",
                minigraph_facts))
        all_t2_portchannel_members = {}
        for each_pc in all_t2_portchannel_intfs:
            all_t2_portchannel_members[each_pc] =\
                minigraph_facts['minigraph_portchannels'][each_pc]['members']

        selected_portchannel = list(all_t2_portchannel_members.keys())[0]

        try:
            # Shutting down the ethernet interfaces
            for intf in all_t2_portchannel_members[selected_portchannel]:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))

            all_t2_ports = list(self.vxlan_test_setup[encap_type]['t2_ports'])
            downed_ports = ecmp_utils.get_corresponding_ports(
                all_t2_portchannel_members[selected_portchannel],
                minigraph_facts)
            self.vxlan_test_setup[encap_type]['t2_ports'] = \
                list(set(all_t2_ports) - set(downed_ports))

            # Verification of traffic
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, check_underlay_ecmp=True)

            for intf in all_t2_portchannel_members[selected_portchannel]:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, check_underlay_ecmp=True)
        except BaseException:
            for intf in all_t2_portchannel_members[selected_portchannel]:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            raise
