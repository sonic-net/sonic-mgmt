"""Test cases to support the Everflow Mirroring feature in SONiC."""
import logging
import time
import pytest

import ptf.testutils as testutils
import everflow_test_utilities as everflow_utils

from tests.ptf_runner import ptf_runner
from everflow_test_utilities import TARGET_SERVER_IP, BaseEverflowTest, DOWN_STREAM, UP_STREAM, DEFAULT_SERVER_IP, get_intf_namespace
# Module-level fixtures
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from tests.common.fixtures.ptfhost_utils import copy_acstests_directory   # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from everflow_test_utilities import setup_info, setup_arp_responder, EVERFLOW_DSCP_RULES       # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py  # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("t0", "t1", "t2")
]


MEGABYTE = 1024 * 1024
DEFAULT_PTF_SOCKET_RCV_SIZE = 1 * MEGABYTE
DEFAULT_PTF_QLEN = 15000


@pytest.fixture
def partial_ptf_runner(request, duthosts, rand_one_dut_hostname, ptfhost):
    """
    Fixture to run each Everflow PTF test case via ptf_runner.

    Takes all the necessary arguments to run the test case and returns a handle to the caller
    to execute the ptf_runner.
    """
    duthost = duthosts[rand_one_dut_hostname]
    def _partial_ptf_runner(setup_info, session_info, acl_stage, mirror_type,  expect_receive = True, test_name = None, **kwargs):
        # Some of the arguments are fixed for each Everflow test case and defined here.
        # Arguments specific to each Everflow test case are passed in by each test via _partial_ptf_runner.
        # Arguments are passed in dictionary format via kwargs within each test case.
        params = {
                  'hwsku' :  duthost.facts['hwsku'],
                  'asic_type' :  duthost.facts['asic_type'],
                  'router_mac': setup_info['router_mac'],
                  'session_src_ip' : session_info['session_src_ip'],
                  'session_dst_ip' : session_info['session_dst_ip'],
                  'session_ttl' : session_info['session_ttl'],
                  'session_dscp' : session_info['session_dscp'],
                  'acl_stage' : acl_stage,
                  'mirror_stage' : mirror_type,
                  'expect_received' : expect_receive,
                  'check_ttl' : 'True' if not duthost.is_multi_asic else 'False' }
        params.update(kwargs)

        ptf_runner(host=ptfhost,
                   testdir="acstests",
                   platform_dir="ptftests",
                   testname="everflow_tb_test.EverflowTest" if not test_name else test_name,
                   params=params,
                   socket_recv_size=DEFAULT_PTF_SOCKET_RCV_SIZE,
                   qlen=DEFAULT_PTF_QLEN,
                   log_file="/tmp/{}.{}.log".format(request.cls.__name__, request.function.__name__))

    return _partial_ptf_runner


class EverflowIPv4Tests(BaseEverflowTest):
    """Base class for testing the Everflow feature w/ IPv4."""

    DEFAULT_SRC_IP = "20.0.0.1"
    DEFAULT_DST_IP = "30.0.0.1"
    MIRROR_POLICER_UNSUPPORTED_ASIC_LIST = ["th3", "j2c+"]

    @pytest.fixture(params=[DOWN_STREAM, UP_STREAM])
    def dest_port_type(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session, tbinfo, request):
        """
        This fixture parametrize  dest_port_type and can perform action based
        on that. As of now cleanup is being done here.
        """
        if setup_info['topo'] == 't2':
            duthost = setup_info[request.param]['everflow_dut']
            remote_dut = setup_info[request.param]['remote_dut']
        else:
            duthost = duthosts[rand_one_dut_hostname]
            remote_dut = duthost

        if setup_info['topo'] == 't2':
            for ns in remote_dut.get_asic_namespace_list():
                remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"redistribute static\"", ns))
            for ns in duthost.get_asic_namespace_list():
                duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"redistribute static\"", ns))
        else:
            remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"redistribute static\"",
                                                                    setup_info[request.param]["namespace"]))
        yield request.param

        for index in range(0, min(3, len(setup_info[request.param]["dest_port"]))):
            tx_port = setup_info[request.param]["dest_port"][index]
            peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
            everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, request.param, tx_port))
            everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][1], peer_ip, get_intf_namespace(setup_info, request.param, tx_port))

        if setup_info['topo'] == 't2':
            for ns in duthost.get_asic_namespace_list():
                duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"no redistribute static\"", ns))
            for ns in remote_dut.get_asic_namespace_list():
                remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"no redistribute static\"", ns))
        else:
            remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"no redistribute static\"",
                                                                    setup_info[request.param]["namespace"]))
        time.sleep(15)

    @pytest.fixture(autouse=True)
    def add_dest_routes(self, duthosts, rand_one_dut_hostname, setup_info, tbinfo, dest_port_type):
        if self.acl_stage() != 'egress':
            yield
            return

        default_traffic_port_type = DOWN_STREAM if dest_port_type == UP_STREAM else UP_STREAM

        if setup_info['topo'] == 't2':
            duthost = setup_info[default_traffic_port_type]['remote_dut']
            rx_port = setup_info[default_traffic_port_type]["dest_port"][0]
        else:
            duthost = duthosts[rand_one_dut_hostname]
            rx_port = setup_info[default_traffic_port_type]["dest_port"][0]

        nexthop_ip = everflow_utils.get_neighbor_info(duthost, rx_port, tbinfo)

        ns = get_intf_namespace(setup_info, default_traffic_port_type, rx_port)
        dst_mask = "30.0.0.0/28"
        everflow_utils.add_route(duthost, dst_mask, nexthop_ip, ns)
        if setup_info['topo'] == 't2':
            duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"redistribute static\"", ns))

        yield

        everflow_utils.remove_route(duthost, dst_mask, nexthop_ip, ns)
        if setup_info['topo'] == 't2':
            duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"no redistribute static\"", ns))

    def test_everflow_basic_forwarding(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session,
                                       dest_port_type, ptfadapter, tbinfo):
        """
        Verify basic forwarding scenarios for the Everflow feature.

        Scenarios covered include:
            - Resolved route
            - Unresolved route
            - LPM (longest prefix match)
            - Route creation and removal
        """
        if setup_info['topo'] == 't2':
            everflow_dut = setup_info[dest_port_type]['everflow_dut']
            remote_dut = setup_info[dest_port_type]['remote_dut']
        else:
            everflow_dut = duthosts[rand_one_dut_hostname]
            remote_dut = everflow_dut
        everflow_dut.shell(everflow_dut.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"no ip nht resolve-via-default\"", get_intf_namespace(setup_info, dest_port_type, setup_info[dest_port_type]['src_port'])))

        # Add a route to the mirror session destination IP
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))

        time.sleep(15)

        # Verify that mirrored traffic is sent along the route we installed
        rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        # Add a (better) unresolved route to the mirror session destination IP
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo, resolved=False)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][1], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        # Verify that mirrored traffic is still sent along the original route
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        # Remove the unresolved route
        everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][1], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))

        # Add a better route to the mirror session destination IP
        tx_port = setup_info[dest_port_type]["dest_port"][1]
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session['session_prefixes'][1], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        # Verify that mirrored traffic uses the new route
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][1]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        # Remove the better route.
        everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][1], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        # Verify that mirrored traffic switches back to the original route
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        everflow_dut.shell(everflow_dut.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"ip nht resolve-via-default\"", get_intf_namespace(setup_info, dest_port_type, setup_info[dest_port_type]['src_port'])))

    def test_everflow_neighbor_mac_change(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session, dest_port_type, ptfadapter, tbinfo):
        """Verify that session destination MAC address is changed after neighbor MAC address update."""
        if setup_info['topo'] == 't2':
            everflow_dut = setup_info[dest_port_type]['everflow_dut']
            remote_dut = setup_info[dest_port_type]['remote_dut']
        else:
            everflow_dut = duthosts[rand_one_dut_hostname]
            remote_dut = everflow_dut

        # Add a route to the mirror session destination IP
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        # Verify that mirrored traffic is sent along the route we installed
        rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        # Update the MAC on the neighbor interface for the route we installed
        if setup_info[dest_port_type]["dest_port_lag_name"][0] != "Not Applicable":
            tx_port = setup_info[dest_port_type]["dest_port_lag_name"][0]
        tx_ns = get_intf_namespace(setup_info, dest_port_type, setup_info[dest_port_type]["dest_port"][0])

        remote_dut.shell(remote_dut.get_linux_ip_cmd_for_namespace("ip neigh replace {} lladdr 00:11:22:33:44:55 nud permanent dev {}".format(peer_ip, tx_port), tx_ns))
        time.sleep(15)
        try:
            # Verify that everything still works
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                everflow_dut,
                rx_port_ptf_id,
                [tx_port_ptf_id],
                dest_port_type,
                mirror_dst_mac="00:11:22:33:44:55"
            )

        finally:
            # Clean up the test
            remote_dut.shell(remote_dut.get_linux_ip_cmd_for_namespace("ip neigh del {} dev {}".format(peer_ip, tx_port), tx_ns))
            remote_dut.get_asic_or_sonic_host_from_namespace(tx_ns).command("ping {} -c3".format(peer_ip))

        # Verify that everything still works
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

    def test_everflow_remove_unused_ecmp_next_hop(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session, dest_port_type, ptfadapter, tbinfo):
        """Verify that session is still active after removal of next hop from ECMP route that was not in use."""
        if setup_info['topo'] == 't2':
            everflow_dut = setup_info[dest_port_type]['everflow_dut']
            remote_dut = setup_info[dest_port_type]['remote_dut']
        else:
            everflow_dut = duthosts[rand_one_dut_hostname]
            remote_dut = everflow_dut
        # Create two ECMP next hops
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip_0 = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip_0, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        tx_port = setup_info[dest_port_type]["dest_port"][1]
        peer_ip_1 = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip_1, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        # Verify that mirrored traffic is sent to one of the next hops
        rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
        tx_port_ptf_ids = [
            setup_info[dest_port_type]["dest_port_ptf_id"][0],
            setup_info[dest_port_type]["dest_port_ptf_id"][1]
        ]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            tx_port_ptf_ids,
            dest_port_type
        )

        # Remaining Scenario not applicable for this topology
        if len(setup_info[dest_port_type]["dest_port"]) <= 2:
            return
        if setup_info['topo'] == "t2":
            # Further route add will not work this way because of recycle port.  This newly added ECMP route may be
            # used since recycle port sends back into datapath.
            return

        # Add another ECMP next hop
        tx_port = setup_info[dest_port_type]["dest_port"][2]
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        # Verify that mirrored traffic is not sent to this new next hop
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][2]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type,
            expect_recv=False,
            valid_across_namespace=False
        )

        # Remove the extra hop
        everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        # Verify that mirrored traffic is not sent to the deleted next hop
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type,
            expect_recv=False,
            valid_across_namespace=False
        )

        # Verify that mirrored traffic is still sent to one of the original next hops
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            tx_port_ptf_ids,
            dest_port_type
        )

    def test_everflow_remove_used_ecmp_next_hop(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session, dest_port_type, ptfadapter, tbinfo):
        """Verify that session is still active after removal of next hop from ECMP route that was in use."""

        # Remaining Scenario not applicable for this topology
        if len(setup_info[dest_port_type]["dest_port"]) <= 2:
            pytest.skip("Skip test as not enough neighbors/ports.")
        if setup_info['topo'] == "t2":
            # This doesn't work with recycle port.  After adding the two ECMP hops, they may be in use since mirror packets
            # go to recycle port and then normal IP forwarding occurs.  There is no guarantee the traffic stays on
            # the original route.
            pytest.skip("Mirror port is always recycle port in T2, so the mirror port can't be controlled as in this test case.")

        duthost = duthosts[rand_one_dut_hostname]
        # Add a route to the mirror session destination IP
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip_0 = everflow_utils.get_neighbor_info(duthost, tx_port, tbinfo)
        everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0, setup_info[dest_port_type]["namespace"])
        time.sleep(15)

        # Verify that mirrored traffic is sent along the route we installed
        rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            duthost,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        # Add two new ECMP next hops
        tx_port = setup_info[dest_port_type]["dest_port"][1]
        peer_ip_1 = everflow_utils.get_neighbor_info(duthost, tx_port, tbinfo)
        everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_1, setup_info[dest_port_type]["namespace"])

        tx_port = setup_info[dest_port_type]["dest_port"][2]
        peer_ip_2 = everflow_utils.get_neighbor_info(duthost, tx_port, tbinfo)
        everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_2, setup_info[dest_port_type]["namespace"])
        time.sleep(15)

        # Verify that traffic is still sent along the original next hop
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            duthost,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type,
            valid_across_namespace=False
        )

        # Verify that traffic is not sent along either of the new next hops
        tx_port_ptf_ids = [
            setup_info[dest_port_type]["dest_port_ptf_id"][1],
            setup_info[dest_port_type]["dest_port_ptf_id"][2]
        ]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            duthost,
            rx_port_ptf_id,
            tx_port_ptf_ids,
            dest_port_type,
            expect_recv=False,
            valid_across_namespace=False
        )

        # Remove the original next hop
        everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0, setup_info[dest_port_type]["namespace"])
        time.sleep(15)

        # Verify that mirrored traffic is no longer sent along the original next hop
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            duthost,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type,
            expect_recv=False
        )

        # Verify that mirrored traffis is now sent along either of the new next hops
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            duthost,
            rx_port_ptf_id,
            tx_port_ptf_ids,
            dest_port_type
        )

    def test_everflow_dscp_with_policer(
            self,
            duthosts,
            enum_rand_one_per_hwsku_frontend_hostname,
            setup_info,
            policer_mirror_session,
            dest_port_type,
            partial_ptf_runner,
            config_method,
            tbinfo
    ):
        """Verify that we can rate-limit mirrored traffic from the MIRROR_DSCP table.
        This tests single rate three color policer mode and specifically checks CIR value
        and switch behaviour under condition when CBS is assumed to be fully absorbed while
        sending traffic over a period of time. Received packets are accumulated and actual
        receive rate is calculated and compared with CIR value with tollerance range 10%.
        """
        # Add explicit for regular packet so that it's dest port is different then mirror port
        # NOTE: This is important to add since for the Policer test case regular packets
        # and mirror packets can go to same interface, which causes tail drop of
        # police packets and impacts test case cir/cbs calculation.
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        if setup_info['topo'] == 't0':
            default_tarffic_port_type = dest_port_type
            # Use the second portchannel as missor session nexthop
            tx_port = setup_info[dest_port_type]["dest_port"][1]
        else:
            default_tarffic_port_type = DOWN_STREAM if dest_port_type == UP_STREAM else UP_STREAM
            tx_port = setup_info[dest_port_type]["dest_port"][0]
        default_traffic_tx_port = setup_info[default_tarffic_port_type]["dest_port"][0]
        default_traffic_peer_ip = everflow_utils.get_neighbor_info(duthost, default_traffic_tx_port, tbinfo)
        everflow_utils.add_route(duthost, self.DEFAULT_DST_IP + "/32", default_traffic_peer_ip, setup_info[default_tarffic_port_type]["namespace"])
        time.sleep(15)

        # Add explicit route for the mirror session
        peer_ip = everflow_utils.get_neighbor_info(duthost, tx_port, tbinfo)
        everflow_utils.add_route(duthost, policer_mirror_session["session_prefixes"][0], peer_ip, setup_info[dest_port_type]["namespace"])
        time.sleep(15)

        try:
            # Add MIRROR_DSCP table for test
            table_name = "EVERFLOW_DSCP"
            table_type = "MIRROR_DSCP"
            rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
            if setup_info['topo'] == 't0' and self.acl_stage() == "egress":
                # For T0 upstream, the EVERFLOW_DSCP table is binded to one of portchannels
                bind_interface = setup_info[dest_port_type]["dest_port_lag_name"][0]
                mirror_port_id = setup_info[dest_port_type]["dest_port_ptf_id"][1]
            else:
                bind_interface = setup_info[dest_port_type]["src_port"]
                mirror_port_id = tx_port_ptf_id
                if setup_info[dest_port_type]["src_port_lag_name"] != "Not Applicable":
                    bind_interface = setup_info[dest_port_type]["src_port_lag_name"]

            # Temp change for multi-asic to create acl table in host and namespace
            # Will be removed once CLI is command is enahnced to work across all namespaces.
            self.apply_acl_table_config(duthost, table_name, table_type, config_method, [bind_interface])
            bind_interface_namespace = self._get_port_namespace(setup_info, int(rx_port_ptf_id))
            if bind_interface_namespace:
                self.apply_acl_table_config(duthost, table_name, table_type, config_method, [bind_interface], bind_interface_namespace) 
            # Add rule to match on DSCP
            self.apply_acl_rule_config(duthost,
                                       table_name,
                                       policer_mirror_session["session_name"],
                                       config_method,
                                       rules=EVERFLOW_DSCP_RULES)

            # Run test with expected CIR/CBS in packets/sec and tolerance %
            partial_ptf_runner(setup_info,
                               policer_mirror_session,
                               self.acl_stage(),
                               self.mirror_type(),
                               expect_receive=True,
                               test_name="everflow_policer_test.EverflowPolicerTest",
                               src_port=rx_port_ptf_id,
                               dst_mirror_ports=mirror_port_id,
                               dst_ports=tx_port_ptf_id,
                               meter_type="packets",
                               cir="100",
                               cbs="100",
                               send_time="10",
                               tolerance="10")
        finally:
            # Clean up ACL rules and routes
            BaseEverflowTest.remove_acl_rule_config(duthost, table_name, config_method)
            self.remove_acl_table_config(duthost, table_name, config_method)
            if bind_interface_namespace:
                self.remove_acl_table_config(duthost, table_name, config_method, bind_interface_namespace)
            everflow_utils.remove_route(duthost, policer_mirror_session["session_prefixes"][0], peer_ip, setup_info[dest_port_type]["namespace"])
            everflow_utils.remove_route(duthost, self.DEFAULT_DST_IP + "/32", default_traffic_peer_ip, setup_info[default_tarffic_port_type]["namespace"])

    def _run_everflow_test_scenarios(self, ptfadapter, setup, mirror_session, duthost, rx_port, tx_ports, direction,
                                     expect_recv=True, valid_across_namespace=True, mirror_dst_mac=None):
        # FIXME: In the ptf_runner version of these tests, LAGs were passed down to the tests as comma-separated strings of
        # LAG member port IDs (e.g. portchannel0001 -> "2,3"). Because the DSCP test is still using ptf_runner we will preserve
        # this for now, but we should try to make the format a little more friendly once the DSCP test also gets converted.
        tx_port_ids = self._get_tx_port_id_list(tx_ports)
        target_ip = "30.0.0.10"
        default_ip = self.DEFAULT_DST_IP
        if 't0' == setup['topo'] and direction == DOWN_STREAM:
            target_ip = TARGET_SERVER_IP
            default_ip = DEFAULT_SERVER_IP

        if "t2" in setup['topo']:
            router_mac = setup[direction]['router_mac']
            if setup[direction]['everflow_dut'] != setup[direction]['remote_dut']:
                # Intercard dut mac will change
                gre_pkt_src_mac = setup[direction]['remote_dut'].facts["router_mac"]
            else:
                gre_pkt_src_mac = router_mac
        else:
            router_mac = setup['router_mac']
            gre_pkt_src_mac = router_mac

        pkt_dict = {
            "(src ip)": self._base_tcp_packet(ptfadapter, router_mac, src_ip="20.0.0.10", dst_ip=default_ip),
            "(dst ip)": self._base_tcp_packet(ptfadapter, router_mac, dst_ip=target_ip),
            "(l4 src port)": self._base_tcp_packet(ptfadapter, router_mac, sport=0x1235, dst_ip=default_ip),
            "(l4 dst port)": self._base_tcp_packet(ptfadapter, router_mac, dport=0x1235, dst_ip=default_ip),
            "(ip protocol)": self._base_tcp_packet(ptfadapter, router_mac, ip_protocol=0x7E, dst_ip=default_ip),
            "(tcp flags)": self._base_tcp_packet(ptfadapter, router_mac, flags=0x12, dst_ip=default_ip),
            "(l4 src range)": self._base_tcp_packet(ptfadapter, router_mac, sport=4675, dst_ip=default_ip),
            "(l4 dst range)": self._base_tcp_packet(ptfadapter, router_mac, dport=4675, dst_ip=default_ip),
            "(dscp)": self._base_tcp_packet(ptfadapter, router_mac, dscp=51, dst_ip=default_ip)
        }

        for description, pkt in pkt_dict.items():
            logging.info("Sending packet with qualifier set %s to DUT" % description)
            self.send_and_check_mirror_packets(
                setup,
                mirror_session,
                ptfadapter,
                duthost,
                pkt,
                src_port=rx_port,
                dest_ports=tx_port_ids,
                expect_recv=expect_recv,
                valid_across_namespace=valid_across_namespace,
                gre_pkt_src_mac=gre_pkt_src_mac,
                gre_pkt_dst_mac=mirror_dst_mac,
                egress_mirror_src_mac=router_mac
            )

    def _base_tcp_packet(
        self,
        ptfadapter,
        router_mac,
        src_ip=DEFAULT_SRC_IP,
        dst_ip=DEFAULT_DST_IP,
        ip_protocol=None,
        dscp=None,
        sport=0x1234,
        dport=0x50,
        flags=0x10
    ):
        pkt = testutils.simple_tcp_packet(
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            eth_dst=router_mac,
            ip_src=src_ip,
            ip_dst=dst_ip,
            ip_ttl=64,
            ip_dscp=dscp,
            tcp_sport=sport,
            tcp_dport=dport,
            tcp_flags=flags
        )

        if ip_protocol:
            pkt["IP"].proto = ip_protocol

        return pkt

    @pytest.mark.topology("t2")
    def test_everflow_mirror_session_output(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session,
                                            dest_port_type, ptfadapter, tbinfo):
        """
        Verify show mirror session shows correct recycle or local port based on mirror session egress route on t2
        chassis.  Move egress route through all ports on both linecards and verify traffic and show command.
        """
        everflow_dut = setup_info[dest_port_type]['everflow_dut']
        remote_dut = setup_info[dest_port_type]['remote_dut']

        everflow_dut.shell(everflow_dut.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"no ip nht resolve-via-default\"", get_intf_namespace(setup_info, dest_port_type, setup_info[dest_port_type]['src_port'])))

        for dst_idx in range(0, len(setup_info[dest_port_type]["dest_port"])):

            tx_port = setup_info[dest_port_type]["dest_port"][dst_idx]

            logging.info("SUBTEST: Add a route to the mirror session destination IP on %s intf %s", remote_dut.hostname, tx_port)
            tx_ns = get_intf_namespace(setup_info, dest_port_type, tx_port)
            peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
            everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, tx_ns)

            time.sleep(5)

            src_show = self.get_monitor_port_info(setup_info, setup_mirror_session, everflow_dut)
            pytest_assert(src_show['asic0'] == "Ethernet-Rec0", "mirror is not recycle port on %s, asic0" % everflow_dut.hostname)
            pytest_assert(src_show['asic1'] == "Ethernet-Rec1", "mirror is not recycle port on %s, asic1" % everflow_dut.hostname)

            time.sleep(15)

            # # Verify that mirrored traffic is sent along the route we installed
            rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][dst_idx]
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                everflow_dut,
                rx_port_ptf_id,
                [tx_port_ptf_id],
                dest_port_type
            )

            everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))

        rev_port_type = DOWN_STREAM if dest_port_type == UP_STREAM else UP_STREAM

        for dst_idx in range(0, len(setup_info[rev_port_type]["dest_port"])):
            try:
                tx_port = setup_info[rev_port_type]["dest_port"][dst_idx]

                logging.info("SUBTEST: Add a route to the mirror session destination IP on %s intf %s", everflow_dut.hostname, tx_port)
                tx_ns = get_intf_namespace(setup_info, rev_port_type, tx_port)
                peer_ip = everflow_utils.get_neighbor_info(everflow_dut, tx_port, tbinfo)
                everflow_utils.add_route(everflow_dut, setup_mirror_session["session_prefixes"][0], peer_ip, tx_ns)

                time.sleep(5)

                dst_show = self.get_monitor_port_info(setup_info, setup_mirror_session, remote_dut)
                pytest_assert(dst_show['asic0'] == "Ethernet-Rec0", "mirror is not recycle port on %s, asic0" % everflow_dut.hostname)
                pytest_assert(dst_show['asic1'] == "Ethernet-Rec1", "mirror is not recycle port on %s, asic1" % everflow_dut.hostname)

                time.sleep(15)
                # # Verify that mirrored traffic is sent along the route we installed
                rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
                tx_port_ptf_id = setup_info[rev_port_type]["dest_port_ptf_id"][dst_idx]
                setup_info[dest_port_type]['remote_dut'] = setup_info[dest_port_type]['everflow_dut']
                self._run_everflow_test_scenarios(
                    ptfadapter,
                    setup_info,
                    setup_mirror_session,
                    everflow_dut,
                    rx_port_ptf_id,
                    [tx_port_ptf_id],
                    dest_port_type
                )
            finally:
                setup_info[dest_port_type]['remote_dut'] = remote_dut
                everflow_utils.remove_route(everflow_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, rev_port_type, tx_port))

    @pytest.mark.topology("t2")
    def test_flap_mirror_port(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session,
                              dest_port_type, ptfadapter, tbinfo):
        """
        Shutdown the mirror port or port channel to deactivate mirror session then startup the interface to reactivate
        the session.
        """
        everflow_dut = setup_info[dest_port_type]['everflow_dut']
        remote_dut = setup_info[dest_port_type]['remote_dut']

        everflow_dut.shell(everflow_dut.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"no ip nht resolve-via-default\"", get_intf_namespace(setup_info, dest_port_type, setup_info[dest_port_type]['src_port'])))

        logging.info("SUBTEST: Add a route to the mirror session destination IP")
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))

        time.sleep(15)
        # Verify that mirrored traffic is sent along the route we installed
        rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        asic = remote_dut.get_asic_or_sonic_host_from_namespace(get_intf_namespace(setup_info, dest_port_type, tx_port))
        logging.info("Shutdown interface %s on host %s", tx_port, remote_dut.hostname)
        asic.shutdown_interface(tx_port)
        time.sleep(5)
        try:
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                everflow_dut,
                rx_port_ptf_id,
                [tx_port_ptf_id],
                dest_port_type,
                expect_recv=False
            )
        finally:
            asic.startup_interface(tx_port)
            logging.info("Startup interface %s on host %s", tx_port, remote_dut.hostname)
        time.sleep(15)
        asic.ping_v4(peer_ip)

        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

    @pytest.mark.topology("t2")
    def test_add_remove_mirror_route(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session,
                                     dest_port_type, ptfadapter, tbinfo):
        """
        Add and remove route to mirror destionation causing mirror session to deactivate and reactivate.
        """
        everflow_dut = setup_info[dest_port_type]['everflow_dut']
        remote_dut = setup_info[dest_port_type]['remote_dut']
        everflow_dut.shell(everflow_dut.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"no ip nht resolve-via-default\"", get_intf_namespace(setup_info, dest_port_type, setup_info[dest_port_type]['src_port'])))

        logging.info("SUBTEST: Add a route to the mirror session destination IP")
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))

        time.sleep(15)

        # Verify that mirrored traffic is sent along the route we installed
        rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
        tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )

        logging.info("SUBTEST: remove the normal route and recreate it")
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type,
            expect_recv=False
        )
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, get_intf_namespace(setup_info, dest_port_type, tx_port))
        time.sleep(15)

        self._run_everflow_test_scenarios(
            ptfadapter,
            setup_info,
            setup_mirror_session,
            everflow_dut,
            rx_port_ptf_id,
            [tx_port_ptf_id],
            dest_port_type
        )


class TestEverflowV4IngressAclIngressMirror(EverflowIPv4Tests):
    def acl_stage(self):
        return "ingress"

    def mirror_type(self):
        return "ingress"


class TestEverflowV4IngressAclEgressMirror(EverflowIPv4Tests):
    def acl_stage(self):
        return "ingress"

    def mirror_type(self):
        return "egress"


class TestEverflowV4EgressAclIngressMirror(EverflowIPv4Tests):
    def acl_stage(self):
        return "egress"

    def mirror_type(self):
        return "ingress"


class TestEverflowV4EgressAclEgressMirror(EverflowIPv4Tests):
    def acl_stage(self):
        return "egress"

    def mirror_type(self):
        return "egress"
