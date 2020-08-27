"""Test cases to support the Everflow Mirroring feature in SONiC."""
import logging
import os
import time
import pytest

import ptf.testutils as testutils
import everflow_test_utilities as everflow_utils

from tests.ptf_runner import ptf_runner
from everflow_test_utilities import BaseEverflowTest

# Module-level fixtures
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from tests.common.fixtures.ptfhost_utils import copy_acstests_directory   # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from everflow_test_utilities import setup_info                            # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error

pytestmark = [
    pytest.mark.topology("t1")
]

TEMPLATE_DIR = "everflow/templates"
EVERFLOW_TABLE_RULE_CREATE_TEMPLATE = "acl_rule_persistent.json.j2"

DUT_RUN_DIR = "/home/admin/everflow_tests"
EVERFLOW_TABLE_RULE_CREATE_FILE = "acl_rule_persistent.json"
EVERFLOW_TABLE_RULE_DELETE_FILE = "acl_rule_persistent-del.json"

@pytest.fixture
def partial_ptf_runner(request, duthost, ptfhost):
    """
    Fixture to run each Everflow PTF test case via ptf_runner.

    Takes all the necessary arguments to run the test case and returns a handle to the caller
    to execute the ptf_runner.
    """
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
                  'expect_received' : expect_receive }
        params.update(kwargs)

        ptf_runner(host=ptfhost,
                   testdir="acstests",
                   platform_dir="ptftests",
                   testname="everflow_tb_test.EverflowTest" if not test_name else test_name,
                   params=params,
                   socket_recv_size=16384,
                   log_file="/tmp/{}.{}.log".format(request.cls.__name__, request.function.__name__))

    return _partial_ptf_runner


class EverflowIPv4Tests(BaseEverflowTest):
    """Base class for testing the Everflow feature w/ IPv4."""

    DEFAULT_SRC_IP = "20.0.0.1"
    DEFAULT_DST_IP = "30.0.0.1"

    @pytest.fixture(params=["tor", "spine"])
    def dest_port_type(self, request):
        """
        Get the dest port for this test case.

        Used to parametrize test cases based on dest port type to validate forwarding behavior.

        Args:
            request: Pytest request object

        Returns:
            A destination port type in {tor, spine}.
        """
        return request.param

    # FIXME: We use a lot of try-catch here to clean up routes, but it's a bit messy.
    # A better solution might be to have a fixture that receives route updates and then
    # cleans up any remaining routes at the end.

    def test_everflow_basic_forwarding(self, duthost, setup_info, setup_mirror_session, dest_port_type, ptfadapter):
        """
        Verify basic forwarding scenarios for the Everflow feature.

        Scenarios covered include:
            - Resolved route
            - Unresolved route
            - LPM (longest prefix match)
            - Route creation and removal
        """
        try:
            # Add a route to the mirror session destination IP
            tx_port = setup_info[dest_port_type]["dest_port"][0]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)
            time.sleep(3)

            # Verify that mirrored traffic is sent along the route we installed
            rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
            )

            # Add a (better) unresolved route to the mirror session destination IP
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port, resolved=False)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][1], peer_ip)
            time.sleep(3)

            # Verify that mirrored traffic is still sent along the original route
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
            )

            # Remove the unresolved route
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][1], peer_ip)

            # Add a better route to the mirror session destination IP
            tx_port = setup_info[dest_port_type]["dest_port"][1]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)
            time.sleep(3)

            # Verify that mirrored traffic uses the new route
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][1]
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
            )

            # Remove the better route.
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][1], peer_ip)
            time.sleep(3)

            # Verify that mirrored traffic switches back to the original route
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
            )

            # Clean up the test
            tx_port = setup_info[dest_port_type]["dest_port"][0]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        except Exception:
            tx_port = setup_info[dest_port_type]["dest_port"][0]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][1], peer_ip)

            tx_port = setup_info[dest_port_type]["dest_port"][1]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][1], peer_ip)

            raise

    def test_everflow_neighbor_mac_change(self, duthost, setup_info, setup_mirror_session, dest_port_type, ptfadapter):
        """Verify that session destination MAC address is changed after neighbor MAC address update."""
        try:
            # Add a route to the mirror session destination IP
            tx_port = setup_info[dest_port_type]["dest_port"][0]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)
            time.sleep(3)

            # Verify that mirrored traffic is sent along the route we installed
            rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
            )

            # Update the MAC on the neighbor interface for the route we installed
            if setup_info[dest_port_type]["dest_port_lag_name"][0] != "Not Applicable":
                tx_port = setup_info[dest_port_type]["dest_port_lag_name"][0]

            duthost.shell("ip neigh replace {} lladdr 00:11:22:33:44:55 nud permanent dev {}".format(peer_ip, tx_port))
            time.sleep(3)

            # Verify that everything still works
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
            )

            # Clean up the test
            duthost.shell("ip neigh del {} dev {}".format(peer_ip, tx_port))
            duthost.shell("ping {} -c3".format(peer_ip))
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)

        except Exception:
            tx_port = setup_info[dest_port_type]["dest_port"][0]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)

            raise

    def test_everflow_remove_unused_ecmp_next_hop(self, duthost, setup_info, setup_mirror_session, dest_port_type, ptfadapter):
        """Verify that session is still active after removal of next hop from ECMP route that was not in use."""
        try:
            # Create two ECMP next hops
            tx_port = setup_info[dest_port_type]["dest_port"][0]
            peer_ip_0, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0)
            time.sleep(3)

            tx_port = setup_info[dest_port_type]["dest_port"][1]
            peer_ip_1, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_1)
            time.sleep(3)

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
                duthost,
                rx_port_ptf_id,
                tx_port_ptf_ids
            )

            # Add another ECMP next hop
            tx_port = setup_info[dest_port_type]["dest_port"][2]
            peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)
            time.sleep(3)

            # Verify that mirrored traffic is not sent to this new next hop
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][2]
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id],
                expect_recv=False
            )

            # Remove the extra hop
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)
            time.sleep(3)

            # Verify that mirrored traffic is not sent to the deleted next hop
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id],
                expect_recv=False
            )

            # Verify that mirrored traffic is still sent to one of the original next hops
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                tx_port_ptf_ids
            )

            # Clean up the test
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_1)

        except Exception:
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_1)   
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip)

            raise

    def test_everflow_remove_used_ecmp_next_hop(self, duthost, setup_info, setup_mirror_session, dest_port_type, ptfadapter):
        """Verify that session is still active after removal of next hop from ECMP route that was in use."""
        try:
            # Add a route to the mirror session destination IP
            tx_port = setup_info[dest_port_type]["dest_port"][0]
            peer_ip_0, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0)
            time.sleep(3)

            # Verify that mirrored traffic is sent along the route we installed
            rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
            )

            # Add two new ECMP next hops
            tx_port = setup_info[dest_port_type]["dest_port"][1]
            peer_ip_1, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_1)

            tx_port = setup_info[dest_port_type]["dest_port"][2]
            peer_ip_2, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
            everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_2)
            time.sleep(3)

            # Verify that traffic is still sent along the original next hop
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id]
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
                expect_recv=False
            )

            # Remove the original next hop
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0)
            time.sleep(3)

            # Verify that mirrored traffic is no longer sent along the original next hop
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                [tx_port_ptf_id],
                expect_recv=False
            )

            # Verify that mirrored traffis is now sent along either of the new next hops
            self._run_everflow_test_scenarios(
                ptfadapter,
                setup_info,
                setup_mirror_session,
                duthost,
                rx_port_ptf_id,
                tx_port_ptf_ids
            )

            # Clean up the tests
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_1)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_2)
        except Exception:
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_0)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_1)
            everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip_2)

            raise

    def test_everflow_dscp_with_policer(self, duthost, setup_info, policer_mirror_session, dest_port_type, partial_ptf_runner):
        """Verify that we can rate-limit mirrored traffic from the MIRROR_DSCP table."""

        # Add explicit route for the mirror session
        tx_port = setup_info[dest_port_type]["dest_port"][0]
        peer_ip, _ = everflow_utils.get_neighbor_info(duthost, tx_port)
        everflow_utils.add_route(duthost, policer_mirror_session["session_prefixes"][0], peer_ip)

        try:
            # Add MIRROR_DSCP table for test
            duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --stage={}".format(self.acl_stage()))

            # Add rule to match on DSCP
            mirror_action = "MIRROR_INGRESS_ACTION" if self.mirror_type() == 'ingress' else "MIRROR_EGRESS_ACTION"
            duthost.command("redis-cli -n 4 hmset \"ACL_RULE|EVERFLOW_DSCP|RULE_1\" PRIORITY 9999 {} {} DSCP 8/56"
                            .format(mirror_action, policer_mirror_session["session_name"]))

            # Sync rule
            time.sleep(3)

            # Run test with expected CIR/CBS in packets/sec and tolerance %
            rx_port_ptf_id = setup_info[dest_port_type]["src_port_ptf_id"]
            tx_port_ptf_id = setup_info[dest_port_type]["dest_port_ptf_id"][0]

            partial_ptf_runner(setup_info,
                               policer_mirror_session,
                               self.acl_stage(),
                               self.mirror_type(),
                               expect_receive=True,
                               test_name="everflow_policer_test.EverflowPolicerTest",
                               src_port=rx_port_ptf_id,
                               dst_mirror_ports=tx_port_ptf_id,
                               dst_ports=tx_port_ptf_id,
                               meter_type="packets",
                               cir="100",
                               cbs="100",
                               tolerance="10")
        finally:
            # Clean up ACL rules and routes
            duthost.command("redis-cli -n 4 del \"ACL_RULE|EVERFLOW_DSCP|RULE_1\"")
            duthost.command("config acl remove table EVERFLOW_DSCP")
            everflow_utils.remove_route(duthost, policer_mirror_session["session_prefixes"][0], peer_ip)

    def _run_everflow_test_scenarios(self, ptfadapter, setup, mirror_session, duthost, rx_port, tx_ports, expect_recv=True):
        # FIXME: In the ptf_runner version of these tests, LAGs were passed down to the tests as comma-separated strings of
        # LAG member port IDs (e.g. portchannel0001 -> "2,3"). Because the DSCP test is still using ptf_runner we will preserve
        # this for now, but we should try to make the format a little more friendly once the DSCP test also gets converted.
        tx_port_ids = []
        for port in tx_ports:
            members = port.split(',')
            for member in members:
                tx_port_ids.append(int(member))

        pkt_dict = {
            "(src ip)": self._base_tcp_packet(ptfadapter, setup, src_ip="20.0.0.10"),
            "(dst ip)": self._base_tcp_packet(ptfadapter, setup, dst_ip="30.0.0.10"),
            "(l4 src port)": self._base_tcp_packet(ptfadapter, setup, sport=0x1235),
            "(l4 dst port)": self._base_tcp_packet(ptfadapter, setup, dport=0x1235),
            "(ip protocol)": self._base_tcp_packet(ptfadapter, setup, ip_protocol=0x7E),
            "(tcp flags)": self._base_tcp_packet(ptfadapter, setup, flags=0x12),
            "(l4 src range)": self._base_tcp_packet(ptfadapter, setup, sport=4675),
            "(l4 dst range)": self._base_tcp_packet(ptfadapter, setup, dport=4675),
            "(dscp)": self._base_tcp_packet(ptfadapter, setup, dscp=51)
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
                expect_recv=expect_recv
            )

    def _base_tcp_packet(
        self,
        ptfadapter,
        setup,
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
            eth_dst=setup["router_mac"],
            ip_src=src_ip,
            ip_dst=dst_ip,
            ip_ttl=64,
            tcp_sport=sport,
            tcp_dport=dport,
            tcp_flags=flags
        )

        # NOTE: Yes testutils has an `ip_dscp` field, no it does not work here. I don't know why either. /shrug
        if dscp:
            pkt["IP"].tos = dscp << 2

        if ip_protocol:
            pkt["IP"].proto = ip_protocol

        return pkt


class TestEverflowV4IngressAclIngressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope="class", autouse=True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("Feature Not Supported: {} ACL w/ {} Mirroring"
                        .format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options["variable_manager"].extra_vars.update({"acl_table_name": "EVERFLOW"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE),
                         dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))

        duthost.command("acl-loader update full {} --session_name={}"
                        .format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE),
                                setup_mirror_session["session_name"]))

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command("acl-loader update full {}".format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE)))
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return "ingress"

    def mirror_type(self):
        return "ingress"


class TestEverflowV4IngressAclEgressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope="class", autouse=True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("Feature Not Supported: {} ACL w/ {} Mirroring"
                        .format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options["variable_manager"].extra_vars.update({"acl_table_name": "EVERFLOW"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE),
                         dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))

        duthost.command("acl-loader update full {} --session_name={}"
                        .format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE),
                                setup_mirror_session["session_name"]))

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command("acl-loader update full {}".format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE)))
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return "ingress"

    def mirror_type(self):
        return "egress"


class TestEverflowV4EgressAclIngressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope="class", autouse=True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("Feature Not Supported: {} ACL w/ {} Mirroring"
                        .format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options["variable_manager"].extra_vars.update({"acl_table_name": "EVERFLOW_EGRESS"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE),
                         dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))

        duthost.command("config acl add table EVERFLOW_EGRESS MIRROR --stage=egress")
        duthost.command("acl-loader update full {} --session_name={}"
                        .format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE),
                                setup_mirror_session["session_name"]))

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command("acl-loader update full {}".format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE)))
        duthost.command("config acl remove table EVERFLOW_EGRESS")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return "egress"

    def mirror_type(self):
        return "ingress"


class TestEverflowV4EgressAclEgressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope='class', autouse=True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("Feature Not Supported: {} ACL w/ {} Mirroring"
                        .format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options["variable_manager"].extra_vars.update({"acl_table_name": "EVERFLOW_EGRESS"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE),
                         dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))

        duthost.command("config acl add table EVERFLOW_EGRESS MIRROR --stage=egress")
        duthost.command("acl-loader update full {} --session_name={} --mirror_stage=egress"
                        .format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE),
                                setup_mirror_session["session_name"]))

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command("acl-loader update full {}".format(os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE)))
        duthost.command("config acl remove table EVERFLOW_EGRESS")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return "egress"

    def mirror_type(self):
        return "egress"
