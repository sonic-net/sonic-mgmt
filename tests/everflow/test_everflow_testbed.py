"""Test cases to support the Everflow Mirroring feature in SONiC."""

import os
import time
import pytest
import everflow_test_utilities as everflow_utils

from tests.ptf_runner import ptf_runner
from everflow_test_utilities import BaseEverflowTest

# Module-level fixtures
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from tests.common.fixtures.ptfhost_utils import copy_acstests_directory   # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error
from everflow_test_utilities import setup_info                            # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
FILES_DIR = os.path.join(BASE_DIR, 'files')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')

EVERFLOW_TABLE_RULE_CREATE_TEMPLATE = 'acl_rule_persistent.json.j2'
EVERFLOW_TABLE_RULE_CREATE_FILE = 'acl_rule_persistent.json'
EVERFLOW_TABLE_RULE_DELETE_FILE = 'acl_rule_persistent-del.json'
DUT_RUN_DIR = '/home/admin/everflow_tests'

pytestmark = [
    pytest.mark.topology('t1')
]

#partial_ptf_runner is a pytest fixture that takes all the necessary arguments to run
#each everflow ptf test cases and calling the main function ptf_runner which will then
#combine all the arguments and form ptf command to run via ptfhost.shell().
#some of the arguments are fix for each everflow test cases and are define here and
#arguments specific to each everflow testcases are passed in each test via partial_ptf_runner
#Argumnents are passed in dictionary format via kwargs within each test case.

@pytest.fixture
def partial_ptf_runner(request, duthost, ptfhost):
    def _partial_ptf_runner(setup_info, session_info, acl_stage, mirror_type,  expect_receive = True, test_name = None, **kwargs):
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
    @pytest.fixture(params=['tor', 'spine'])
    def dest_port_type(self, request):
        """
        used to parametrized test cases on dest port type
        :param request: pytest request object
        :return: destination port type
        """
        return request.param

    def test_everflow_case1(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """  Test on Resolved route, unresolved route, best prefix match route creation and removal flows """

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        # call the function return by pytest fixture and pass arguments needed for
        # ptf test case like src port, dest port, acl_stage, mirror_type.
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port, False)

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)

        tx_port = setup_info[dest_port_type]['dest_port'][1]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][1]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)
        time.sleep(3)
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][1], peer_ip)
        time.sleep(3)
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

    def test_everflow_case2(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """Test case 2 - Change neighbor MAC address.
        Verify that session destination MAC address is changed after neighbor MAC address update."""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)


        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        if setup_info[dest_port_type]['dest_port_lag_name'][0] != 'Not Applicable':
            tx_port = setup_info[dest_port_type]['dest_port_lag_name'][0]


        duthost.shell("ip neigh replace {} lladdr 00:11:22:33:44:55 nud permanent dev {}".format(peer_ip, tx_port))

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id,
                           expected_dst_mac = '00:11:22:33:44:55')


        duthost.shell("ip neigh del {} dev {}".format(peer_ip, tx_port))

        duthost.shell("ping {} -c3".format(peer_ip))


        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

    def test_everflow_case3(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """Test case 3 -  ECMP route change (remove next hop not used by session).
        Verify that after removal of next hop that was used by session from ECMP route session state is active."""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)
        peer_ip0 = peer_ip

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        tx_port = setup_info[dest_port_type]['dest_port'][1]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][1]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)
        peer_ip1 = peer_ip

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][0])

        tx_port = setup_info[dest_port_type]['dest_port'][2]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][2]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = setup_info[dest_port_type]['dest_port_ptf_id'][0] + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][1])

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip0)
        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip1)


    def test_everflow_case4(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):
        """Test case 4 - ECMP route change (remove next hop used by session).
        Verify that removal of next hop that is not used by session doesn't cause DST port and MAC change."""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)
        peer_ip0 = peer_ip

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = tx_port_ptf_id)

        tx_port = setup_info[dest_port_type]['dest_port'][1]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)
        peer_ip1 = peer_ip

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        tx_port = setup_info[dest_port_type]['dest_port'][2]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)
        peer_ip2 = peer_ip

        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports = setup_info[dest_port_type]['dest_port_ptf_id'][0])


        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports =  setup_info[dest_port_type]['dest_port_ptf_id'][1] + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][2])

        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip0)

        time.sleep(3)

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(), expect_receive = False,
                           src_port = rx_port_ptf_id,
                           dst_ports = setup_info[dest_port_type]['dest_port_ptf_id'][0])

        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           src_port = rx_port_ptf_id,
                           dst_ports =  setup_info[dest_port_type]['dest_port_ptf_id'][1] + ',' + setup_info[dest_port_type]['dest_port_ptf_id'][2])

        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip1)
        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip2)

    def test_everflow_case5(self, duthost, setup_info, setup_mirror_session, dest_port_type, partial_ptf_runner):

        """Test case 5 - Policer enforced DSCP value/mask test"""

        rx_port_ptf_id =  setup_info[dest_port_type] ['src_port_ptf_id']
        tx_port = setup_info[dest_port_type]['dest_port'][0]
        tx_port_ptf_id = setup_info[dest_port_type]['dest_port_ptf_id'][0]
        peer_ip, peer_mac = everflow_utils.get_neighbor_info(duthost, tx_port)
        everflow_utils.add_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)

        # Create Policer.
        duthost.shell("redis-cli -n 4 hmset 'POLICER|TEST_POLICER' meter_type packets mode sr_tcm\
                        cir 100 cbs 100 red_packet_action drop")

        # Add Mirror Session with Policer aqttached to it.
        duthost.command('config mirror_session add TEST_POLICER_SESSION {} {} {} {} {} --policer TEST_POLICER'.format(
                        setup_mirror_session['session_src_ip'], setup_mirror_session['session_dst_ip'],
                        setup_mirror_session['session_dscp'], setup_mirror_session['session_ttl'],
                        setup_mirror_session['session_gre']))

       # Add ACL rule to match on DSCP and action as mirror
        mirror_action = "MIRROR_INGRESS_ACTION" if self.mirror_type() == 'ingress' else "MIRROR_EGRESS_ACTION"
        duthost.shell("redis-cli -n 4 hmset 'ACL_RULE|EVERFLOW_DSCP|RULE_1' PRIORITY 9999  {} TEST_POLICER_SESSION DSCP 8/56".format(mirror_action))

        time.sleep(3)

        # Send Traiffic with expected cir/cbs and tolerlance %
        partial_ptf_runner(setup_info, setup_mirror_session,self.acl_stage(), self.mirror_type(),
                           expect_receive = True, test_name = 'everflow_policer_test.EverflowPolicerTest',
                           src_port = rx_port_ptf_id, dst_mirror_ports = tx_port_ptf_id,
                           dst_ports = tx_port_ptf_id, meter_type = "packets", cir = "100", cbs = "100",
                           tolerance = "10")

        # Cleanup
        duthost.command('config mirror_session remove TEST_POLICER_SESSION')
        duthost.shell("redis-cli -n 4 del 'POLICER|TEST_POLICER_SESSION'")
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|EVERFLOW_DSCP|RULE_1'")
        everflow_utils.remove_route(duthost, setup_mirror_session['session_prefixes'][0], peer_ip)


class TestEverflowV4IngressAclIngressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
            pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))
        duthost.command('acl-loader update full {} --session_name={}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_TEST")

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return 'ingress'

    def mirror_type(self):
        return 'ingress'


class TestEverflowV4IngressAclEgressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
            pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW"})
        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))
        duthost.command('acl-loader update full {} --session_name={}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_TEST --stage=ingress")

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

    def acl_stage(self):
        return 'ingress'

    def mirror_type(self):
        return 'egress'


class TestEverflowV4EgressAclIngressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
           pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))

        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW_EGRESS"})

        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))

        # Remove default SONiC Everflow table (since SONiC allows only one mirror table)
        duthost.command("config acl remove table EVERFLOW")

        duthost.command("config acl add table EVERFLOW_EGRESS MIRROR --description EVERFLOW_EGRESS --stage=egress")
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_EGRESS_TEST --stage=egress")
        duthost.command('acl-loader update full {} --session_name={} --mirror_stage=egress'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_EGRESS")
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

        # Add default SONiC Everflow table back
        duthost.command("config acl add table EVERFLOW MIRROR --description EVERFLOW --stage=ingress")

    def acl_stage(self):
        return 'egress'

    def mirror_type(self):
        return 'ingress'


class TestEverflowV4EgressAclEgressMirror(EverflowIPv4Tests):
    @pytest.fixture(scope='class',  autouse = True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        if setup_info[self.acl_stage()][self.mirror_type()] == False:
           pytest.skip("Skipping Feature not Supported {} ACL having {} Mirror".format(self.acl_stage(), self.mirror_type()))

        duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))
        duthost.host.options['variable_manager'].extra_vars.update({'acl_table_name' : "EVERFLOW_EGRESS"})


        duthost.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_CREATE_TEMPLATE), dest=os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE))

        # Remove default SONiC Everflow table (since SONiC allows only one mirror table)
        duthost.command("config acl remove table EVERFLOW")

        duthost.command("config acl add table EVERFLOW_EGRESS MIRROR --description EVERFLOW_EGRESS --stage=egress")
        duthost.command("config acl add table EVERFLOW_DSCP MIRROR_DSCP --description EVERFLOW_EGRESS_TEST --stage=egress")
        duthost.command('acl-loader update full {} --session_name={} --mirror_stage=egress'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_CREATE_FILE)),setup_mirror_session['session_name']))

        yield

        duthost.copy(src=os.path.join(TEMPLATE_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE), dest=DUT_RUN_DIR)
        duthost.command('acl-loader update full {}'.format((os.path.join(DUT_RUN_DIR, EVERFLOW_TABLE_RULE_DELETE_FILE))))
        duthost.command("config acl remove table EVERFLOW_EGRESS")
        duthost.command("config acl remove table EVERFLOW_DSCP")
        duthost.shell("rm -rf {}".format(DUT_RUN_DIR))

        # Add default SONiC Everflow table back
        duthost.command("config acl add table EVERFLOW MIRROR --description EVERFLOW --stage=ingress")

    def acl_stage(self):
        return 'egress'

    def  mirror_type(self):
        return 'egress'
