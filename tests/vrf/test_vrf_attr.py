import pytest

from test_vrf import g_vars
from test_vrf import setup_vrf              # lgtm[py/unused-import]
from test_vrf import dut_facts             # lgtm[py/unused-import]
from test_vrf import gen_vrf_neigh_file
from test_vrf import partial_ptf_runner     # lgtm[py/unused-import]
from test_vrf import ptf_test_port_map      # lgtm[py/unused-import]
from test_vrf import mg_facts      # lgtm[py/unused-import]
from test_vrf import vlan_mac      # lgtm[py/unused-import]
from test_vrf import PTF_TEST_PORT_MAP

from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory

pytestmark = [
    pytest.mark.topology('t0')
]

# tests
class TestVrfAttrSrcMac():
    new_vrf1_router_mac = '00:12:34:56:78:9a'

    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_attr_src_mac(self, duthosts, rand_one_dut_hostname, ptfhost, dut_facts):
        duthost = duthosts[rand_one_dut_hostname]
        # -------- Setup ----------
        extra_vars = { 'router_mac': self.new_vrf1_router_mac }
        duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
        duthost.template(src="vrf/vrf_attr_src_mac.j2", dest="/tmp/vrf_attr_src_mac.json")

        duthost.shell("config load -y /tmp/vrf_attr_src_mac.json")

        gen_vrf_neigh_file('Vrf1', ptfhost, render_file="/tmp/vrf1_neigh.txt")

        gen_vrf_neigh_file('Vrf2', ptfhost, render_file="/tmp/vrf2_neigh.txt")

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        extra_vars = { 'router_mac': dut_facts['router_mac'] }
        duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
        duthost.template(src="vrf/vrf_attr_src_mac.j2", dest="/tmp/vrf_attr_src_mac.json")

        duthost.shell("config load -y /tmp/vrf_attr_src_mac.json")

    def test_vrf_src_mac_cfg(self, duthosts, rand_one_dut_hostname):
        duthost = duthosts[rand_one_dut_hostname]
        # get vrf1 new router_mac from config_db
        vrf1_mac = duthost.shell("redis-cli -n 4 hget 'VRF|Vrf1' 'src_mac'")['stdout']
        assert vrf1_mac == self.new_vrf1_router_mac

    def test_vrf1_neigh_with_default_router_mac(self, partial_ptf_runner):
        # send packets with default router_mac
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            pkt_action='drop',
            fib_info_files=['/tmp/vrf1_neigh.txt'],
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf1_neigh_with_new_router_mac(self, ptfhost, tbinfo):
        # send packets with new router_mac
        ptf_runner(ptfhost,
                "ptftests",
                "vrf_test.FwdTest",
                platform_dir='ptftests',
                params={'testbed_type': tbinfo['topo']['name'],
                        'router_macs': [self.new_vrf1_router_mac],
                        'fib_info_files': ["/tmp/vrf1_neigh.txt"],
                        'src_ports': g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000'],
                        'ptf_test_port_map': PTF_TEST_PORT_MAP},
                log_file="/tmp/vrf_attr_src_mac_test.FwdTest2.log")

    def test_vrf2_neigh_with_default_router_mac(self, partial_ptf_runner):
        # verify router_mac of Vrf2 keep to be default router_mac
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf2_neigh.txt'],
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )


class TestVrfAttrTTL():
    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_attr_ttl(self, duthosts, rand_one_dut_hostname, ptfhost):
        duthost = duthosts[rand_one_dut_hostname]
        # -------- Setup ----------
        duthost.copy(src="vrf/vrf_attr_ttl_action.json", dest="/tmp")
        duthost.copy(src="vrf/vrf_restore.json", dest="/tmp")

        duthost.shell("config load -y /tmp/vrf_attr_ttl_action.json")

        gen_vrf_neigh_file('Vrf1', ptfhost, render_file="/tmp/vrf1_neigh.txt")

        gen_vrf_neigh_file('Vrf2', ptfhost, render_file="/tmp/vrf2_neigh.txt")

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        duthost.shell("config load -y /tmp/vrf_restore.json")

    def test_vrf1_drop_pkts_with_ttl_1(self, partial_ptf_runner):
        # verify packets in Vrf1 with ttl=1 should be drop
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            pkt_action='drop',
            fib_info_files=['/tmp/vrf1_neigh.txt'],
            ttl=1,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf1_fwd_pkts_with_ttl_2(self, partial_ptf_runner):
        # verify packets in Vrf1 with ttl=2 should be forward
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf1_neigh.txt'],
            ttl=2,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf2_fwd_pkts_with_ttl_1(self, partial_ptf_runner):
        # verify packets in Vrf2 with ttl=1 should be forward
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf2_neigh.txt'],
            ttl=1,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )


class TestVrfAttrIpAction():
    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_attr_ip_opt_action(self, duthosts, rand_one_dut_hostname, ptfhost):
        duthost = duthosts[rand_one_dut_hostname]
        # -------- Setup ----------
        duthost.copy(src="vrf/vrf_attr_ip_opt_action.json", dest="/tmp")
        duthost.copy(src="vrf/vrf_restore.json", dest="/tmp")

        duthost.shell("config load -y /tmp/vrf_attr_ip_opt_action.json")

        gen_vrf_neigh_file('Vrf1', ptfhost, render_file="/tmp/vrf1_neigh.txt")

        gen_vrf_neigh_file('Vrf2', ptfhost, render_file="/tmp/vrf2_neigh.txt")

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        duthost.shell("config load -y /tmp/vrf_restore.json")

    def test_vrf1_drop_pkts_with_ip_opt(self, partial_ptf_runner):
        # verify packets in Vrf1 with ip_option should be drop
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            pkt_action='drop',
            fib_info_files=['/tmp/vrf1_neigh.txt'],
            ip_option=True,
            ipv4=True,
            ipv6=False,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf1_fwd_pkts_without_ip_opt(self, partial_ptf_runner):
        # verify packets in Vrf1 without ip_option should be forward
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf1_neigh.txt'],
            ip_option=False,
            ipv4=True,
            ipv6=False,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf2_fwd_pkts_with_ip_opt(self, partial_ptf_runner):
        # verify packets in Vrf2 with ip_option should be forward
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf2_neigh.txt'],
            ip_option=True,
            ipv4=True,
            ipv6=False,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )


class TestVrfAttrIpState():
    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_attr_ip_state(self, duthosts, rand_one_dut_hostname, ptfhost):
        duthost = duthosts[rand_one_dut_hostname]
        # -------- Setup ----------
        duthost.copy(src="vrf/vrf_attr_ip_state.json", dest="/tmp")
        duthost.copy(src="vrf/vrf_restore.json", dest="/tmp")

        duthost.shell("config load -y /tmp/vrf_attr_ip_state.json")

        gen_vrf_neigh_file('Vrf1', ptfhost, render_file="/tmp/vrf1_neigh.txt")

        gen_vrf_neigh_file('Vrf2', ptfhost, render_file="/tmp/vrf2_neigh.txt")

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        duthost.shell("config load -y /tmp/vrf_restore.json")

    def test_vrf1_drop_v4(self, partial_ptf_runner):
        # verify ipv4 L3 traffic is dropped in vrf1
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf1_neigh.txt'],
            pkt_action='drop',
            ipv4=True,
            ipv6=False,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf1_forward_v6(self, partial_ptf_runner):
        # verify ipv6 L3 traffic is forwarded in vrf1
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf1_neigh.txt'],
            ipv4=False,
            ipv6=True,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf2_forward_v4(self, partial_ptf_runner):
        # verify ipv4 L3 traffic is forwarded in vrf2
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            fib_info_files=['/tmp/vrf2_neigh.txt'],
            ipv4=True,
            ipv6=False,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )

    def test_vrf2_drop_v6(self, partial_ptf_runner):
        # verify ipv6 L3 traffic is dropped in vrf2
        partial_ptf_runner(
            testname='vrf_test.FwdTest',
            pkt_action='drop',
            fib_info_files=['/tmp/vrf2_neigh.txt'],
            ipv4=False,
            ipv6=True,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )
