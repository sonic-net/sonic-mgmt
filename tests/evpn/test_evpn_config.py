import logging
import pytest

from conftest import DUT_VTEP_IP

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]


class Test_EVPN_Config():
    @pytest.fixture(scope="class")
    def setup_dut(self, evpn_env):
        evpn_env.setup_dut_base()
        yield
        evpn_env.teardown_dut_base()

    @pytest.fixture(scope="class")
    def vrf_vni_map_set(self, duthost, setup_dut):
        duthost.shell("config vrf add Vrf1")
        duthost.shell("config vrf add_vrf_vni_map Vrf1 10000")
        yield
        duthost.shell("config vrf del_vrf_vni_map Vrf1")
        duthost.shell("config vrf del Vrf1")
        duthost.shell('sleep 3')
        duthost.shell("vtysh -c 'configure' -c 'no vrf {}'".format("Vrf1"))

    def test_vlan_vni_map_configuration(self, duthost, setup_dut):
        # vtep
        res = duthost.shell("redis-cli -n 4 -c hgetall 'VXLAN_TUNNEL|vtep'")
        res_list = res['stdout_lines']
        if (res_list[0] != 'src_ip') or (res_list[1] != DUT_VTEP_IP):
            assert(0)
        res = duthost.shell("redis-cli -n 0 -c hgetall 'VXLAN_TUNNEL_TABLE:vtep'")
        res_list = res['stdout_lines']
        if (res_list[0] != 'src_ip') or (res_list[1] != DUT_VTEP_IP):
            assert(0)
        # evpnnvo
        res = duthost.shell("redis-cli -n 4 -c hgetall 'VXLAN_EVPN_NVO|evpnnvo1'")
        res_list = res['stdout_lines']
        if (res_list[0] != 'source_vtep') or (res_list[1] != 'vtep'):
            assert(0)
        res = duthost.shell("redis-cli -n 0 -c hgetall 'VXLAN_EVPN_NVO_TABLE:evpnnvo1'")
        res_list = res['stdout_lines']
        if (res_list[0] != 'source_vtep') or (res_list[1] != 'vtep'):
            assert(0)
        # map
        res = duthost.shell("redis-cli -n 4 -c hgetall 'VXLAN_TUNNEL_MAP|vtep|map_10000_Vlan1000'")
        res_list = res['stdout_lines']
        if (res_list[2] != 'vlan') or (res_list[3] != 'Vlan1000') or (res_list[0] != 'vni') or (res_list[1] != '10000'):
            assert(0)
        res = duthost.shell("redis-cli -n 0 -c hgetall 'VXLAN_TUNNEL_MAP_TABLE:vtep:map_10000_Vlan1000'")
        res_list = res['stdout_lines']
        logging.info(res_list)
        if (res_list[2] != 'vlan') or (res_list[3] != 'Vlan1000') or (res_list[0] != 'vni') or (res_list[1] != '10000'):
            assert(0)

    def test_vrf_vni_map_configuration(self, duthost, vrf_vni_map_set):
        # vrf
        res = duthost.shell("redis-cli -n 4 -c hgetall 'VRF|Vrf1'")
        res_list = res['stdout_lines']
        if 'vni' not in res_list or '10000' not in res_list:
            assert(0)
        res = duthost.shell("redis-cli -n 0 -c hgetall 'VRF_TABLE:Vrf1'")
        res_list = res['stdout_lines']
        if 'vni' not in res_list or '10000' not in res_list:
            assert(0)
        res = duthost.shell("redis-cli -n 0 -c hgetall 'VXLAN_VRF_TABLE:vtep:evpn_map_10000_Vrf1'")
        res_list = res['stdout_lines']
        if 'vni' not in res_list or '10000' not in res_list or 'vrf' not in res_list or 'Vrf1' not in res_list:
            assert(0)
