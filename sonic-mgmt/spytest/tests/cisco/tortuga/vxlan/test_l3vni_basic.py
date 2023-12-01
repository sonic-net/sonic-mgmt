import pytest
from spytest import st
import apis.system.box_services as boxserv_obj

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:4",  "D1D4:4", "D2D3:4",  "D2D4:4")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass

####################
#                  #
#    D1 = Leaf0    #
#    D2 = Leaf1    #
#    D3 = Spine0   #
#    D4 = Spine1   #
#                  #
####################

def test_l3vni_two_neighbors():

    vars = st.get_testbed_vars()

    leaf0 = vars.D1
    leaf1 = vars.D2

    # Configure Leaf0
    leaf0_cfg = '''
    sudo config hostname LEAF0
    sudo config interface startup Ethernet0
    sudo config interface startup Ethernet16
    sudo config interface startup Ethernet32
    sudo config interface ipv6 enable use-link-local-only Ethernet0
    sudo config interface ipv6 enable use-link-local-only Ethernet16
    sudo config interface ipv6 enable use-link-local-only Ethernet32
    sudo config interface ipv6 disable use-link-local-only Ethernet0
    sudo config loopback add Loopback0
    sudo config interface ip add Loopback0 10.200.200.200/32
    sudo config vlan add 2
    sudo config vlan member add -u 2 Ethernet0
    sudo config vxlan add VXLAN 10.200.200.200
    sudo config vxlan evpn_nvo add NVO VXLAN
    sudo config vlan add 100
    sudo config vrf add Vrf01
    sudo config interface vrf bind Vlan2 Vrf01
    sudo config interface vrf bind Vlan100 Vrf01
    sudo config vxlan map add VXLAN 100 1000
    sudo config vrf add_vrf_vni_map Vrf01 1000
    sudo config interface ip add Vlan2 100.100.100.254/24
    '''
    commands = leaf0_cfg.splitlines()
    st.config(leaf0, commands)

    # Configure Leaf1
    leaf1_cfg = '''
    sudo config hostname LEAF1
    sudo config interface startup Ethernet0
    sudo config interface startup Ethernet16
    sudo config interface startup Ethernet32
    sudo config interface ipv6 enable use-link-local-only Ethernet0
    sudo config interface ipv6 enable use-link-local-only Ethernet16
    sudo config interface ipv6 enable use-link-local-only Ethernet32
    sudo config interface ipv6 disable use-link-local-only Ethernet0
    sudo config loopback add Loopback0
    sudo config interface ip add Loopback0 10.200.200.201/32
    sudo config vlan add 3
    sudo config vlan member add -u 3 Ethernet0
    sudo config vxlan add VXLAN 10.200.200.201
    sudo config vxlan evpn_nvo add NVO VXLAN
    sudo config vlan add 100
    sudo config vrf add Vrf01
    sudo config interface vrf bind Vlan3 Vrf01
    sudo config interface vrf bind Vlan100 Vrf01
    sudo config vxlan map add VXLAN 100 1000
    sudo config vrf add_vrf_vni_map Vrf01 1000
    sudo config interface ip add Vlan3 100.100.101.254/24
    '''
    commands = leaf1_cfg.splitlines()
    st.config(leaf1, commands)

    st.report_pass("test_case_passed")
