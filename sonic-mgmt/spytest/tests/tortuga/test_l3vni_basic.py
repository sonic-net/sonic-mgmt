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
'''
vtysh
configure terminal
router bgp 65100
bgp router-id 10.200.200.200
no bgp ebgp-requires-policy
no bgp default ipv4-unicast
neighbor SERVICE peer-group
neighbor SERVICE remote-as internal
neighbor SERVICE update-source Loopback0
neighbor 10.200.200.201 peer-group SERVICE
neighbor 10.200.200.202 peer-group SERVICE
neighbor TRANSIT peer-group
neighbor TRANSIT bfd
neighbor TRANSIT remote-as internal
neighbor Ethernet16 interface peer-group TRANSIT
neighbor Ethernet32 interface peer-group TRANSIT
address-family ipv4 unicast
redistribute connected
neighbor TRANSIT activate
exit
address-family l2vpn evpn
neighbor SERVICE activate
advertise-all-vni
advertise ipv4 unicast
exit
exit
vrf Vrf01
vni 1000
exit
router bgp 65100 vrf Vrf01
address-family ipv4 unicast
redistribute connected
exit-address-family
address-family l2vpn evpn
advertise ipv4 unicast
exit-address-family
exit
exit
exit
'''


'''
vtysh
configure terminal
router bgp 65100
bgp router-id 10.200.200.201
no bgp ebgp-requires-policy
no bgp default ipv4-unicast
neighbor SERVICE peer-group
neighbor SERVICE remote-as internal
neighbor SERVICE update-source Loopback0
neighbor 10.200.200.200 peer-group SERVICE
neighbor 10.200.200.202 peer-group SERVICE
neighbor TRANSIT peer-group
neighbor TRANSIT bfd
neighbor TRANSIT remote-as internal
neighbor Ethernet16 interface peer-group TRANSIT
neighbor Ethernet32 interface peer-group TRANSIT
address-family ipv4 unicast
redistribute connected
neighbor TRANSIT activate
exit
address-family l2vpn evpn
neighbor SERVICE activate
advertise-all-vni
advertise ipv4 unicast
exit
exit
vrf Vrf01
vni 1000
exit-vrf
router bgp 65100 vrf Vrf01
address-family ipv4 unicast
redistribute connected
exit-address-family
address-family l2vpn evpn
advertise ipv4 unicast
exit-address-family
exit
exit
exit
'''
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
    
