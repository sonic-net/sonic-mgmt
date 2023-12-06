import os
import yaml
import pytest
from spytest import st
import apis.routing.bgp as bgpapi

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:1",  "D1D4:1", "D2D3:1",  "D2D4:1")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

CONFIGS_FILE = 'vxlan_l3vni_configs.yaml'

def setup_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

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

####################################################################
#                                                                  #
#   leaf0.Ethernet0-11.11.11.2  ---- spine0.Ethernet0-11.11.11.1   #
#   leaf1.Ethernet12-11.11.12.2 ---- spine0.Ethernet8-11.11.12.1   #
#                                                                  #
####################################################################
def test_l3vni_basic_config():

    vars = st.get_testbed_vars()
    #import pdb; pdb.set_trace()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            setup_node(nodes[node], config['sonic'], '')
            setup_node(nodes[node], config['bgp'], 'vtysh')

    count = 5
    st.show(nodes['leaf0'], "sudo ping -c {} {} -q".format(count, '11.11.11.1'))
    st.show(nodes['leaf1'], "sudo ping -c {} {} -q".format(count, '11.11.12.1'))

    
    
#    # Configure Leaf0
#    leaf0_cfg = '''
#    sudo config interface startup Ethernet0
#    sudo config interface startup Ethernet16
#    sudo config interface startup Ethernet32
#    sudo config interface ipv6 enable use-link-local-only Ethernet0
#    sudo config interface ipv6 enable use-link-local-only Ethernet16
#    sudo config interface ipv6 enable use-link-local-only Ethernet32
#    sudo config interface ipv6 disable use-link-local-only Ethernet0
#    sudo config loopback add Loopback0
#    sudo config interface ip add Loopback0 10.200.200.200/32
#    sudo config vlan add 2
#    sudo config vlan member add -u 2 Ethernet0
#    sudo config vxlan add VXLAN 10.200.200.200
#    sudo config vxlan evpn_nvo add NVO VXLAN
#    sudo config vlan add 100
#    sudo config vrf add Vrf01
#    sudo config interface vrf bind Vlan2 Vrf01
#    sudo config interface vrf bind Vlan100 Vrf01
#    sudo config vxlan map add VXLAN 100 1000
#    sudo config vrf add_vrf_vni_map Vrf01 1000
#    sudo config interface ip add Vlan2 100.100.100.254/24
#    '''
#    #commands = leaf0_cfg.splitlines()
#    #st.config(leaf0, commands)
#
#    bgpapi.config_bgp(leaf0, router_id='10.200.200.200', local_as=65100, config='yes')
#    '''
#    router bgp 65100
#    bgp router-id 10.200.200.200
#    no bgp ebgp-requires-policy
#    '''
#
#    '''
#    no bgp default ipv4-unicast
#    neighbor SERVICE peer-group
#    neighbor SERVICE remote-as internal
#    '''
#
#    #bgpapi.config_bgp(leaf0, router_id='10.200.200.200', local_as=65100, config='yes', neighbor='10.200.200.201',
#    #                  remote_as='internal', peergroup='SERVICE', config_type_list=['peergroup'])
#
#    bgpapi.create_bgp_peergroup(leaf0, local_asn=65100, peer_grp_name='SERVICE',
#                                remote_asn='internal', neighbor_ip='10.200.200.201', update_src_intf='Loopback0',
#                                vrf='default', family='ipv4', skip_error_check=False)
#
#    '''
#    neighbor SERVICE peer-group
#    neighbor SERVICE remote-as internal
#    neighbor 10.200.200.201 peer-group SERVICE
#    '''
#
#    #bgpapi.config_bgp(leaf0, router_id='10.200.200.200', local_as=65100, config='yes', neighbor='10.200.200.202',
#    #                  remote_as='internal', peergroup='SERVICE', config_type_list=['peergroup'])
#    bgpapi.create_bgp_peergroup(leaf0, local_asn=65100, peer_grp_name='SERVICE',
#                                remote_asn='internal', neighbor_ip='10.200.200.202', update_src_intf='Loopback0',
#                                vrf='default', family='ipv4', skip_error_check=False)
#
#    '''
#    neighbor 10.200.200.202 peer-group SERVICE
#    '''
#
#    #bgpapi.config_bgp(leaf0, router_id='10.200.200.200', local_as=65100, config='yes', neighbor='SERVICE',
#    #                  update_src ='Loopback0', config_type_list=["update_src"])
#    '''
#    neighbor SERVICE update-source Loopback0
#    '''
#
#    #bgpapi.config_bgp(leaf0, router_id='10.200.200.200', local_as=65100, config='yes', remote_as='internal',
#    #                  peergroup='TRANSIT', config_type_list=['peergroup', 'bfd'])
#    bgpapi.create_bgp_peergroup(leaf0, local_asn=65100, peer_grp_name='TRANSIT',
#                                remote_asn='internal', neighbor_ip='10.200.200.202', update_src_intf='Loopback0',
#                                vrf='default', family='ipv4', skip_error_check=False, bfd=True,
#                                neighbor_intfs=['Ethernet16', 'Ethernet32'])
#    '''
#    neighbor TRANSIT peer-group
#    neighbor TRANSIT bfd
#    neighbor TRANSIT remote-as internal
#    '''
#
#    #bgpapi.config_bgp(leaf0, router_id='10.200.200.200', local_as=65100, config='yes', remote_as='internal',
#    #                  interface='Ethernet16', neighbor='Ethernet16', peergroup='TRANSIT', config_type_list=['peergroup'])
#                      
#    #bgpapi.config_bgp(leaf0, router_id='10.200.200.200', local_as=65100, config='yes', remote_as='internal',
#    #                  interface='Ethernet32', neighbor='Ethernet32', peergroup='TRANSIT', config_type_list=['peergroup'])
#
#    '''
#    neighbor Ethernet16 interface peer-group TRANSIT
#    neighbor Ethernet32 interface peer-group TRANSIT
#    '''
#
#    #bgpapi.create_bgp_peergroup(leaf0, local_asn=65100, peer_grp_name='TRANSIT', remote_asn='internal',
#    #                            vrf='default', family='ipv4', skip_error_check=False)
#    #bgpapi.config_address_family_redistribute(leaf0, local_asn=65100, mode_type='l2vpn',
#    #                                          mode='evpn', value='connected', peer_group='SERVICE')
#    l2vpn_evpn_cmd = '''
#    router bgp 65100
#    address-family l2vpn evpn
#    neighbor SERVICE activate
#    advertise-all-vni
#    advertise ipv4 unicast
#    '''
#    st.config(leaf0,l2vpn_evpn_cmd, type='vtysh', skip_error_check=False, conf=True) 
#    
#    bgpapi.config_address_family_redistribute(leaf0, local_asn=65100, mode_type='ipv4',
#                                              mode='unicast', value='connected', peer_group='TRANSIT')
#    '''
#    address-family ipv4 unicast
#    redistribute connected
#    neighbor TRANSIT activate
#    '''
#
#    l3_vrf_vni = '''
#    vrf Vrf01
#    vni 1000
#    exit
#    '''
#    st.config(leaf0,l3_vrf_vni, type='vtysh', skip_error_check=False, conf=True) 
#
#    '''
#    router bgp 65100 vrf Vrf01
#    address-family ipv4 unicast
#    redistribute connected
#    exit-address-family
#    address-family l2vpn evpn
#    advertise ipv4 unicast
#    exit-address-family
#    exit
#    exit
#    exit
#    '''
#
#    # Configure Leaf1
#    leaf1_cfg = '''
#    sudo config hostname LEAF1
#    sudo config interface startup Ethernet0
#    sudo config interface startup Ethernet16
#    sudo config interface startup Ethernet32
#    sudo config interface ipv6 enable use-link-local-only Ethernet0
#    sudo config interface ipv6 enable use-link-local-only Ethernet16
#    sudo config interface ipv6 enable use-link-local-only Ethernet32
#    sudo config interface ipv6 disable use-link-local-only Ethernet0
#    sudo config loopback add Loopback0
#    sudo config interface ip add Loopback0 10.200.200.201/32
#    sudo config vlan add 3
#    sudo config vlan member add -u 3 Ethernet0
#    sudo config vxlan add VXLAN 10.200.200.201
#    sudo config vxlan evpn_nvo add NVO VXLAN
#    sudo config vlan add 100
#    sudo config vrf add Vrf01
#    sudo config interface vrf bind Vlan3 Vrf01
#    sudo config interface vrf bind Vlan100 Vrf01
#    sudo config vxlan map add VXLAN 100 1000
#    sudo config vrf add_vrf_vni_map Vrf01 1000
#    sudo config interface ip add Vlan3 100.100.101.254/24
#    '''
#    #commands = leaf1_cfg.splitlines()
#    #st.config(leaf1, commands)
#
#    setup_spines(spine0)
#    st.report_pass("test_case_passed")
#
