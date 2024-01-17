import pytest
from spytest import st
import apis.system.box_services as boxserv_obj

##
## config based on : /auto/vxr1/sonic-images/jeflo/l2vni/
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD1 -- Spine1  - D2
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##

config         = {     "SD1 sonic" : """sudo config ipv6 enable link-local
                                        sudo config interface startup Ethernet0
                                        sudo config interface startup Ethernet16""" 
                        ,
                        "SD1 vtysh" : """configure terminal
                                        router bgp 65100
                                        bgp router-id 10.200.200.10
                                        no bgp ebgp-requires-policy
                                        no bgp default ipv4-unicast
                                        neighbor TRANSIT peer-group
                                        neighbor TRANSIT remote-as internal
                                        neighbor TRANSIT bfd
                                        neighbor Ethernet0 interface peer-group TRANSIT
                                        neighbor Ethernet16 interface peer-group TRANSIT
                                        address-family ipv4 unicast
                                        neighbor TRANSIT activate
                                        neighbor TRANSIT route-reflector-client
                                        exit
                                        exit
                                        exit
                                        exit"""
                        ,
                        "SD2 sonic" : """sudo config ipv6 enable link-local
                                        sudo config interface startup Ethernet0
                                        sudo config interface startup Ethernet16""" 
                        ,
                        "SD2 vtysh" : """configure terminal
                                        router bgp 65100
                                        bgp router-id 10.200.200.11
                                        no bgp ebgp-requires-policy
                                        no bgp default ipv4-unicast
                                        neighbor TRANSIT peer-group
                                        neighbor TRANSIT remote-as internal
                                        neighbor TRANSIT bfd
                                        neighbor Ethernet0 interface peer-group TRANSIT
                                        neighbor Ethernet4 interface peer-group TRANSIT
                                        address-family ipv4 unicast
                                        neighbor TRANSIT activate
                                        neighbor TRANSIT route-reflector-client
                                        exit
                                        exit
                                        exit
                                        exit""" 
                        ,
                        "SD3 sonic" : """sudo config interface ipv6 enable use-link-local-only Ethernet0
                                        sudo config interface ipv6 enable use-link-local-only Ethernet16
                                        sudo config interface startup Ethernet0
                                        sudo config interface startup Ethernet16
                                        sudo config interface startup Ethernet32
                                        sudo config loopback add Loopback0
                                        sudo config interface ip add Loopback0 10.200.200.200/32
                                        sudo config vlan add 2
                                        sudo config vlan member add -u 2 Ethernet32
                                        sudo config vxlan add VXLAN 10.200.200.200
                                        sudo config vxlan evpn_nvo add NVO VXLAN
                                        sudo config vxlan map add VXLAN 2 5002""" 
                        ,
                        "SD3 vtysh" : """configure terminal
                                        router bgp 65100
                                        bgp router-id 10.200.200.200
                                        no bgp ebgp-requires-policy
                                        no bgp default ipv4-unicast
                                        neighbor SERVICE peer-group
                                        neighbor SERVICE remote-as internal
                                        neighbor SERVICE update-source Loopback0
                                        neighbor 10.200.200.201 peer-group SERVICE
                                        neighbor TRANSIT peer-group
                                        neighbor TRANSIT bfd
                                        neighbor TRANSIT remote-as internal
                                        neighbor Ethernet0 interface peer-group TRANSIT
                                        neighbor Ethernet16 interface peer-group TRANSIT
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
                                        exit
                                        exit"""
                        ,
                        "SD4 sonic" : """sudo config interface ipv6 enable use-link-local-only Ethernet0
                                        sudo config interface ipv6 enable use-link-local-only Ethernet16
                                        sudo config interface startup Ethernet0
                                        sudo config interface startup Ethernet16
                                        sudo config interface startup Ethernet32
                                        sudo config loopback add Loopback0
                                        sudo config interface ip add Loopback0 10.200.200.201/32
                                        sudo config vlan add 2
                                        sudo config vlan member add -u 2 Ethernet32
                                        sudo config vxlan add VXLAN 10.200.200.201
                                        sudo config vxlan evpn_nvo add NVO VXLAN
                                        sudo config vxlan map add VXLAN 2 5002""" 
                        ,
                        "SD4 vtysh" : """configure terminal
                                        router bgp 65100
                                        bgp router-id 10.200.200.201
                                        no bgp ebgp-requires-policy
                                        no bgp default ipv4-unicast
                                        neighbor SERVICE peer-group
                                        neighbor SERVICE remote-as internal
                                        neighbor SERVICE update-source Loopback0
                                        neighbor 10.200.200.200 peer-group SERVICE
                                        neighbor TRANSIT peer-group
                                        neighbor TRANSIT bfd
                                        neighbor TRANSIT remote-as internal
                                        neighbor Ethernet0 interface peer-group TRANSIT
                                        neighbor Ethernet16 interface peer-group TRANSIT
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
                                        exit
                                        exit"""
                }


pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    #vars = st.ensure_min_topology("D1T1:2")
    #dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    #vars = st.ensure_min_topology("D1", "D2", "D3", "D4")
    vars = st.ensure_min_topology("D1D3:4","D1D4:4","D2D3:4","D2D4:4")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass


def config_sonic(_dut):
    global config
    for sonic_config_line in config[_dut + " sonic"].splitlines():
        st.config(_dut, sonic_config_line.strip(),skip_error_check=True)
        st.wait(2)
        
def config_vtysh(_dut):
    global config
    for vty_config_line in config[_dut + " vtysh"].splitlines():

        st.log(vty_config_line.strip(), _dut)
        st.config(_dut, vty_config_line.strip(), type='vtysh',skip_error_check=True)
        st.wait(2)
 
    output4=st.vtysh(_dut, "show running")
    st.log(output4,_dut)
   
def verify_vtep_state (_dut_list):
    
    # Test 1: Verify if the State is UP - oper_up 
    for _dut in _dut_list:
        output = st.config(_dut, "show vxlan remotevtep | grep oper_up")
        st.wait(2)
        st.log(output,_dut)

        if "EVPN" in str(output.encode('ascii','ignore')):
            st.log("EVPN State oper_up UP", _dut)
        else:
            st.log("EVPN State Error: NOT oper_up",_dut)
            st.error("EVPN State Error: NOT oper_up",_dut)
            st.report_fail("test_case_failed",_dut)
        st.report_pass("test_case_passed", _dut)   
    
    ## Test 2: verification vtep SIP-DIP Pair on leaf0 - D3
    """
    root@sonic:/home/cisco# show vxlan remotevtep
    +----------------+----------------+-------------------+--------------+
    | SIP            | DIP            | Creation Source   | OperStatus   |
    +================+================+===================+==============+
    | 10.200.200.200 | 10.200.200.201 | EVPN              | oper_up      |
    +----------------+----------------+-------------------+--------------+
    """
    
    _dut = _dut_list[0]
    leaf0_output = st.config(_dut, "show vxlan remotevtep | grep oper_up")
    st.wait(2)
    
    if  ".200 | 10." in str(leaf0_output.encode('ascii','ignore')):
        st.log("Leaf0 SIP DIP Pair is matched", _dut)
    else:
        st.log("Leaf0 SIP DIP Pair is NOT matchedy",_dut)
        st.error("Leaf0 SIP DIP Pair is NOT matched",_dut)
        st.report_fail("test_case_failed",_dut)
    st.report_pass("test_case_passed", _dut)
    
    # Test 3: Verify SIP and DIP Pair on Leaf1 D4
    ## verification vtep on leaf1 - D4
    """
    root@sonic:/home/cisco# show vxlan remotevtep
    +----------------+----------------+-------------------+--------------+
    | SIP            | DIP            | Creation Source   | OperStatus   |
    +================+================+===================+==============+
    | 10.200.200.201 | 10.200.200.200 | EVPN              | oper_up      |
    +----------------+----------------+-------------------+--------------+
    Total count : 1
    root@sonic:/home/cisco# 
    """
    
    _dut = _dut_list[1] 
    leaf1_output = st.config(_dut, "show vxlan remotevtep | grep oper_up")
    st.wait(2)
    
    if  ".201 | 10" in str(leaf1_output.encode('ascii','ignore')):
        st.log("Leaf1 SIP DIP Pair is matched", _dut)
    else:
        st.log("Leaf1 SIP DIP Pair is NOT matched",_dut)
        st.error("Leaf1 SIP DIP Pair is NOT matched",_dut)
        st.report_fail("test_case_failed",_dut)
    st.report_pass("test_case_passed", _dut)  
    

def test_vtep_cli ():
    vars = st.get_testbed_vars()    
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]

    for dut in dut_list:
        st.banner('Configure Sonic') 
        config_sonic(dut)
        st.wait(10)
        st.banner('Configure Vtysh') 
        config_vtysh(dut)
        st.wait(10)

    st.wait(30)

    # Test1: Verify Vtep State for L0 and L1
    vtep_vars = [vars.D3, vars.D4]
    verify_vtep_state (vtep_vars)
    #for dut in dut_list:
    #    st.banner('clear configs')
    #    st.clear_config(dut)
    #    st.wait(20)
 
