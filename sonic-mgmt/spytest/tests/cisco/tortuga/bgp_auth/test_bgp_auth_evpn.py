import os
import time
import yaml
import pytest
import bgp_auth_utils as bgp_auth_object
from spytest import st

CONFIGS_FILE = 'bgp_auth_evpn_cfg.yaml'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

##
## config: eBGP + ECMP
##  Topology : 1 Spine + 2 Leafs + 1 external router connected to leaf0
##
##  D1 -- Spine0  
##  D2 -- external(Spine1 is used as exteral router connected to Leaf0) 
##  D3 -- Leaf0  
##  D4 -- Leaf1   

def config_static(node, config_domain, vrf_bgp = False, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if not vrf_bgp:
            if add:
                config_node(nodes[node], config_list[node][config_domain]['config'], domain)
            else:
                config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)
        else:    
            if add:
                if 'config_vrf' in config_list[node][config_domain]:
                    config_node(nodes[node], config_list[node][config_domain]['config_vrf'], domain)
            else:
                if 'deconfig_vrf' in config_list[node][config_domain]:
                    config_node(nodes[node], config_list[node][config_domain]['deconfig_vrf'], domain)
                    
def report_fail(msg=''):
    st.banner(msg) 
    st.report_fail('test_case_failed')

@pytest.fixture(scope="module", autouse=True)
def setup_teardown_bgp_auth():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    global updated_config_file
    updated_config_file = bgp_auth_object.modify_config_file(CONFIGS_FILE,vars)


    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            # Disabling drake so that there are no automatic underlay configs
            # Check drake agent is running before disabling it.
            cmd = 'systemctl status drake'
            cmd_output = st.config(nodes[node], cmd)
            if "active (running)" in str(cmd_output.encode('ascii','ignore')):
                st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
                st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)

            config_static(node, 'sonic')
            config_static(node, 'bgp')
    st.wait(60)

    yield 'setup_teardown_bgp_auth'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)
            
    ### Remove the temp config file after the test ###        
    bgp_auth_object.remove_temp_config(updated_config_file)

@pytest.fixture(scope="function")  
def setup_custormer_vrf():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
           
            config_static(node, 'sonic', vrf_bgp = True)
            config_static(node, 'bgp', vrf_bgp = True)
    st.wait(60)

    yield 'setup_teardown_bgp_auth'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', vrf_bgp = True, add=False)
            config_static(node, 'sonic', vrf_bgp = True, add=False)
    
    
######################################################################
# Test Cases
######################################################################

# testcase #0: To verify bgp peer establish with matched password
def test_peer_established():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    bgp_underlay = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')

    if bgp_underlay and bgp_overlay:
        st.report_pass('test_case_passed')    
    else:
        st.report_fail('test_case_failed') 
       
# testcase #1: To verify only OVERLAY bgp peer will be down after OVERLAY password is removed from one end
def test_peer_remove_password_overlay():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    #remove neighbor password of OVERLAY peer group in leaf0
    cmds = ['router bgp 2363073663',
           'no neighbor OVERLAY password overlay',
           'exit']
    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)
    time.sleep(60)

    #validate OVERLAY neighbors are down and TRANSIT neighbors are still up
    bgp_underlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    #add back neighbor password of OVERLAY peer group in leaf0
    cmds = ['router bgp 2363073663',
           'neighbor OVERLAY password overlay',
           'exit']
    
    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)
    time.sleep(60)
    
    #validate both TRANSIT and OVERLAY neighbors recover
    bgp_underlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    #output report
    if bgp_overlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_before\' status.')
    if not bgp_underlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_before\' status.')
    if not bgp_overlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_after\' status.')
    if not bgp_underlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_after\' status.')
    st.report_pass('test_case_passed')

# testcase #2: To verify both OVERLAY and TRANSIT bgp peer will be down after TRANSIT password is removed from one end 
def test_peer_remove_password_transit():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4        
        
    #remove neighbor password of TRANSIT peer group in leaf0
    cmds = ['router bgp 2363073663',
           'no neighbor TRANSIT password transit',
           'exit']
    
    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)    
    time.sleep(180)  
   
    #validate both OVERLAY neighbors and TRANSIT neighbors are down
    bgp_underlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    #add back neighbor password of TRANSIT peer group in leaf0
    cmds = ['router bgp 2363073663',
           'neighbor TRANSIT password transit',
           'exit']
    
    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)
        
    time.sleep(60)
    
    #validate both TRANSIT and OVERLAY neighbors recover
    bgp_underlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
          
    #output report
    if bgp_underlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_before\' status.')
    if bgp_overlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_before\' status.')
    if not bgp_underlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_after\' status.')
    if not bgp_overlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_after\' status.')
    st.report_pass('test_case_passed')
   

# testcase #3: To verify only OVERLAY bgp peer will be down after OVERLAY password is changed from one end
def test_peer_change_password_overlay():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    #change neighbor password of OVERLAY peer group in leaf0
    cmds = ['router bgp 2363073663',
           'neighbor OVERLAY password overlay_wrong',
           'exit']
    
    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)
    time.sleep(60)
    
    #validate both TRANSIT and OVERLAY neighbors are down 
    bgp_underlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')

    #add back neighbor password of OVERLAY peer group in leaf0
    cmds = ['router bgp 2363073663',
           'neighbor OVERLAY password overlay',
           'exit']
    
    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)
    time.sleep(60)
    
    #validate both TRANSIT and OVERLAY neighbors recover
    bgp_underlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
          
    #output report
    if bgp_overlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_before\' status.')
    if not bgp_underlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_before\' status.')
    if not bgp_overlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_after\' status.')
    if not bgp_underlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_after\' status.')
    st.report_pass('test_case_passed')
    
# testcase #4: To verify both OVERLAY and TRANSIT bgp peer will be down after TRANSIT password is changed from one end
def test_peer_change_password_transit():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    #change neighbor password of TRANSIT peer group in leaf0
    cmds = ['router bgp 2363073663',
        'neighbor TRANSIT password transit_wrong',
        'exit']

    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)
    time.sleep(180)  
        
    #validate both OVERLAY neighbors and UNDERLAY neighbors are down
    bgp_underlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    #add back neighbor password of TRANSIT peer group in leaf0
    cmds = ['router bgp 2363073663',
        'neighbor TRANSIT password transit',
        'exit']
    
    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)
    time.sleep(60)
    
    #validate both TRANSIT and OVERLAY neighbors recover   
    bgp_underlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
        
    #output report
    if bgp_underlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_before\' status.')
    if bgp_overlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_before\' status.')
    if not bgp_underlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_after\' status.')
    if not bgp_overlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_after\' status.')
    st.report_pass('test_case_passed')
        
# testcase #5: To verify bgp peer will recover after interface flaps
def test_bgp_interface_flap():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    #shutdown D3D1P1 on leaf0
    cmd = 'sudo config interface shutdown ' + vars.D3D1P1
    st.config(nodes['leaf0'], cmd)
    time.sleep(300)

    bgp_underlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT', neighbor = vars.D3D1P1)
    bgp_overlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')  

    #no shutdown D3D1P1 on leaf0 
    cmd = 'sudo config interface startup ' + vars.D3D1P1
    st.config(nodes['leaf0'], cmd)

    time.sleep(60)  
    bgp_underlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT', neighbor = vars.D3D1P1)
    bgp_overlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    
    if bgp_underlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_before\' status.')
    if bgp_overlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_before\' status.')
    if not bgp_underlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_after\' status.')
    if not bgp_overlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_after\' status.') 
    st.report_pass('test_case_passed')
        

# testcase #6: To verify bgp status with unmatched MTU 
def test_wrong_mtu():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    #set mtu for leaf0 to 100 (default 9100)
    cmd = 'sudo config interface mtu ' + vars.D3D1P1 + ' 100'
    st.config(nodes['leaf0'], cmd)
    time.sleep(300) 
    bgp_underlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')

    #set mtu for leaf0 back to 9100
    cmd = 'sudo config interface mtu ' + vars.D3D1P1 + ' 9100'
    st.config(nodes['leaf0'], cmd)
    time.sleep(60)  
    bgp_underlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    if bgp_underlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_before\' status.') 
    if bgp_overlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_before\' status.') 
    if not bgp_underlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_after\' status.') 
    if not bgp_overlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_after\' status.')  
    st.report_pass('test_case_passed')
           
# testcase #7 To verify bgp status after bgp hard reset 
def test_bgp_reset():
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    cmd = 'clear bgp *'
    st.vtysh_show(nodes['leaf0'], cmd)
    st.vtysh_show(nodes['spine0'], cmd)
    
    bgp_underlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_before = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    time.sleep(60)

    bgp_underlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'TRANSIT')
    bgp_overlay_after = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'OVERLAY')
    
    if bgp_underlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_before\' status.') 
    if bgp_overlay_before:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_before\' status.') 
    if not bgp_underlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_underlay_after\' status.') 
    if not bgp_overlay_after:
        report_fail('The test case failed due to an incorrect \'bgp_overlay_after\' status.') 
    st.report_pass('test_case_passed')
        
# testcase #8  test externally provisioned BGP session (from customer VRF) 
def test_vrf_bgp(setup_custormer_vrf):
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['external'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    bgp_vrf = bgp_auth_object.check_neigh_state(nodes['leaf0'], 'CUSTOMER', 'Vrf01')
    if bgp_vrf:
        st.report_pass('test_case_passed')   
    else:
        st.report_fail('test_case_failed') 
    