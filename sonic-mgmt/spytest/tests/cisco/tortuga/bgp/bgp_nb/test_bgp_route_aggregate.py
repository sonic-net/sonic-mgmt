import os
import time
import yaml
import pytest
import sys
import re
from spytest import st
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(script_dir, '../common/'))

import tortuga_common_utils as common_obj

CONFIGS_FILE = 'bgp_ag_base_cfg.yaml'

vars
nodes = {}

####################
#                  #
#    D1 = spine0   #
#    D2 = spine1   #
#    D3 = leaf0    #
#    D4 = leaf1    #
#                  #
####################

@pytest.fixture(scope="module", autouse=True)
def setup_teardown_bgp_route_aggr():
    vars = st.get_testbed_vars()

    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    update_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE, vars)

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'bgp', True, update_path)
            common_obj.config_static(node, 'sonic', True, update_path)

    count = 5    
    st.show(nodes['spine0'], 'sudo ping -c {} {} -q'.format(count, '10.1.1.2'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_bgp_route_aggr'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'bgp', False, update_path)
            common_obj.config_static(node, 'sonic', False, update_path)

#########################################
# Testcases
#########################################
def test_bgp_ra_session_establish():
    retries = 4;

    cmd = 'show bgp neighbor 10.1.1.2'

    for attempt in range(retries):
        parsed_output = st.vtysh_show(nodes['spine0'], cmd)

        if not parsed_output:
            st.report_fail("test_case_failed", nodes['spine0'])

        if parsed_output[0]['state'] != 'Established':
            st.log("BGP peer is still not UP, wait for 30s")
            time.sleep(30)
        else:
            break

    if parsed_output[0]['state'] != 'Established':
        st.report_fail("test_case_failed", nodes['spine0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_ra_summary_only():

    st.log("Verify 192.168.1.3/32 lo addressed is advertised to leaf0")
    cmd = 'show ip bgp'
    cmd_output = st.vtysh_show(nodes['leaf0'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    if '*> 192.168.1.3/32' not in cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.log("Verify route-aggregate summary route only adevrtised to BGP peer")
    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'aggregate-address 192.168.1.0/24 summary-only']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    cmd = 'show ip bgp'
    cmd_output = st.vtysh_show(nodes['leaf0'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    prefix_found = False
    ag_route = False
    if  '*> 192.168.1.3/32' in cmd_output:
        prefix_found = True
    if '*> 192.168.1.0/24' in cmd_output:
        ag_route = True

    if ((prefix_found == False) and (ag_route == True)):
        st.log("BGP route aggregate is advertised")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'no aggregate-address 192.168.1.0/24 summary-only']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_ra_summary_as_set():

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'aggregate-address 192.168.2.0/24 as-set summary-only']


    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    cmd = 'show ip bgp'
    cmd_output = st.vtysh_show(nodes['leaf0'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    match_pattern = r'\*> 192\.168\.2\.0\/24\s+10\.1\.1\.1\s+0\s+0\s+1001\s+400\s+\?'

    if re.search(match_pattern, cmd_output):
        st.log("Prefix 192.168.2.0/24 is with AS path 1001 400")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'no aggregate-address 192.168.2.0/24 as-set summary-only']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_ra_matching_MED():

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'aggregate-address 192.168.1.0/24 summary-only matching-MED-only',
            'aggregate-address 192.168.3.0/24 summary-only matching-MED-only']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    cmd = 'show ip bgp'
    cmd_output = st.vtysh_show(nodes['leaf0'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    med_prefix_found = False
    non_med_prefix = False
    if '*> 192.168.1.0/24' in cmd_output:
        med_prefix_found = True
    if '*> 192.168.3.0/24' in cmd_output:
        non_med_prefix = True

    if ((med_prefix_found == True) and (non_med_prefix == False)):
        st.log("Non matching MED is not aggregated")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'no aggregate-address 192.168.1.0/24 summary-only matching-MED-only',
            'no aggregate-address 192.168.3.0/24 summary-only matching-MED-only']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_ra_origin():

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'aggregate-address 192.168.1.0/24 origin egp']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    cmd = 'show ip bgp 192.168.1.0/24'
    cmd_output = st.vtysh_show(nodes['leaf0'], cmd, skip_tmpl=True, skip_error_check=False)

    if 'Origin EGP' not in cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'no aggregate-address 192.168.1.0/24 origin egp']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_ra_add_route_map():

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'aggregate-address 192.168.1.0/24 summary-only route-map AGG_ROUTE_MAP']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    cmd = 'show ip bgp'
    cmd_output = st.vtysh_show(nodes['leaf0'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    match_pattern = r'\*> 192\.168\.1\.0\/24\s+10\.1\.1\.1\s+10'
    if re.search(match_pattern, cmd_output):
        st.log("Found 192.168.1.0/24 prefix with metric 10")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'no aggregate-address 192.168.1.0/24 summary-only route-map AGG_ROUTE_MAP']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_ra_add_supp_map():

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'aggregate-address 192.168.1.0/24 suppress-map SUP_RM']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    cmd = 'show ip bgp'
    cmd_output = st.vtysh_show(nodes['leaf0'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    if cmd_output in '192.168.1.4/24':
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['router bgp 1001',
            'address-family ipv4 unicast',
            'no aggregate-address 192.168.1.0/24 suppress-map SUP_RM']

    for cmd in cmds:
        st.vtysh_config(nodes['spine0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['leaf0'])
