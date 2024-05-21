import os
import time
import yaml
import json
import pytest
from spytest import st
import utilities.utils as utils_obj
import vxlan_utils as vxlan_obj

# TODO: Parameterize the configs. For now, use static configs
CONFIGS_FILE = 'bgp_bfd_evpn_configs.yaml'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_l3vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            config_static(node, 'bgp')

    yield 'setup_teardown_l3vni'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)

def test_bgp_bfd_evpn():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    peer = {}
    peer['leaf0'] = '10.200.200.201'
    peer['leaf1'] = '10.200.200.200'

    # sleep for 60 seconds for BGP to converge
    time.sleep(60)

    # Start Verification

    for node in nodes:
        cmd_output = st.show(nodes[node], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
        print("************************"+node+" bfdd output************************")
        print(cmd_output)
        js = json.loads(cmd_output[:cmd_output.rfind(']')+1])
        print(js)
        # Expectng bfd session is UP
        if len(js) < 1:
            report_fail(nodes[node], msg='no bfd sessions found')
        else: 
            for bs in js:
                if bs["status"] != "up":
                    report_fail(nodes[node], msg='bfd session is not up')

        cmd_output = st.show(nodes[node], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
        print("************************"+node+" bgp sum json************************")
        print(cmd_output)
        js = json.loads(cmd_output[:cmd_output.rfind('}')+1])
        print(js)
        if 'l2VpnEvpn' not in js:
            report_fail(nodes[node], msg='l2VpnEvpn is no in bgp')
        if 'l2VpnEvpn' in js:
            if js['l2VpnEvpn']['peers'][peer[node]]['state'] != 'Established':
                report_fail(nodes[node], msg='bgp neighbor is not Established')

    print("************************shutdown interface in leaf1************************")
    st.config(nodes['leaf1'], 'sudo config interface shutdown '+ vars.D4D1P1, sudo=False, split_cmds=False)
    st.config(nodes['leaf1'], 'sudo config interface shutdown '+ vars.D4D2P1, sudo=False, split_cmds=False)

    time.sleep(3)

    bgp0_output = st.show(nodes['leaf0'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    bfd0_output = st.show(nodes['leaf0'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)

    print("************************leaf0 bfdd output************************")
    print(bfd0_output)
    js = json.loads(bfd0_output[:bfd0_output.rfind(']')+1])
    print(js)
    # Expecting bfd session is DOWN
    if len(js) < 1:
        report_fail(nodes['leaf0'], msg='no bfd sessions found')
    else: 
        for bs in js:
            if bs['peer'] == '10.200.200.201' and bs["status"] != "down":
                report_fail(nodes['leaf0'], msg='bfd session (10.200.200.201) is not down')

    print("************************leaf0 bgp sum json************************")
    print(bgp0_output)
    js = json.loads(bgp0_output[:bgp0_output.rfind('}')+1])
    print(js)
    if 'l2VpnEvpn' not in js:
        report_fail(nodes['leaf0'], msg='l2VpnEvpn is no in bgp')
    if 'l2VpnEvpn' in js:
        if js['l2VpnEvpn']['peers']['10.200.200.201']['state'] == 'Established':
            report_fail(nodes['leaf0'], msg='10.200.200.201 is Established after shutdown interfaces in peer system')

    print("************************startup interface in leaf1************************")
    st.config(nodes['leaf1'], 'sudo config interface startup '+ vars.D4D1P1, sudo=False, split_cmds=False)
    st.config(nodes['leaf1'], 'sudo config interface startup '+ vars.D4D2P1, sudo=False, split_cmds=False)
    st.config(nodes['leaf0'], 'ping -c 3 10.200.200.201 ', sudo=False, split_cmds=False)
    time.sleep(5)

    for node in nodes:
        cmd_output = st.show(nodes[node], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
        print("************************"+node+" bfdd output************************")
        print(cmd_output)
        js = json.loads(cmd_output[:cmd_output.rfind(']')+1])
        print(js)
        # Expectng bfd session is UP
        if len(js) < 1:
            report_fail(nodes[node], msg='no bfd sessions found')
        else: 
            for bs in js:
                if bs["status"] != "up":
                    report_fail(nodes[node], msg='bfd session is not up after interface noshut')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

