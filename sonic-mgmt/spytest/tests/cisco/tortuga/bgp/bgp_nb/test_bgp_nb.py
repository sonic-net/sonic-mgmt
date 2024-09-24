import os
import time
import yaml
import pytest
import sys
from spytest import st
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(script_dir, '../common/'))

import tortuga_common_utils as common_obj

vars = {}
nodes = {}

CONFIGS_FILE = 'bgp_nb_base_cfg.yaml'

####################
#                  #
#    D1 = spine0   #
#    D2 = spine1   #
#    D3 = leaf0    #
#    D4 = leaf1    #
#                  #
####################

def config_static(node, config_domain, add, config_file):
    vars = st.get_testbed_vars()

    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    sub_intf_dict = {
        'cmono': {
            'SUB_D1_D3_P1': 'Eth1_1',
            'SUB_D1_D3_P2': 'Eth1_2',
            'SUB_D2_D3_P1': 'Eth1_1',
            'SUB_D2_D3_P2': 'Eth1_2',
            'SUB_D3_D1_P1': 'Eth1_1',
            'SUB_D3_D1_P2': 'Eth1_2',
            'SUB_D3_D2_P5': 'Eth1_5',
            'SUB_D3_D2_P6': 'Eth1_6'
        },
        'mathilda': {
            'SUB_D1_D3_P1': 'Eth0',
            'SUB_D1_D3_P2': 'Eth4',
            'SUB_D2_D3_P1': 'Eth0',
            'SUB_D2_D3_P2': 'Eth4',
            'SUB_D3_D1_P1': 'Eth0',
            'SUB_D3_D1_P2': 'Eth4',
            'SUB_D3_D2_P5': 'Eth16',
            'SUB_D3_D2_P6': 'Eth20'
        }
    }

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            type = 'config'
        else:
            type = 'deconfig'

        # Below work around will be taken out when infra support sub-interface in dict
        if vars.D1D3P1 == 'Ethernet1_1':
            for sub_intf_name, sub_intf in sub_intf_dict['cmono'].items():
                config_list[node][config_domain][type] = config_list[node][config_domain][type].replace(sub_intf_name, sub_intf)
        elif vars.D1D3P1 == 'Ethernet0':
            for sub_intf_name, sub_intf in sub_intf_dict['mathilda'].items():
                config_list[node][config_domain][type] = config_list[node][config_domain][type].replace(sub_intf_name, sub_intf)

        common_obj.config_node(nodes[node], config_list[node][config_domain][type], domain)

@pytest.fixture(scope="module", autouse=True)
def setup_teardown_bgp_nb():
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
            config_static(node, 'bgp', True, update_path)
            config_static(node, 'sonic', True, update_path)

    yield 'setup_teardown_bgp_nb'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', False, update_path)
            config_static(node, 'sonic', False, update_path)


#########################################
# Testcases
#########################################
def test_bgp_nb_sub_interface_is_reachable():

    st.log("check ping is working for IPv4 and IPv6 address configured on sub-interface of DUT")

    data = [("Vrf01", "10.1.1.2"), ("Vrf01", "2001:db1::2"), ("Vrf01", "10.1.2.2"), ("Vrf01", "2001:db2::2"),
            ("Vrf02", "10.1.1.2"), ("Vrf02", "2001:db1::2"), ("Vrf02", "10.1.2.2"), ("Vrf02", "2001:db2::2"),
            ("Vrf03", "10.1.1.2"), ("Vrf03", "2001:db1::2"), ("Vrf03", "10.1.2.2"), ("Vrf03", "2001:db2::2")]

    for vrf, ip in data:
        cmd = 'ping -I {} -c 5 {}'.format(vrf, ip)
        cmd_output = st.config(nodes['leaf0'], cmd)
        if "0% packet loss" in str(cmd_output.encode('ascii','ignore')):
            st.log("Ping to vrf {} IP {} sub-interface is Successful".format(vrf, ip))
        else:
            st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def get_bgp_neighbor_state(neigh, node, vrf=""):

    if vrf != "":
        cmd = 'show bgp vrf {} neighbor {}'.format(vrf, neigh)
    else:
        cmd = 'show bgp neighbor{}'.format(neigh)

    cmd_output = st.vtysh_show(nodes[node], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes[node])

    if "BGP state = Established" in cmd_output:
        return 'Established'

def test_bgp_nb_sub_interface_bgp_sess():

    st.log("check BGP sessions are UP with ip address configured on sub-interface")

    data = [('10.1.1.2', 'leaf0', "Vrf01"), ('10.1.2.2', 'leaf0', "Vrf01"), ('2001:db1::2', 'leaf0', "Vrf01"), ('2001:db2::2', 'leaf0', "Vrf01"),
            ('10.1.1.2', 'leaf0', "Vrf02"), ('10.1.2.2', 'leaf0', "Vrf02"), ('2001:db1::2', 'leaf0', "Vrf02"), ('2001:db2::2', 'leaf0', "Vrf02"),
            ('10.1.1.2', 'leaf0', "Vrf03"), ('10.1.2.2', 'leaf0', "Vrf03"), ('2001:db1::2', 'leaf0', "Vrf03"), ('2001:db2::2', 'leaf0', "Vrf03")]

    for ip, node, vrf in data:
        state = get_bgp_neighbor_state(ip, node, vrf)
        if state != 'Established':
            st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_nb_shut_and_unshut_sub_interface():
    vars = st.get_testbed_vars()

    if vars.D1D3P1 == 'Ethernet1_1':
        shut_cmd = 'sudo config interface shutdown Eth1_1.100'
        unshut_cmd = 'sudo config interface startup Eth1_1.100'
    else:
        shut_cmd = 'sudo config interface shutdown Eth0.100'
        unshut_cmd = 'sudo config interface startup Eth0.100'

    st.config(nodes['leaf0'], shut_cmd)
    time.sleep(5)

    state = get_bgp_neighbor_state('10.1.1.2', 'leaf0', "Vrf01")
    if state == 'Established':
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.config(nodes['leaf0'], unshut_cmd)

    time.sleep(5)
    state = get_bgp_neighbor_state('10.1.1.2', 'leaf0', "Vrf01")
    if state != 'Established':
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])

def test_bgp_nb_as_aliasing():

    # Verify local ASN's are not exposed to BGP neighbour in prefix update
    # Check local BGP route is updated with private ASN's
    cmd = 'show ip bgp vrf Vrf03'
    cmd_output = st.vtysh_show(nodes['spine1'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    if '200 64514 64515 ?' not in cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    # configure "remove-private-AS" to strip local ASN's
    cmds = ['router bgp 100 vrf Vrf03',
            'address-family ipv4 unicast',
            'neighbor 10.1.2.2 remove-private-AS all']

    for cmd in cmds:
        st.vtysh_config(nodes['leaf0'], cmd)

    # Wait for 5sec to reflect our configuration
    time.sleep(5)

    # Check private ASN's are stripped off when bgp prefix is updated
    cmd = 'show ip bgp vrf Vrf03'
    cmd_output = st.vtysh_show(nodes['spine1'], cmd, skip_tmpl=True, skip_error_check=False)

    if not cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    if '200 64514 64515 ?' in cmd_output:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
