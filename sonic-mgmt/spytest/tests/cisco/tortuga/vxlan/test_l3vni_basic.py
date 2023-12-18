import os
import time
import yaml
import pytest
from spytest import st
import apis.routing.bgp as bgpapi

pytest.fixture(scope='module', autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology('D1D3:1',  'D1D4:1', 'D2D3:1',  'D2D4:1')
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope='function', autouse=True)
def box_service_func_hooks(request):
    yield

# TODO: Parameterize the configs. For now, use static configs
CONFIGS_FILE = 'vxlan_l3vni_configs.yaml'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

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

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

@pytest.fixture()
def setup_teardown_l3vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            config_static(node, 'bgp')

    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, '11.11.11.1'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, '11.11.12.1'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_l3vni'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)

    '''
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    for name, node in nodes.items():
        st.show(node, 'sudo config reload -fy', skip_tmpl=True, skip_error_check=True)
    '''

def config_vlan(node, vlan, members = [], vrf = None, add = True):
    config = ''
    if add:
        config = config + 'sudo config vlan add {}\n'.format(vlan)
        for member in members:
            config = config + 'sudo config vlan member add -u {} {}\n'.format(vlan, member)
        if vrf:
            config = config + 'sudo config interface vrf bind {} {}\n'.format('Vlan' + str(vlan), vrf)

    else:
        if vrf:
            config = config + 'sudo config interface vrf unbind {}\n'.format('Vlan' + str(vlan))
        for member in members:
            config = config + 'sudo config vlan member del {} {}\n'.format(vlan, member)
        config = config + 'sudo config vlan del {}\n'.format(vlan)

    st.config(node, config, skip_error_check=False, conf=True)


def config_vrf(node, vrf, add=True):
    config = ''
    if add:
        config = config + 'sudo config vrf add {}'.format(vrf)
    else:
        config = config + 'sudo config vrf del {}'.format(vrf)

    st.config(node, config, skip_error_check=False, conf=True)


def config_vxlan_map(node, vxlan, vni, vrf=None, vlan=None, add=True):
    config = ''
    if add:
        if vlan:
            config = config + 'sudo config vxlan map add {} {} {}\n'.format(vxlan, vlan, vni)
        if vrf:
            config = config + 'sudo config vrf add_vrf_vni_map {} {}\n'.format(vrf, vni)
    else:
        if vrf:
            config = config + 'sudo config vrf del_vrf_vni_map {}\n'.format(vrf)
        if vlan:
            config = config + 'sudo config vxlan map del {} {} {}\n'.format(vxlan, vlan, vni)
    st.config(node, config, skip_error_check=False, conf=True)


@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_l3vni_basic_config(setup_teardown_l3vni):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    leaf0_vlan_ip = '100.100.100.254/24'
    leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # Start configuration
    '''
    a. add vrf
    '''
    config_vrf(nodes['leaf0'], vrf)
    config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    config_vlan(nodes['leaf0'], leaf0_vlan, members=['Ethernet8'], vrf=vrf)
    config_vlan(nodes['leaf1'], leaf1_vlan, members=['Ethernet8'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf)
    config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    f. add IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    # sleep for 30 seconds for BGP to converge
    time.sleep(30)

    # Start Verification
    leaf0_vrf_prefix = '100.100.100.0'
    leaf1_vrf_prefix = '100.100.101.0'

    leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf0_parsed = st.parse_show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix),
                                 leaf0_output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

    leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf1_parsed = st.parse_show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix),
                                 leaf1_output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

    if len(leaf0_parsed) == 0:
        report_fail(nodes['leaf0'], msg='Found no prefixes advertised to Leaf0')

    if len(leaf1_parsed) == 0:
        report_fail(nodes['leaf1'], msg='Found no prefixes advertised to Leaf1')

    for path in leaf0_parsed:
        if path['valid'] != 'valid':
            report_fail(nodes['leaf0'], msg='Invalid path found in leaf0')
        if path['pathevpntype'] != '5':
            report_fail(nodes['leaf0'], msg='Invalid evpn type {} found in leaf0'.format(path['evpntype']))
        if path['vni'] != '1000':
            report_fail(nodes['leaf0'], msg='Invalid vni found in leaf0')

    for path in leaf1_parsed:
        if path['valid'] != 'valid':
            report_fail(nodes['leaf1'], msg='Invalid path found in leaf1')
        if path['pathevpntype'] != '5':
            report_fail(nodes['leaf1'], msg='Invalid evpn type {} found in leaf1'.format(path['evpntype']))
        if path['vni'] != '1000':
            report_fail(nodes['leaf1'], msg='Invalid vni found in leaf1')

    '''
    f. remove IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    '''
    e. delete vrf to vni map

    d. delete vlan to vni map

    '''
    config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    '''
    c. remove dummy vlan
    '''
    config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf, add=False)
    config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf, add=False)

    '''
    b. remove vlan
    '''
    config_vlan(nodes['leaf0'], leaf0_vlan, members=['Ethernet8'], vrf=vrf, add=False)
    config_vlan(nodes['leaf1'], leaf1_vlan, members=['Ethernet8'], vrf=vrf, add=False)

    '''
    a. delete vrf
    '''
    config_vrf(nodes['leaf0'], vrf, add=False)
    config_vrf(nodes['leaf1'], vrf, add=False)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])

def test_l3vni_multiple_vni(setup_teardown_l3vni):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : ['Ethernet8'], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : ['Ethernet20'], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : ['Ethernet24'], 'vni' : '4000', 'dummy_vlan' : '400' }}

    svi_ips = { 'leaf0' : [ { 'vlan' : '2', 'ip' : '100.100.102.254/24', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '100.100.103.254/24', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '100.100.104.254/24', 'vni' : '4000' } ],
                'leaf1' : [ { 'vlan' : '2', 'ip' : '100.100.112.254/24', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '100.100.113.254/24', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '100.100.114.254/24', 'vni' : '4000' } ]}

    # Start configuration
    '''
    a. add vrf
    '''
    for vrf, value in vrfs.items():
        config_vrf(nodes['leaf0'], vrf)
        config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    for vrf, value in vrfs.items():
        config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf)
        config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    for vrf, value in vrfs.items():
        config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf)
        config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    for vrf, value in vrfs.items():
        config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])
        config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])

    '''
    f. add IP address on vlan
    '''
    for leaf, value in svi_ips.items():
        for v in value:
            st.config(nodes[leaf], 'sudo config interface ip add {} {}'.format('Vlan' + v['vlan'], v['ip']))

    # sleep for 30 seconds for BGP to converge
    time.sleep(30)

    # Start Verification
    for value in svi_ips['leaf1']:
        prefix = value['ip'].strip('254/24') + '0'
        output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

        parsed = st.parse_show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(prefix),
                               output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

        if len(parsed) == 0:
            report_fail(nodes['leaf0'], msg='Found no prefixes advertised to Leaf0')

        for path in parsed:
            if path['valid'] != 'valid':
                report_fail(nodes['leaf0'], msg='Invalid path found in leaf0')
            if path['pathevpntype'] != '5':
                report_fail(nodes['leaf0'], msg='Invalid evpn type {} found in leaf0'.format(path['evpntype']))
            if path['vni'] != value['vni']:
                report_fail(nodes['leaf0'], msg='Invalid vni found in leaf0')

    for value in svi_ips['leaf0']:
        prefix = value['ip'].strip('254/24') + '0'
        output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

        parsed = st.parse_show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(prefix),
                               output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

        if len(parsed) == 0:
            report_fail(nodes['leaf1'], msg='Found no prefixes advertised to Leaf0')

        for path in parsed:
            if path['valid'] != 'valid':
                report_fail(nodes['leaf1'], msg='Invalid path found in leaf1')
            if path['pathevpntype'] != '5':
                report_fail(nodes['leaf1'], msg='Invalid evpn type {} found in leaf1'.format(path['evpntype']))
            if path['vni'] != value['vni']:
                report_fail(nodes['leaf1'], msg='Invalid vni found in leaf1')

    '''
    f. remove IP address on vlan
    '''
    for leaf, value in svi_ips.items():
        for v in value:
            st.config(nodes[leaf], 'sudo config interface ip rem {} {}'.format('Vlan' + v['vlan'], v['ip']))

    '''
    e. delete vrf to vni map

    d. delete vlan to vni map

    '''
    for vrf, value in vrfs.items():
        config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
        config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

    '''
    c. del dummy vlan
    '''
    for vrf, value in vrfs.items():
        config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
        config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

    '''
    b. del vlan
    '''
    for vrf, value in vrfs.items():
        config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
        config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

    '''
    a. del vrf
    '''
    for vrf, value in vrfs.items():
        config_vrf(nodes['leaf0'], vrf, add=False)
        config_vrf(nodes['leaf1'], vrf, add=False)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


def test_l3vni_remove_add_bgp(setup_teardown_l3vni):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    leaf0_vlan_ip = '100.100.100.254/24'
    leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # Start configuration
    '''
    a. add vrf
    '''
    config_vrf(nodes['leaf0'], vrf)
    config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    config_vlan(nodes['leaf0'], leaf0_vlan, members=['Ethernet8'], vrf=vrf)
    config_vlan(nodes['leaf1'], leaf1_vlan, members=['Ethernet8'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf)
    config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    f. add IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    # sleep for 30 seconds for BGP to converge
    time.sleep(30)

    # Start Verification
    leaf0_vrf_prefix = '100.100.100.0'
    leaf1_vrf_prefix = '100.100.101.0'

    leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf0_parsed = st.parse_show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix),
                                 leaf0_output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

    leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf1_parsed = st.parse_show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix),
                                 leaf1_output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

    if len(leaf0_parsed) == 0:
        report_fail(nodes['leaf0'], msg='Found no prefixes advertised to Leaf0')

    if len(leaf1_parsed) == 0:
        report_fail(nodes['leaf1'], msg='Found no prefixes advertised to Leaf1')

    for path in leaf0_parsed:
        if path['valid'] != 'valid':
            report_fail(nodes['leaf0'], msg='Invalid path found in leaf0')
        if path['pathevpntype'] != '5':
            report_fail(nodes['leaf0'], msg='Invalid evpn type {} found in leaf0'.format(path['evpntype']))
        if path['vni'] != '1000':
            report_fail(nodes['leaf0'], msg='Invalid vni found in leaf0')

    for path in leaf1_parsed:
        if path['valid'] != 'valid':
            report_fail(nodes['leaf1'], msg='Invalid path found in leaf1')
        if path['pathevpntype'] != '5':
            report_fail(nodes['leaf1'], msg='Invalid evpn type {} found in leaf1'.format(path['evpntype']))
        if path['vni'] != '1000':
            report_fail(nodes['leaf1'], msg='Invalid vni found in leaf1')

    #######
    # a. Remove vrf vni mapping
    # b. Remove BGP
    # c. Check if the routes are withdrawn
    # d. Add vrf vni mapping
    # e. Add BGP
    # f. Check if the routes are back
    ######
    '''
    a. Remove l3vni mapping
    '''
    config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    '''
    b. Remove BGP
    '''
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp', add=False)

    # sleep for 30 seconds for BGP to converge
    time.sleep(30)

    '''
    c. Check if the routes are withdrawn
    '''
    # Start Verification
    leaf0_vrf_prefix = '100.100.100.0'
    leaf1_vrf_prefix = '100.100.101.0'

    leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    if 'No BGP process is configured' not in leaf0_output:
        report_fail(nodes['leaf0'], msg='Found prefixes {}'.format(leaf0_output))

    if 'No BGP process is configured' not in leaf1_output:
        report_fail(nodes['leaf1'], msg='Found prefixes {}'.format(leaf1_output))

    '''
    d. add vlan to vni map
    '''
    config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    e. Add BGP
    '''
    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp')

    '''
    f. Check if the routes are back
    '''
    # sleep for 30 seconds for BGP to converge
    time.sleep(30)

    # Start Verification
    leaf0_vrf_prefix = '100.100.100.0'
    leaf1_vrf_prefix = '100.100.101.0'

    leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf0_parsed = st.parse_show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix),
                                 leaf0_output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

    leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf1_parsed = st.parse_show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix),
                                 leaf1_output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

    if len(leaf0_parsed) == 0:
        report_fail(nodes['leaf0'], msg='Found no prefixes advertised to Leaf0')

    if len(leaf1_parsed) == 0:
        report_fail(nodes['leaf1'], msg='Found no prefixes advertised to Leaf1')

    for path in leaf0_parsed:
        if path['valid'] != 'valid':
            report_fail(nodes['leaf0'], msg='Invalid path found in leaf0')
        if path['pathevpntype'] != '5':
            report_fail(nodes['leaf0'], msg='Invalid evpn type {} found in leaf0'.format(path['evpntype']))
        if path['vni'] != '1000':
            report_fail(nodes['leaf0'], msg='Invalid vni found in leaf0')

    for path in leaf1_parsed:
        if path['valid'] != 'valid':
            report_fail(nodes['leaf1'], msg='Invalid path found in leaf1')
        if path['pathevpntype'] != '5':
            report_fail(nodes['leaf1'], msg='Invalid evpn type {} found in leaf1'.format(path['evpntype']))
        if path['vni'] != '1000':
            report_fail(nodes['leaf1'], msg='Invalid vni found in leaf1')

    '''
    f. remove IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    '''
    e. delete vrf to vni map

    d. delete vlan to vni map

    '''
    config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    '''
    c. remove dummy vlan
    '''
    config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf, add=False)
    config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf, add=False)

    '''
    b. remove vlan
    '''
    config_vlan(nodes['leaf0'], leaf0_vlan, members=['Ethernet8'], vrf=vrf, add=False)
    config_vlan(nodes['leaf1'], leaf1_vlan, members=['Ethernet8'], vrf=vrf, add=False)

    '''
    a. delete vrf
    '''
    config_vrf(nodes['leaf0'], vrf, add=False)
    config_vrf(nodes['leaf1'], vrf, add=False)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
