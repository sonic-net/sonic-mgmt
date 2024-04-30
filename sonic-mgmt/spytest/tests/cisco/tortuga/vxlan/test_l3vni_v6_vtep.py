import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj

##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD1 -- Spine1  - D2
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##

## tgen Stream Config
data = SpyTestDict()
data.config_vrfs = []

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "500"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.01"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "100"
    else:
        data.mode ="create"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "1000"
    yield

data.d3t1_ip_addr = "1.1.1.3"
data.t1d3_ip_addr = "1.1.1.2"
data.t1d3_mac_addr = "00:0a:01:00:11:01"

data.d4t1_ip_addr = "1.1.1.2"
data.t1d4_ip_addr = "1.1.1.3"
data.t1d4_mac_addr = "00:0a:01:00:12:01"

CONFIGS_FILE = 'vxlan_l3vni_v6_vtep_config_template.yaml'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

@pytest.fixture(scope="function", autouse=True)
def vxlan_config_hooks():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    st.wait(60)
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)

def configure_and_validate_basic_l3vni(overlay_afamily):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    if overlay_afamily == 'ipv6':
        leaf0_vlan_ip = '2002:db8:1::1/64'
        leaf1_vlan_ip = '2003:db8:1::1/64'
    else:
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
    vxlan_obj.config_vrf(nodes['leaf0'], vrf)
    vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], leaf0_vlan, members=[vars.D3T1P1], vrf=vrf)
    vxlan_obj.config_vlan(nodes['leaf1'], leaf1_vlan, members=[vars.D4T1P1], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf)
    vxlan_obj.config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    f. add IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

    # Start Verification
    if overlay_afamily == 'ipv6':
        leaf0_vrf_prefix = '2002:db8:1::'
        leaf1_vrf_prefix = '2003:db8:1::'
    else:
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


def deconfigure_basic_l3vni(overlay_afamily):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    if overlay_afamily == 'ipv6':
        leaf0_vlan_ip = '2002:db8:1::1/64'
        leaf1_vlan_ip = '2003:db8:1::1/64'
    else:
        leaf0_vlan_ip = '100.100.100.254/24'
        leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    '''
    f. remove IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    '''
    e. delete vrf to vni map

    d. delete vlan to vni map

    '''
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    '''
    c. remove dummy vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf, add=False)
    vxlan_obj.config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf, add=False)

    '''
    b. remove vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], leaf0_vlan, members=[vars.D3T1P1], vrf=vrf, add=False)
    vxlan_obj.config_vlan(nodes['leaf1'], leaf1_vlan, members=[vars.D4T1P1], vrf=vrf, add=False)

    '''
    a. delete vrf
    '''
    data.config_vrfs.append(vrf)


# v6 over v6 tests
def test_l3vni_v6_v6_vtep_basic_config():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    # Configure and Validate basic l3vni configs and route exchanges
    configure_and_validate_basic_l3vni('ipv6')

    # Deconfigure basic l3vni configs
    deconfigure_basic_l3vni('ipv6')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


def test_l3vni_v6_v6_vtep_multiple_vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

    svi_ips = { 'leaf0' : [ { 'vlan' : '2', 'ip' : '2002:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2003:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2004:db8:1::1/64', 'vni' : '4000' } ],
                'leaf1' : [ { 'vlan' : '2', 'ip' : '2112:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2113:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2114:db8:1::1/64', 'vni' : '4000' } ]}

    # Start configuration
    '''
    a. add vrf
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vrf(nodes['leaf0'], vrf)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])

    '''
    f. add IP address on vlan
    '''
    for leaf, value in svi_ips.items():
        for v in value:
            st.config(nodes[leaf], 'sudo config interface ip add {} {}'.format('Vlan' + v['vlan'], v['ip']))

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

    # Start Verification
    for value in svi_ips['leaf1']:
        prefix = value['ip'].strip('1/64') + '0'
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
        prefix = value['ip'].strip('1/64') + '0'
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
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

    '''
    c. del dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

    '''
    b. del vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

    '''
    a. del vrf
    '''
    for vrf, value in vrfs.items():
        data.config_vrfs.append(vrf)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


def test_l3vni_v6_v6_vtep_multiple_vni_load():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

    svi_ips = { 'leaf0' : [ { 'vlan' : '2', 'ip' : '2002:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2003:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2004:db8:1::1/64', 'vni' : '4000' } ],
                'leaf1' : [ { 'vlan' : '2', 'ip' : '2112:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2113:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2114:db8:1::1/64', 'vni' : '4000' } ]}

    # Start configuration
    '''
    a. add vrf
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vrf(nodes['leaf0'], vrf)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])

    '''
    f. add IP address on vlan
    '''
    for leaf, value in svi_ips.items():
        for v in value:
            st.config(nodes[leaf], 'sudo config interface ip add {} {}'.format('Vlan' + v['vlan'], v['ip']))

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

    # Start Verification
    for value in svi_ips['leaf1']:
        prefix = value['ip'].strip('1/64') + '0'
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
        prefix = value['ip'].strip('1/64') + '0'
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
    Save config to a file before unconfiguring. The same saved file will be used for load operation
    '''
    for k,v in nodes.items():
        if 'spine' not in k:
            filename = "/tmp/config-db-{}.json".format(k)
            st.config(v, "config save {} -y".format(filename), skip_error_check=True)

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
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

    '''
    c. del dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

    '''
    b. del vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

    '''
    Remove BGP before vrf is removed
    '''
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp', add=False)

    '''
    a. del vrf
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)

    '''
    Remove SONiC Config too
    '''
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'sonic', add=False)

    # sleep for 30 seconds for BGP to converge
    st.wait(30)

    ############# Start adding configuration back #############

    '''
    Add BGP back
    '''
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp')

    '''
    Now load config from already saved config file
    '''
    for k,v in nodes.items():
        if 'spine' not in k:
            filename = "/tmp/config-db-{}.json".format(k)
            st.config(v, "config load {} -y".format(filename), skip_error_check=True)

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

    # Start Verification
    for value in svi_ips['leaf1']:
        prefix = value['ip'].strip('1/64') + '0'
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
        prefix = value['ip'].strip('1/64') + '0'
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
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

    '''
    c. del dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

    '''
    b. del vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

    '''
    a. del vrf
    '''
    for vrf, value in vrfs.items():
        data.config_vrfs.append(vrf)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


def test_l3vni_v6_v6_vtep_remove_add_bgp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    leaf0_vlan_ip = '2002:db8:1::1/64'
    leaf1_vlan_ip = '2003:db8:1::1/64'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # Configure and validate basic l3vni and route exchanges
    configure_and_validate_basic_l3vni('ipv6')

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
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    '''
    b. Remove BGP
    '''
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp', add=False)

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

    '''
    c. Check if the routes are withdrawn
    '''
    # Start Verification
    leaf0_vrf_prefix = '2002:db8:1::'
    leaf1_vrf_prefix = '2003:db8:1::'

    leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

    if 'No BGP process is configured' not in leaf0_output:
        report_fail(nodes['leaf0'], msg='Found prefixes {}'.format(leaf0_output))

    if 'No BGP process is configured' not in leaf1_output:
        report_fail(nodes['leaf1'], msg='Found prefixes {}'.format(leaf1_output))

    '''
    d. add vlan to vni map
    '''
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    e. Add BGP
    '''
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp')

    '''
    f. Check if the routes are back
    '''
    # sleep for 60 seconds for BGP to converge
    st.wait(60)

    # Start Verification
    leaf0_vrf_prefix = '2002:db8:1::'
    leaf1_vrf_prefix = '2003:db8:1::'

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

    # Deconfigure basic l3vni configs
    deconfigure_basic_l3vni('ipv6')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


def test_l3vni_v6_v6_vtep_port_flap():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    leaf0_vlan_ip = '2002:db8:1::1/64'
    leaf1_vlan_ip = '2003:db8:1::1/64'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # Configure and validate basic l3vni and route exchanges
    configure_and_validate_basic_l3vni('ipv6')

    st.banner("Flapping Spine links on LEAF0")
    st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D1P1))
    st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D2P1))
    st.wait(10)

    '''
    Check if the routes are withdrawn
    '''
    # Start Verification
    leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
    leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

    for vtep in leaf0_parsed:
        if vtep['total_count'] == 0:
            st.log("Remote VTEP is not seen anymore", nodes['leaf0'])

    # Bringup the spine interfaces
    st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D1P1))
    st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D2P1))
    st.wait(60)
    st.banner("Spine links restored on LEAF0")

    # Start Verification if routes are back
    leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
    leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

    for vtep in leaf0_parsed:
        if vtep['total_count'] == 1:
            st.log("Remote VTEP is seen now", nodes['leaf0'])

    leaf0_vrf_prefix = '2002:db8:1::'
    leaf1_vrf_prefix = '2003:db8:1::'

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

    # Deconfigure basic l3vni configs
    deconfigure_basic_l3vni('ipv6')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


# v4 over v6 tests
#
# TODO: We shouldn't be duplicating test cases. However, pytest parameterization is not working. This is
# a temporary work around till the time parameterization is actually made to work.
#
# TODO: As noted in skip reason, test cases fail due to a zebra crash, we need to get a handle on that.
@pytest.mark.xfail(reason="Sometimes the tests fail due to zebra crash, cannot enable till it is fixed")
def test_l3vni_v4_v6_vtep_basic_config():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    # Configure and Validate basic l3vni configs and route exchanges
    configure_and_validate_basic_l3vni('ipv4')

    # Deconfigure basic l3vni configs
    deconfigure_basic_l3vni('ipv4')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


@pytest.mark.xfail(reason="Sometimes the tests fail due to zebra crash, cannot enable till it is fixed")
def test_l3vni_v4_v6_vtep_multiple_vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

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
        vxlan_obj.config_vrf(nodes['leaf0'], vrf)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])

    '''
    f. add IP address on vlan
    '''
    for leaf, value in svi_ips.items():
        for v in value:
            st.config(nodes[leaf], 'sudo config interface ip add {} {}'.format('Vlan' + v['vlan'], v['ip']))

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

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
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

    '''
    c. del dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

    '''
    b. del vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

    '''
    a. del vrf
    '''
    for vrf, value in vrfs.items():
        data.config_vrfs.append(vrf)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


@pytest.mark.xfail(reason="Sometimes the tests fail due to zebra crash, cannot enable till it is fixed")
def test_l3vni_v4_v6_vtep_multiple_vni_load():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

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
        vxlan_obj.config_vrf(nodes['leaf0'], vrf)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])

    '''
    f. add IP address on vlan
    '''
    for leaf, value in svi_ips.items():
        for v in value:
            st.config(nodes[leaf], 'sudo config interface ip add {} {}'.format('Vlan' + v['vlan'], v['ip']))

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

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
    Save config to a file before unconfiguring. The same saved file will be used for load operation
    '''
    for k,v in nodes.items():
        if 'spine' not in k:
            filename = "/tmp/config-db-{}.json".format(k)
            st.config(v, "config save {} -y".format(filename), skip_error_check=True)

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
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

    '''
    c. del dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

    '''
    b. del vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

    '''
    Remove BGP before vrf is removed
    '''
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp', add=False)

    '''
    a. del vrf
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)

    '''
    Remove SONiC Config too
    '''
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'sonic', add=False)

    # sleep for 30 seconds for BGP to converge
    st.wait(30)

    ############# Start adding configuration back #############

    '''
    Add BGP back
    '''
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp')

    '''
    Now load config from already saved config file
    '''
    for k,v in nodes.items():
        if 'spine' not in k:
            filename = "/tmp/config-db-{}.json".format(k)
            st.config(v, "config load {} -y".format(filename), skip_error_check=True)

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

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
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

    '''
    c. del dummy vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

    '''
    b. del vlan
    '''
    for vrf, value in vrfs.items():
        vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

    '''
    a. del vrf
    '''
    for vrf, value in vrfs.items():
        data.config_vrfs.append(vrf)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


@pytest.mark.xfail(reason="Sometimes the tests fail due to zebra crash, cannot enable till it is fixed")
def test_l3vni_v4_v6_vtep_remove_add_bgp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    leaf0_vlan_ip = '100.100.100.254/24'
    leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # Configure and validate basic l3vni and route exchanges
    configure_and_validate_basic_l3vni('ipv4')

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
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    '''
    b. Remove BGP
    '''
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            if 'spine' not in node:
                config_static(node, 'bgp', add=False)

    # sleep for 60 seconds for BGP to converge
    st.wait(60)

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
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    e. Add BGP
    '''
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp')

    '''
    f. Check if the routes are back
    '''
    # sleep for 60 seconds for BGP to converge
    st.wait(60)

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

    # Deconfigure basic l3vni configs
    deconfigure_basic_l3vni('ipv4')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


@pytest.mark.xfail(reason="Sometimes the tests fail due to zebra crash, cannot enable till it is fixed")
def test_l3vni_v4_v6_vtep_port_flap():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    leaf0_vlan_ip = '100.100.100.254/24'
    leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # Configure and validate basic l3vni and route exchanges
    configure_and_validate_basic_l3vni('ipv4')

    st.banner("Flapping Spine links on LEAF0")
    st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D1P1))
    st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D2P1))
    st.wait(10)

    '''
    Check if the routes are withdrawn
    '''
    # Start Verification
    leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
    leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

    for vtep in leaf0_parsed:
        if vtep['total_count'] == 0:
            st.log("Remote VTEP is not seen anymore", nodes['leaf0'])

    # Bringup the spine interfaces
    st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D1P1))
    st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D2P1))
    st.wait(60)
    st.banner("Spine links restored on LEAF0")

    # Start Verification if routes are back
    leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
    leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

    for vtep in leaf0_parsed:
        if vtep['total_count'] == 1:
            st.log("Remote VTEP is seen now", nodes['leaf0'])

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

    # Deconfigure basic l3vni configs
    deconfigure_basic_l3vni('ipv4')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
