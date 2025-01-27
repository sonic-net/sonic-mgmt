import os
import time
import yaml
import json
import pytest
from spytest import st
import utilities.utils as utils_obj
import vxlan_utils as vu
import vxlan_utils as vxlan_obj

# TODO: Parameterize the configs. For now, use static configs
CONFIGS_FILE = 'bgp_bfd_configs_template.yaml'

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

    st.wait(30)
    for node in nodes:
        cmd_output = st.show(nodes[node], 'show running', type='vtysh', skip_tmpl=True, skip_error_check=True)
        print("************************"+node+" show running output************************")
        print(cmd_output)

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
            st.wait(2)
        # sleep for BGP to converge
        st.wait(120)            
        for n in nodes:
            cmd_output = st.show(nodes[n], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
            print("************************"+n+" show bgp sum output************************")
            print(cmd_output)
            cmd_output = st.show(nodes[n], 'show ip route vrf all ', skip_tmpl=True, skip_error_check=True)
            print("************************"+n+" show show ip route vrf all output************************")
            print(cmd_output)

    yield 'setup_teardown_l3vni'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            st.wait(4)
            config_static(node, 'sonic', add=False)
            st.wait(4)
        for n in nodes:
            cmd_output = st.show(nodes[n], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
            print("************************"+n+" show bfd peers output after deconfig************************")
            print(cmd_output) 
    vxlan_obj.remove_temp_config(updated_config_file)

python_script = '''
#!/usr/bin/python3

import subprocess
result = subprocess.getoutput('redis-dump -d 0 -y | grep BFD').split('\\n')
cfg = "["
for k in result:
    cfg += "{"+k+'}, "OP":"DEL"},'
cfg =cfg[:-1]+ "]"
fp = open("/tmp/bfd_config.json", "w")
fp.write(cfg)
fp.close()

'''

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_bgp_bfd_basic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    # Start Verification

    cmd_output = st.show(nodes['leaf0'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************leaf0 bfdd output************************")
    print(cmd_output)
    js = json.loads(cmd_output[:cmd_output.rfind(']')+1])
    print(js)
    # Expectng both bfd sessions are UP
    if len(js) < 2:
        report_fail(nodes['leaf0'], msg='number of bfd sessions less than 2 (2 bfd sessions for 2 spine)')
    else: 
        for bs in js:
            if bs["status"] != "up":
                report_fail(nodes['leaf0'], msg='bfd session is not up')

    cmd_output = st.show(nodes['leaf1'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************leaf1 bgp sum output************************")
    print(cmd_output)
    cmd_output = st.show(nodes['leaf1'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************leaf1 bfdd output************************")
    print(cmd_output)
    js = json.loads(cmd_output[:cmd_output.rfind(']')+1])
    print(js)
    # Expectng both bfd sessions are UP
    if len(js) < 2:
        report_fail(nodes['leaf1'], msg='number of bfd sessions less than 2 (2 bfd sessions for 2 spine)')
    else: 
        for bs in js:
            if bs["status"] != "up":
                report_fail(nodes['leaf1'], msg='bfd session is not up')

    cmd_output = st.show(nodes['spine0'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************spine0 bgp sum json************************")
    print(cmd_output)
    cmd_output = st.show(nodes['spine0'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************spine0 bfdd output json************************")
    print(cmd_output)
    js = json.loads(cmd_output[:cmd_output.rfind(']')+1])
    print(js)
    # Expectng both bfd sessions are UP
    if len(js) < 2:
        report_fail(nodes['spine0'], msg='number of bfd sessions less than 2 (2 bfd sessions for 2 leaf)')
    else: 
        for bs in js:
            if bs["status"] != "up":
                report_fail(nodes['spine0'], msg='bfd sessions is not up')

    cmd_output = st.show(nodes['spine1'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************spine1 show bgp sum json************************")
    print(cmd_output)
    cmd_output = st.show(nodes['spine1'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************spine1 bfdd output json************************")
    print(cmd_output)
    js = json.loads(cmd_output[:cmd_output.rfind(']')+1])
    print(js)
    # Expectng both bfd sessions are UP
    if len(js) < 2:
        report_fail(nodes['spine1'], msg='number of bfd sessions less than 2 (2 bfd sessions for 2 leaf)')
    else: 
        for bs in js:
            if bs["status"] != "up":
                report_fail(nodes['spine1'], msg='bfd sessions is not up')

    cmd_output = st.show(nodes['leaf0'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************leaf0 bgp sum json************************")
    print(cmd_output)
    js = json.loads(cmd_output[:cmd_output.rfind('}')+1])
    print(js)
    if 'ipv4Unicast' not in js and 'ipv6Unicast' not in js:
        report_fail(nodes['leaf0'], msg='Neither ipv4Unicase nor ipv6 unicase in bgp')
    if 'ipv4Unicast' in js:
        if js['ipv4Unicast']['peers'][vars.D3D1P1]['state'] != 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet0 is not Established')
        if js['ipv4Unicast']['peers'][vars.D3D2P1]['state'] != 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet16 is not Established')
    if 'ipv6Unicast' in js:
        if js['ipv6Unicast']['peers'][vars.D3D1P1]['state'] != 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet0 is not Established')
        if js['ipv4Unicast']['peers'][vars.D3D2P1]['state'] != 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet16 is not Established')

    cmd_output = st.show(nodes['leaf1'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    print("************************leaf1 bgp sum json************************")
    print(cmd_output)
    js = json.loads(cmd_output[:cmd_output.rfind('}')+1])
    print(js)
    if 'ipv4Unicast' not in js and 'ipv6Unicast' not in js:
        report_fail(nodes['leaf1'], msg='Neither ipv4Unicase nor ipv6 unicase in bgp')
    if 'ipv4Unicast' in js:
        if js['ipv4Unicast']['peers'][vars.D4D1P1]['state'] != 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet0 is not Established')
        if js['ipv4Unicast']['peers'][vars.D4D2P1]['state'] != 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet16 is not Established')
    if 'ipv6Unicast' in js:
        if js['ipv6Unicast']['peers'][vars.D4D1P1]['state'] != 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet0 is not Established')
        if js['ipv4Unicast']['peers'][vars.D4D2P1]['state'] != 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet16 is not Established')

    #[{'count': '2', 'address': 'fe80::7acf:35ff:fe5b:ca00', 'interface': 'Ethernet16', 'vrf': 'default', 'state': 'Up'}, {'count': '2', 'address': 'fe80::7a9a:1cff:fee9:c600', 'interface': 'Ethernet0', 'vrf': 'default', 'state': 'Up'}]
    cmd_output = st.show(nodes['leaf0'], 'show bfd sum', skip_tmpl=True, skip_error_check=True)
    print("************************leaf0 sonic output************************")
    print(cmd_output)
    cmd_parsed = st.parse_show(nodes['leaf0'], "show bfd sum", cmd_output, "show_bfd_sum_sonic.tmpl")
    print(cmd_parsed)
    if len(cmd_parsed) < 2: 
        report_fail(nodes['leaf0'], msg='number of bfd sessions less than 2 (show bfd sum)')
    else:
        for bs in cmd_parsed:
            print(bs)
            if bs['state'] != 'Up': 
                report_fail(nodes['leaf0'], msg='bfd session is not up (show bfd sum)')

    cmd_output = st.show(nodes['leaf1'], 'show bfd sum', skip_tmpl=True, skip_error_check=True)
    print("************************leaf1 sonic output************************")
    print(cmd_output)
    cmd_parsed = st.parse_show(nodes['leaf1'], "show bfd sum", cmd_output, "show_bfd_sum_sonic.tmpl")
    print(cmd_parsed)
    if len(cmd_parsed) < 2: 
        report_fail(nodes['leaf1'], msg='number of bfd sessions less than 2 (show bfd sum)')
    else:
        for bs in cmd_parsed:
            print(bs)
            if bs['state'] != 'Up': 
                report_fail(nodes['leaf1'], msg='bfd session is not up (show bfd sum)')


    print("************************remove all bfd sessions in spine1************************")
    print(python_script)
    fp = open("/tmp/gen_bfd_cfg.py", "w")
    fp.write(python_script)
    fp.close()
    utils_obj.copy_files_to_dut(nodes['spine1'], ['/tmp/gen_bfd_cfg.py'], '/tmp/')
    st.config(nodes['spine1'], 'sudo python3 /tmp/gen_bfd_cfg.py', sudo=False, split_cmds=False)
    st.config(nodes['spine1'], 'sudo docker exec -i swss swssconfig /dev/stdin < /tmp/bfd_config.json', sudo=False, split_cmds=False)
    st.config(nodes['spine1'], 'sudo rm -f /tmp/gen_bfd_cfg.py /tmp/bfd_config.json', sudo=False, split_cmds=False)

    time.sleep(0.5)

    bgp0_output = st.show(nodes['leaf0'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    bgp1_output = st.show(nodes['leaf1'], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    bfd0_output = st.show(nodes['leaf0'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
    bfd1_output = st.show(nodes['leaf1'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)

    #Neighbor D3D2P1 will be down in leaf0 and leaf1
    print("************************leaf0 bfdd output************************")
    print(bfd0_output)
    js = json.loads(bfd0_output[:bfd0_output.rfind(']')+1])
    print(js)
    # Expecting one bfd session is UP and another is DOWN
    if len(js) < 2:
        report_fail(nodes['leaf0'], msg='number of bfd sessions less than 2 (2 bfd sessions for 2 spine)')
    else: 
        for bs in js:
            if bs['interface'] == vars.D3D1P1 and bs["status"] != "up":
                report_fail(nodes['leaf0'], msg='bfd sessions (Ethernet0) is not up')
            if bs['interface'] == vars.D3D2P1 and bs["status"] != "down":
                report_fail(nodes['leaf0'], msg='bfd sessions (Ethernet16) is not down')

    print("************************leaf1 bfdd output************************")
    print(bfd1_output)
    js = json.loads(bfd1_output[:bfd1_output.rfind(']')+1])
    print(js)
    # Expecting one bfd session is UP and another is DOWN
    if len(js) < 2:
        report_fail(nodes['leaf1'], msg='number of bfd sessions less than 2 (2 bfd sessions for 2 spine)')
    else: 
        for bs in js:
            if bs['interface'] == vars.D4D1P1 and bs["status"] != "up":
                report_fail(nodes['leaf1'], msg='bfd sessions (Ethernet0) is not up')
            if bs['interface'] == vars.D4D2P1 and bs["status"] != "down":
                report_fail(nodes['leaf1'], msg='bfd sessions (Ethernet16) is not down')

    print("************************leaf0 bgp sum json************************")
    print(bgp0_output)
    js = json.loads(bgp0_output[:bgp0_output.rfind('}')+1])
    print(js)
    if 'ipv4Unicast' not in js and 'ipv6Unicast' not in js:
        report_fail(nodes['leaf0'], msg='Neither ipv4Unicase nor ipv6 unicase in bgp')
    if 'ipv4Unicast' in js:
        if js['ipv4Unicast']['peers'][vars.D3D1P1]['state'] != 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet0 is not Established')
        if js['ipv4Unicast']['peers'][vars.D3D2P1]['state'] == 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet16 should not be Established')
    if 'ipv6Unicast' in js:
        if js['ipv6Unicast']['peers'][vars.D3D1P1]['state'] != 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet0 is not Established')
        if js['ipv6Unicast']['peers'][vars.D3D2P1]['state'] == 'Established':
            report_fail(nodes['leaf0'], msg='peer Ethernet16 should not be Established')

    print("************************leaf1 bgp sum json************************")
    print(bgp1_output)
    js = json.loads(bgp1_output[:bgp1_output.rfind('}')+1])
    print(js)
    if 'ipv4Unicast' not in js and 'ipv6Unicast' not in js:
        report_fail(nodes['leaf1'], msg='Neither ipv4Unicase nor ipv6 unicase in bgp')
    if 'ipv4Unicast' in js:
        if js['ipv4Unicast']['peers'][vars.D4D1P1]['state'] != 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet0 is not Established')
        if js['ipv4Unicast']['peers'][vars.D4D2P1]['state'] == 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet16 should not be Established')
    if 'ipv6Unicast' in js:
        if js['ipv6Unicast']['peers'][vars.D4D1P1]['state'] != 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet0 is not Established')
        if js['ipv6Unicast']['peers'][vars.D4D2P1]['state'] == 'Established':
            report_fail(nodes['leaf1'], msg='peer Ethernet16 should not be Established')

    #[{'count': '2', 'address': 'fe80::7acf:35ff:fe5b:ca00', 'interface': 'Ethernet16', 'vrf': 'default', 'state': 'Up'}, {'count': '2', 'address': 'fe80::7a9a:1cff:fee9:c600', 'interface': 'Ethernet0', 'vrf': 'default', 'state': 'Up'}]

    cmd_output = st.show(nodes['leaf0'], 'show bfd sum', skip_tmpl=True, skip_error_check=True)
    print("************************leaf0 sonic output************************")
    print(cmd_output)
    cmd_parsed = st.parse_show(nodes['leaf0'], "show bfd sum", cmd_output, "show_bfd_sum_sonic.tmpl")
    print(cmd_parsed)
    if len(cmd_parsed) < 2: 
        report_fail(nodes['leaf0'], msg='number of bfd sessions less than 2 (show bfd sum)')
    else:
        for bs in cmd_parsed:
            print(bs)
            if bs['interface'] == vars.D3D1P1 and bs['state'] != 'Up': 
                report_fail(nodes['leaf0'], msg='bfd session (Ethernet0) is not Up (show bfd sum)')
            if bs['interface'] == vars.D3D2P1 and bs['state'] != 'Down': 
                report_fail(nodes['leaf0'], msg='bfd session (Ethernet16) is not Down (show bfd sum)')

    cmd_output = st.show(nodes['leaf1'], 'show bfd sum', skip_tmpl=True, skip_error_check=True)
    print("************************leaf1 sonic output************************")
    print(cmd_output)
    cmd_parsed = st.parse_show(nodes['leaf1'], "show bfd sum", cmd_output, "show_bfd_sum_sonic.tmpl")
    print(cmd_parsed)
    if len(cmd_parsed) < 2: 
        report_fail(nodes['leaf1'], msg='number of bfd sessions less than 2 (show bfd sum)')
    else:
        for bs in cmd_parsed:
            print(bs)
            if bs['interface'] == vars.D4D1P1 and bs['state'] != 'Up': 
                report_fail(nodes['leaf1'], msg='bfd session (Ethernet0) is not Up (show bfd sum)')
            if bs['interface'] == vars.D4D2P1 and bs['state'] != 'Down': 
                report_fail(nodes['leaf1'], msg='bfd session (Ethernet16) is not Down (show bfd sum)')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])

