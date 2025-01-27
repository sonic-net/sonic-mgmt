import os
import time
import yaml
import json
import pytest
from spytest import st
import utilities.utils as utils_obj
import vxlan_utils as vxlan_obj
import tortuga_common_utils as common_obj

# TODO: Parameterize the configs. For now, use static configs
CONFIGS_FILE = 'bfd_lla.yaml'

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

def dump_bfd_state_changes(node, nodename):
    cmd_output = st.show(node, 'sudo grep BFD /var/log/swss/sairedis.rec', skip_tmpl=True, skip_error_check=True)
    print("******** "+nodename+" sonic output (SAI redis rec)***********")
    print(cmd_output)

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_l3vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    for node in nodes:
        cmd_output = st.show(nodes[node], 'show running', type='vtysh', skip_tmpl=True, skip_error_check=True)
        print("************************ "+node+" show running output************************")
        print(cmd_output)

    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE, vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', True, updated_config_file)
            st.wait(2)
            common_obj.config_static(node, 'bgp', True, updated_config_file)
            st.wait(2)
        # sleep for BGP to converge
        st.wait(180)            
        for n in nodes:
            cmd_output = st.show(nodes[n], 'show bgp sum json', type='vtysh', skip_tmpl=True, skip_error_check=True)
            print("************************"+n+" show bgp sum output************************")
            print(cmd_output)

    yield 'setup_teardown_l3vni'


    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'bgp', False, updated_config_file)
            st.wait(4)
            common_obj.config_static(node, 'sonic', False, updated_config_file)
            st.wait(4)

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

# Test if multiple BFD sessions with same src/dst IP address (LLA) but different interface can be created

def test_bgp_bfd_lla():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    # Start Verification

    for node in nodes:
        cmd_output = st.show(nodes[node], 'sudo grep "ptm-add-dest: register peer" /var/log/syslog', skip_tmpl=True, skip_error_check=True)
        print("******** "+node+" sonic output (frr create bfd session (syslog))***********")
        print(cmd_output)

        cmd_output = st.show(nodes[node], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)
        print("************************ "+node+" bfdd output************************")
        print(cmd_output)
        js = json.loads(cmd_output[:cmd_output.rfind(']')+1])
        print(js)
        # Expectng all bfd sessions are UP
        if len(js) < 4:
            #2 bfd sessions between each leaf-spine pair
            report_fail(nodes[node], msg='number of bfd sessions less than 4')
        else: 
            for bs in js:
                if bs["status"] != "up":
                    dump_bfd_state_changes(nodes[node], node)
                    report_fail(nodes[node], msg='bfd session is not up')

        #example [{'count': '2', 'address': 'fe80::7acf:35ff:fe5b:ca00', 'interface': 'Ethernet16', 'vrf': 'default', 'state': 'Up'}, {'count': '2', 'address': 'fe80::7a9a:1cff:fee9:c600', 'interface': 'Ethernet0', 'vrf': 'default', 'state': 'Up'}]
        cmd_output = st.show(nodes[node], 'show bfd sum', skip_tmpl=True, skip_error_check=True)
        print("************************ "+node+" sonic output************************")
        print(cmd_output)
        cmd_parsed = st.parse_show(nodes[node], "show bfd sum", cmd_output, "show_bfd_sum_sonic.tmpl")
        print(cmd_parsed)
        if len(cmd_parsed) < 4: 
            report_fail(nodes[node], msg='number of bfd sessions less than 4 (show bfd sum)')
        else:
            for bs in cmd_parsed:
                print(bs)
                if bs['state'] != 'Up': 
                    dump_bfd_state_changes(nodes[node], node)
                    report_fail(nodes[node], msg='bfd session is not up (show bfd sum)')

    print("************************remove all bfd sessions in spine1************************")
    print(python_script)
    fp = open("/tmp/gen_bfd_cfg.py", "w")
    fp.write(python_script)
    fp.close()
    utils_obj.copy_files_to_dut(nodes['spine1'], ['/tmp/gen_bfd_cfg.py'], '/tmp/')
    st.config(nodes['spine1'], 'sudo python3 /tmp/gen_bfd_cfg.py', sudo=False, split_cmds=False)
    st.config(nodes['spine1'], 'sudo docker exec -i swss swssconfig /dev/stdin < /tmp/bfd_config.json', sudo=False, split_cmds=False)
    st.config(nodes['spine1'], 'sudo rm -f /tmp/gen_bfd_cfg.py /tmp/bfd_config.json', sudo=False, split_cmds=False)

    time.sleep(2)

    bfd0_output = st.show(nodes['leaf0'], 'show bfd peers json', type='vtysh', skip_tmpl=True, skip_error_check=True)

    #Neighbor D3D2P1 and D3D2P2 will be down in leaf0
    print("************************leaf0 bfdd output************************")
    print(bfd0_output)
    js = json.loads(bfd0_output[:bfd0_output.rfind(']')+1])
    print(js)
    # Expecting one bfd session is UP and another is DOWN
    if len(js) < 4:
        report_fail(nodes['leaf0'], msg='number of bfd sessions less than 4')
    else: 
        for bs in js:
            if bs['interface'] == vars.D3D1P1 and bs["status"] != "up":
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D1P1+' is not up')
            if bs['interface'] == vars.D3D1P2 and bs["status"] != "up":
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D1P2+' is not up')
            if bs['interface'] == vars.D3D2P1 and bs["status"] != "down":
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D2P1+' is not down')
            if bs['interface'] == vars.D3D2P2 and bs["status"] != "down":
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D2P2+' is not down')

    #example [{'count': '2', 'address': 'fe80::7acf:35ff:fe5b:ca00', 'interface': 'Ethernet16', 'vrf': 'default', 'state': 'Up'}, {'count': '2', 'address': 'fe80::7a9a:1cff:fee9:c600', 'interface': 'Ethernet0', 'vrf': 'default', 'state': 'Up'}]

    cmd_output = st.show(nodes['leaf0'], 'show bfd sum', skip_tmpl=True, skip_error_check=True)
    print("************************leaf0 sonic output************************")
    print(cmd_output)
    cmd_parsed = st.parse_show(nodes['leaf0'], "show bfd sum", cmd_output, "show_bfd_sum_sonic.tmpl")
    print(cmd_parsed)
    if len(cmd_parsed) < 4: 
        report_fail(nodes['leaf0'], msg='number of bfd sessions less than 4 (show bfd sum)')
    else:
        for bs in cmd_parsed:
            print(bs)
            if bs['interface'] == vars.D3D1P1 and bs['state'] != 'Up': 
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D1P1+' is not up')
            if bs['interface'] == vars.D3D1P2 and bs['state'] != 'Up': 
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D1P2+' is not up')
            if bs['interface'] == vars.D3D2P1 and bs['state'] != 'Down': 
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D2P1+' is not down')
            if bs['interface'] == vars.D3D2P2 and bs['state'] != 'Down': 
                dump_bfd_state_changes(nodes[node], node)
                report_fail(nodes['leaf0'], msg='bfd session '+vars.D3D2P2+' is not down')

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
