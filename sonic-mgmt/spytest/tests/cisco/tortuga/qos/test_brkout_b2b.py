import time
import random
import json
import os
import sys
import pytest
import pprint
import tortuga_common_utils as common_util
import traffic_stream_ixia_api as stream_api

from spytest import st, tgapi, SpyTestDict
module_dir = os.path.join(os.path.dirname(__file__), '../../', 'common')
sys.path.insert(0, os.path.abspath(module_dir))

lane_speed_50g = ['1x50G(1)', '1x200G(4)', '1x400G', '2x200G', '4x100G',
                  '1x100G(2)', '2x100G(4)']
lane_speed_25g = ['1x25G(1)', '1x100G(4)', '2x100G', '4x25G(4)']
lane_speed_10g = ['1x10G(1)', '4x10G(4)', '1x40G(4)']

def platform_to_modes(plat_str):
    if common_util.is_q200(plat_str):
        return vars.test_info['Q200_modes']
    if common_util.is_g200(plat_str):
        return vars.test_info['G200_modes']

def check_dut_tgen_ports(dut, first_key):
    port_list = []
    port_key = first_key
    ctr = 1

    # First build a list of router ports connected to tgen
    while port_key in tb_dict:
        port_list.append(tb_dict[port_key])
        ctr += 1
        port_key = port_key[:-1] + str(ctr)

    cfg_dut = ''
    result = st.show(dut, 'show int status', skip_tmpl=True)
    lines = result.splitlines()
    for line in lines:
        tokens = line.split()
        if 'Ethernet' not in tokens[0]:
            # ignore extraneous lines
            continue
        if tokens[0] in port_list:
            cfg_dut += 'config interface startup {}\n'.format(tokens[0])
            port_list.remove(tokens[0])

    if len(port_list) == 0:
        st.config(dut, cfg_dut, skip_tmpl=True)
        st.wait(15)
        return True
    return False

@pytest.fixture(scope="module")
def env_config():
    return {
        "pfc_input_file" : os.getenv("PFC_INPUT_FILE"),
    }

@pytest.fixture(scope="module", autouse=True)
def setup_topo(env_config):
    global vars
    global tb_dict
    global brkout_result

    # We need 4 links from tgen to each dut and one link between the two duts
    tb_dict = st.ensure_min_topology("D1D2:1", "T1D1:4", "T1D2:4")
    vars = st.get_testbed_vars()
    vars.b2b_list = [vars.D1D2P1, vars.D2D1P1]
    vars.plat_str = []
    vars.if_dict = {}

    # Make sure router ports connected to tgen exist. Sometimes the parent
    # has to be broken for the child ports to be instantiated
    if not check_dut_tgen_ports(vars.D1, 'D1T1P1') or \
       not check_dut_tgen_ports(vars.D2, 'D2T1P1'):
        st.report_fail('msg', 
                       'Ports specified in yaml file do not exist on DUT')
        return

    result2 = st.show(vars.D2, 'show int status', skip_tmpl=True)
    port_list = []
    port_key = 'D2T1P'
    
    for dut, if_name in zip(vars.dut_list, vars.b2b_list):
        vars.plat_str.append(common_util.find_platform_str(dut))
        # get the interface specific list from show interface breakout
        full_brk_dict = common_util.show_cmd_to_dict(dut, 'interface breakout',
                                                     False)
        vars.if_dict[dut] = full_brk_dict[if_name]
        st.config(dut, 'config feature state lldp enabled', skip_tmpl=True)

    # Get platform specific or test specific info from input json
    if env_config['pfc_input_file'] == None:
        input_file = 'dpb_input.json2'
    else:
        input_file = env_config['pfc_input_file']
    input_file = os.path.join(os.path.dirname(__file__), input_file)
    vars.test_info = common_util.json2_file_to_dict(input_file)
    if vars.test_info == None:
        st.report_fail('msg', 'Failed to get input json dictionary')
        return

    vars.test_info = vars.test_info['DPB_TEST']
    # There are some platform specific restrictions on breakout modes
    # These restrictions are given in the input json file
    set1 = platform_to_modes(vars.plat_str[0])
    set2 = platform_to_modes(vars.plat_str[1])
    vars.supported_modes = list(set(set1) & set(set2))
    if len(vars.supported_modes) == 0:
        st.report_fail('msg', 'No common breakout modes on {} link'
                       .format(vars.D1D2P1))
        return

    vars.wait_time = int(vars.test_info['post_breakout_wait'])
    brkout_result = {}
    for cli_mode in vars.supported_modes:
       brkout_result[cli_mode] = ''

    print('Final breakout modes {}'.format(brkout_result))

    st.config(vars.D1, 'config qos reload', skip_tmpl=True)
    st.config(vars.D2, 'config qos reload', skip_tmpl=True)
    stream_api.tgen_handle, _ = tgapi.get_handle_byname('T1D1P1')

    # Now make sure we have the required tgen ports on the router side
    # Sometimes they have to be broken due to previous state of router
    yield

def mode_to_speed(mode):
    # will accept a string like '1x800G' and return '800G'
    # the show interface status shows a string like 800G in the output
    idx1 = mode.find('x')
    idx2 = mode.find('G')
    assert (idx1 != -1 and idx2 != -1 and idx2 > idx1)
    return mode[idx1 + 1 : idx2 + 1]

def perform_qos_cli(dut, port_list, op):
    # Perform a qos clear or reload on the given port list
    cmd = 'config qos {} --ports '.format(op)
    for if_name in port_list:
        cmd += '{},'.format(if_name)
    st.config(dut, cmd[:-1], skip_tmpl=True)

def collect_if_list(dut, if_name):
    # Collect all interfaces that are part of the breakout of the given if_name
    if_list = []
    result = st.show(dut,
                "show int status | egrep '{} |{}_' | awk '{{print $1}}'"
                .format(if_name, if_name), skip_tmpl=True)
    lines = result.splitlines()
    for line in lines:
        # Guard against extraneous content in the output
        if line.startswith('Ethernet'):
            if_list.append(line)
    return if_list

def config_b2b_link_ip(if1, if2, ctr):
    # Given 2 peer interfaces on DUT1 and DUT2, configure IP addresses
    # and perform ping test from DUT1 to DUT2
    ip1 = '192.168.{}.1'.format(100 + ctr)
    ip2 = '192.168.{}.2'.format(100 + ctr)
    vars.if_map.append((ip1, ip2))
    st.config(vars.D1, 'config interface ip add {} {}/24'
                .format(if1, ip1), skip_tmpl=True)
    st.config(vars.D2, 'config interface ip add {} {}/24'
                .format(if2, ip2), skip_tmpl=True)
    vars.addr_uncfg1 += 'config interface ip remove {} {}/24\n'.format(if1,
                                                                ip1)
    vars.addr_uncfg2 += 'config interface ip remove {} {}/24\n'.format(if2,
                                                                ip2)

def collect_lldp_neighor_info(intf_cnt):
    # Now that all interfaces are up, get LLDP neighbor info
    # This is always done on DUT1 side
    ctr = 0
    vars.if_map = []
    vars.addr_uncfg1 = ''
    vars.addr_uncfg2 = ''
    result = st.show(vars.D1, "show lldp table", skip_tmpl=True)
    lines = result.splitlines()
    list1 = list2 = []
    for line in lines:
        if vars.D1D2P1 not in line:
            continue
        tokens = line.split()
        ctr += 1
        # Keep track of interfaces seen in lldp table output
        list1.append(tokens[0])
        list2.append(tokens[4])
        config_b2b_link_ip(tokens[0], tokens[4], ctr)

    # All new interfaces should have shown up in LLDP table
    delta = intf_cnt - ctr
    if delta > 1:
        return 'LLDP neighbor count mismatch'
    if delta == 1:
        st.log('Handling one missing LLDP neighbor case')
        diff1 = set(vars.exp_if_list1) - set(list1)
        diff2 = set(vars.exp_if_list2) - set(list2)
        ctr += 1
        config_b2b_link_ip(diff1.pop(), diff2.pop(), ctr)
    return 'OK'

def ping_neighbor(ip_addr):
    # perform ping to the neighbor IP
    result = st.config(vars.D1,
                        'ping -c 10 {}'.format(ip_addr),
                        skip_tmpl=True)
    # Parse the ping result by checking for % packet loss
    idx = result.find('% packet loss')
    if idx == -1:
        return 'Unknown'
    save_idx = idx
    idx -= 1
    while idx >= 0 and result[idx] >= '0' and result[idx] <= '9':
        idx -= 1
    return int(result[idx + 1: save_idx])

def perform_ping_test():
    for pair in vars.if_map:
        loss = ping_neighbor(pair[1])
        if loss > 10:
            return 'Patchy ping to {}'.format(pair[1])

def perform_traffic_test():
    stream_api.config_b2b_with_ixia_setup(tb_dict, vars)
    # For each interface create full rate stream so there will be
    # backpressure and drops. FIXME: 1 GBPs per stream for now
    TGEN_PORT_CNT = 4
    streams = []
    pps = stream_api.gbps_to_pps(1, 8192)
    i = 1
    for pair in vars.if_map:
        st.log('Creating stream for link {} using tgen port# {}'.
               format(pair, i))
        str_hndl = stream_api.create_traffic_stream(tb_dict,
                                'T1D1P' + str(i),
                                'T1D2P' + str(i),
                                8192, pps, 3)
        if str_hndl != None:
            streams.append(str_hndl)
        i = (i + 1) if (i + 1) <= TGEN_PORT_CNT else 1

    stream_api.start_traffic_stream()
    st.wait(45)
    stream_api.stop_traffic_stream()
    stats = stream_api.collect_traffic_stream_stats()
    if 'traffic_item' not in stats:
        st.report_fail('msg', 'Failed to find traffic_item in stats')
        return
    for s in streams:
        stream_api.delete_traffic_stream(s)
    # All config should now be removed to prepare for next breakout
    st.config(vars.D1, vars.route_uncfg1 + vars.addr_uncfg1, skip_tmpl=True)
    st.config(vars.D2, vars.route_uncfg2 + vars.addr_uncfg2, skip_tmpl=True)

def perform_one_breakout(mode, test_type):
    brkout_result[mode] = []
    # Collect existing interfaces before breakout and perform qos clear
    for dut, if_name in zip(vars.dut_list, vars.b2b_list):
        port_list = collect_if_list(dut, if_name)
        perform_qos_cli(dut, port_list, 'clear')
    
    # Get expected interface list after breakout. This is taken from
    # show interface breakout output collected during topo setup
    vars.exp_if_list1 = vars.if_dict[vars.D1]['breakout_modes'][mode]
    vars.exp_if_list2 = vars.if_dict[vars.D2]['breakout_modes'][mode]
    if len(vars.exp_if_list1) != len(vars.exp_if_list2):
        brkout_result[mode] = 'Mismatch in breakout count'
        return
    exp_if_list = [vars.exp_if_list1, vars.exp_if_list2]
    intf_cnt = len(vars.exp_if_list1)

    # Determine the breakout flags
    fec_t = ['none', 'none']
    if mode in lane_speed_25g:
        flags = '-yf'
        fec_t[0] = ('none' if vars.plat1 == 'siren' else 'rs')
        fec_t[1] = ('none' if vars.plat2 == 'siren' else 'rs')
    elif mode in lane_speed_10g:
        flags = '-yf'
    else:
        flags = '-yfl'
    # Now perform breakout on both DUTs
    for dut, if_name, fec in zip(vars.dut_list, vars.b2b_list, fec_t):
        brkout_cmd = 'config interface breakout {} "{}" {}'.format(
                        if_name, mode, flags)
        if mode in lane_speed_25g:
            brkout_cmd += '\nconfig interface fec {} {}'.format(if_name, fec)
        result = st.config(dut, brkout_cmd, skip_tmpl=True)
        if 'ERROR' in result:
            brkout_result[mode] = result.splitlines()[0]
            return

    # Now get actual interface list after breakout and verify count
    for dut, org_if_name in zip(vars.dut_list, vars.b2b_list):
        port_list = collect_if_list(dut, org_if_name)
        if len(port_list) != intf_cnt:
            brkout_result[mode] = 'Mismatch in breakout count after cli'
            return
        # Perform qos reload on the new interfaces
        perform_qos_cli(dut, port_list, 'reload')

    # Startup all the newly created interfaces
    for dut, if_list in zip(vars.dut_list, exp_if_list):
        for if_name in if_list:
            st.config(dut,
                    'config interface startup {}\n'.format(if_name) +
                    'sleep 1\n', skip_tmpl=True)

    # Give some time for new interfaces to come up
    # We can simply check this on one DUT because if they are up/up on one side
    # they should be in same state on the other DUT
    wait_time = 0
    while wait_time < vars.wait_time:
        st.wait(10)
        wait_time += 10
        result1 = st.show(vars.D1,
                          "show int status | egrep '{} |{}_'"
                          .format(vars.D1D2P1, vars.D1D2P1),
                          skip_tmpl=True)
        lines = result1.splitlines()
        down_ctr = 0
        for line in lines:
            if vars.D1D2P1 not in line:
                continue
            tokens = line.split()
            if tokens[7] != 'up':
                down_ctr += 1
                break
        if down_ctr == 0:
            break

    if down_ctr > 0:
        # One or more interfaces continue to remain down even after
        # waiting for 2 to 3 minutes
        brkout_result[mode] = 'One or more interfaces down after breakout'
        return

    brkout_result[mode] = collect_lldp_neighor_info(intf_cnt)
    if brkout_result[mode] != 'OK':
        return

    # Run show config on both DUTs before running ping and traffic tests
    # for dut in vars.dut_list:
        # st.show(dut, 'show runningconfiguration all', skip_tmpl=True)
    perform_ping_test()
    perform_traffic_test()

def process_brkout_result():
    for key, value in brkout_result.items():
        print('{:^10} : {}'.format(key, value))
        if value == 'OK':
            vars.pass_ctr += 1
        else:
            vars.fail_ctr += 1

def test_all_breakout():
    st.banner('Test STARTED')
    vars.pass_ctr = 0
    vars.fail_ctr = 0

    # Do breakout 3 times in random sequence
    for ctr in range(3):
        # Randomize the order of operations
        random.shuffle(vars.supported_modes)
        brkout_result.clear()
        # Now run all breakouts on a single port connecting 2 DUTs 
        for mode in vars.supported_modes:
            perform_one_breakout(mode, 'stream')
        process_brkout_result()

    result = 'Test Cases: Passed={} Failed={}'.format(vars.pass_ctr,
                vars.fail_ctr)
    if vars.fail_ctr > 0:
        st.report_fail('msg', result)
    else:
        st.report_pass('msg', result)
