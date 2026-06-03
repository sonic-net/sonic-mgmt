import time
import random
import json
import os
import sys
import pytest
import pprint
import qos_test_utils as common_util
import qos_test_utils
import traffic_stream_ixia_api as stream_api

from spytest import st, tgapi, SpyTestDict

lane_speed_50g = ['1x50G(1)', '1x200G(4)', '1x400G', '2x200G', '4x100G',
                  '1x100G(2)', '2x100G(4)']
lane_speed_25g = ['1x25G(1)', '1x100G(4)', '2x100G', '4x25G(4)']
lane_speed_10g = ['1x10G(1)', '4x10G(4)', '1x40G(4)']

def platform_to_modes(plat_str):
    if common_util.is_q200(plat_str):
        return vars.test_info['Q200_modes']
    if common_util.is_g200(plat_str):
        return vars.test_info['G200_modes']
    # Just reuse the G200 breakout modes for now
    if common_util.is_gamut(plat_str):
        return vars.test_info['G200_modes']

def dut_to_tgen_str(dut):
    if dut == vars.D1:
        return 'D1T1P1'
    if dut == vars.D2:
        return 'D2T1P1'
    if dut == vars.D3:
        return 'D3T1P1'
    if dut == vars.D4:
        return 'D4T1P1'
    return ''

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global vars
    global tb_dict
    global brkout_result

    # This is standard 2 spine 2 leaf topology with 4 tgen ports on each leaf
    tb_dict = st.ensure_min_topology("D1D3:2", "D3T1:3", "D4T1:1")
    vars = st.get_testbed_vars()

    vars.plat_str = []
    vars.if_dict = []
    # Get platform specific or test specific info from input json
    vars.test_info = common_util.get_qos_test_dict('../pfc/brkout_input.json2',
                                                   'DPB_TEST')
    if vars.test_info == None:
        st.report_fail('msg', 'Failed to get input json dictionary')
        return

    # Make sure router ports connected to tgen exist. Sometimes the parent
    # has to be broken for the child ports to be instantiated
    if vars.test_info['Traffic_test'] == 'True' and 'D3D4P1' in tb_dict:
        # This is a non standard connection between the 2 leaves
        vars.b2b_dut = [vars.D3, vars.D4]
        vars.b2b_link = [vars.D3D4P1, vars.D4D3P1]
        vars.tgen_str = ['T1D3', 'T1D4']
        vars.tgen_speed = common_util.get_if_speed(vars.D3, vars.D3T1P1)
        st.log(f'tgen port speed is {vars.tgen_speed}G')
    else:
        # Conn between first spine and first leaf will be used for breakouts
        vars.b2b_link = [vars.D1D3P1, vars.D3D1P1]
        vars.b2b_dut = [vars.D1, vars.D3]
        vars.test_info['Traffic_test'] = 'False'

    for dut in vars.b2b_dut:
        qos_test_utils.cleanup_config(dut)

    # Note down the current breakout mode and restore it at the end
    vars.org_mode = st.show(vars.b2b_dut[0],
                      f"show interface breakout current-mode {vars.b2b_link[0]} | grep Ethernet | awk '{{print $4}}'",
                            skip_tmpl=True)
    vars.org_mode = vars.org_mode.splitlines()[0]
    for dut, if_name in zip(vars.b2b_dut, vars.b2b_link):
        vars.plat_str.append(common_util.find_platform_str(dut))

        # get the interface specific list from show interface breakout
        full_brk_dict = common_util.show_cmd_to_dict(dut, 'interface breakout',
                                                     False)
        vars.if_dict.append(full_brk_dict[if_name])
        st.config(dut, 'config feature state lldp enabled', skip_tmpl=True)
        stream_api.init_qos_on_dut(dut)

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
    if op == 'reload':
        cmd = f"config qos reload --ports {','.join(port_list)} --no-dynamic-buffer"
    else:
        cmd = f"config qos clear --ports {','.join(port_list)}" 
    st.config(dut, cmd, skip_tmpl=True)

def collect_if_list(dut, if_name):
    # Collect all interfaces that are part of the breakout of the given if_name
    if_list = []
    result = st.show(dut, f"show int status | grep {if_name}", skip_tmpl=True)
    lines = result.splitlines()
    for line in lines:
        # Guard against extraneous content in the output
        if 'Ethernet' not in line:
            continue
        port = line.split()[0]
        # Match exact parent interface or breakout ports (parent_N)
        if port == if_name or port.startswith(f"{if_name}_"):
            if_list.append(port)
    return if_list

def config_b2b_link_pair(if1, if2, ctr):
    ip_list = ['192.168.{}.1'.format(100 + ctr),
               '192.168.{}.2'.format(100 + ctr)]
    intf_name = if1
    for i in range(2):
        st.config(vars.b2b_dut[i], 'config interface ip add {} {}/24'
                  .format(intf_name, ip_list[i]), skip_tmpl=True)
        intf_name = if2
    vars.if_map.append(ip_list)

def collect_lldp_neighor_info(intf_cnt):
    # Now that all interfaces are up, get LLDP neighbor info
    # This is always done on DUT1 side
    ctr = 0
    vars.if_map = []
    st.wait(32)
    # Build precise grep pattern from actual breakout port names
    grep_pattern = '|'.join(vars.actual_if_list[0])
    result = st.show(vars.b2b_dut[0],
                     f"show lldp table | egrep '{grep_pattern}'",
                     skip_tmpl=True)
    lines = result.splitlines()
    list1, list2 = [], []
    for line in lines:
        if 'Ethernet' not in line:
            continue
        tokens = line.split()
        ctr += 1
        config_b2b_link_pair(tokens[0], tokens[4], ctr)
        # Keep track of interfaces seen in lldp table output
        list1.append(tokens[0])
        list2.append(tokens[4])

    # All new interfaces should have shown up in LLDP table
    delta = intf_cnt - ctr
    if delta > 1:
        return 'LLDP neighbor count mismatch'
    if delta == 1:
        st.log('Handling one missing LLDP neighbor case')
        diff1 = set(vars.exp_if_list[0]) - set(list1)
        diff2 = set(vars.exp_if_list[1]) - set(list2)
        ctr += 1
        config_b2b_link_pair(diff1.pop(), diff2.pop(), ctr)
    return 'OK'

def ping_neighbor(ip_addr):
    # perform ping to the neighbor IP
    result = st.config(vars.b2b_dut[0], 'ping -c 10 {}'.format(ip_addr),
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
    return 'OK'


def get_timestamp(tstamp_str):
    idx = tstamp_str.rfind(':')
    return int(tstamp_str[idx + 1 : idx + 3]), int(tstamp_str[idx + 4:])

def calc_tx_time(rx_stats):
    # Timestamps are of the form 00:00:35.688.
    # We only care about secs and millisecs
    sec1, msec1 = get_timestamp(rx_stats['last_tstamp'])
    sec2, msec2 = get_timestamp(rx_stats['first_tstamp'])
    if msec2 > msec1:
        msec1 += 1000
        sec1 -= 1
    return (sec1 - sec2) * 1000 + (msec1 - msec2)

def perform_traffic_test(frame_sz):
    stream_api.config_b2b_with_ixia_setup(tb_dict, vars)

    # For each interface create almost full rate stream so there will be
    # backpressure and we should not see drops or packet loss
    TGEN_PORT_CNT = 4
    tgen_src_if = vars.tgen_str[0] + 'P1'
    tgen_dst_if = vars.tgen_str[1] + 'P1'
    pps = stream_api.gbps_to_pps(vars.tgen_speed * 0.99, frame_sz)
    for pair in vars.if_map:
        st.log('Creating stream for link {}'.format(pair))
        s1 = stream_api.create_traffic_stream(tb_dict,
                                tgen_src_if, tgen_dst_if, frame_sz, pps, 3)
        if s1 == None:
            continue

        dst_net = stream_api.ip_to_net(s1['dst_ip'])
        st.config(vars.b2b_dut[0],
                  'config route add prefix {}/24 nexthop {}\n'.format(dst_net, pair[1]),
                  skip_tmpl=True)
        src_net = stream_api.ip_to_net(s1['src_ip'])
        st.config(vars.b2b_dut[1],
                  'config route add prefix {}/24 nexthop {}\n'.format(src_net, pair[0]),
                  skip_tmpl=True)
        st.wait(1)

        # Get PFC counters before traffic for both IXIA port and leaf-to-leaf link
        cntr1_tgen = common_util.get_pfc_tx_count(vars.b2b_dut[0], vars.D3T1P1, 3)
        cntr1_b2b = common_util.get_pfc_tx_count(vars.b2b_dut[1], vars.b2b_link[1], 3)
        stream_api.start_traffic_stream(s1)
        st.wait(30)
        stream_api.stop_traffic_stream(s1)
        stats = stream_api.collect_traffic_stream_stats()
        stream_api.delete_traffic_stream(s1)
        # Get PFC counters after traffic for both interfaces
        cntr2_tgen = common_util.get_pfc_tx_count(vars.b2b_dut[0], vars.D3T1P1, 3)
        cntr2_b2b = common_util.get_pfc_tx_count(vars.b2b_dut[1], vars.b2b_link[1], 3)
        if 'traffic_item' not in stats:
            # Cleanup routes before returning on error
            st.config(vars.b2b_dut[0],
                      'config route del prefix {}/24'.format(dst_net))
            st.config(vars.b2b_dut[1],
                      'config route del prefix {}/24'.format(src_net))
            return 'Frame size={}: Failed to find traffic_item in stats'\
                    .format(frame_sz)
        else:
            tx_stats = stats['traffic_item'][s1['stream_id']]['tx']
            rx_stats = stats['traffic_item'][s1['stream_id']]['rx']
            loss = float(rx_stats['loss_percent'])
            tx_time = calc_tx_time(rx_stats)
            if tx_time == 0:
                # Unexpectedly the tx time is 0
                pfc_delta_tgen = cntr2_tgen - cntr1_tgen
                pfc_delta_b2b = cntr2_b2b - cntr1_b2b
                st.banner(f"Tx={tx_stats['total_pkts']} "
                          f"Rx={rx_stats['total_pkts']} "
                          f"Loss%={loss:.2f} "
                          f"PFC(IXIA)={pfc_delta_tgen}"
                          f"PFC(L2L)={pfc_delta_b2b}")
            else:
                pfc_rate_tgen = (1000 * (cntr2_tgen - cntr1_tgen)) / tx_time
                pfc_rate_b2b = (1000 * (cntr2_b2b - cntr1_b2b)) / tx_time
                st.banner(f"Tx={tx_stats['total_pkts']} "
                          f"Rx={rx_stats['total_pkts']} "
                          f"Loss%={loss:.2f} "
                          f"PFC(IXIA)={pfc_rate_tgen:.2f}/sec "
                          f"PFC(L2L)={pfc_rate_b2b:.2f}/sec")
            if loss > 1:
                # Cleanup routes before returning on error
                st.config(vars.b2b_dut[0],
                          'config route del prefix {}/24'.format(dst_net))
                st.config(vars.b2b_dut[1],
                          'config route del prefix {}/24'.format(src_net))
                return 'Frame size={}: Stream loss% {:.2f}'.format(frame_sz, loss)
        # All config should now be removed to prepare for next breakout
        st.config(vars.b2b_dut[0],
                  'config route del prefix {}/24'.format(dst_net))
        st.config(vars.b2b_dut[1],
                  'config route del prefix {}/24'.format(src_net))
    return 'OK'

def perform_one_breakout(mode):
    brkout_result[mode] = []
    # Collect existing interfaces before breakout and perform qos clear
    for dut, if_name in zip(vars.b2b_dut, vars.b2b_link):
        port_list = collect_if_list(dut, if_name)
        perform_qos_cli(dut, port_list, 'clear')
    
    # Get expected interface list after breakout. This is taken from
    # show interface breakout output collected during topo setup
    vars.exp_if_list = []
    for i in range(2):
        vars.exp_if_list.append(vars.if_dict[i]['breakout_modes'][mode])
    if len(vars.exp_if_list[0]) != len(vars.exp_if_list[1]):
        brkout_result[mode] = 'Mismatch in breakout count'
        return -1
    intf_cnt = len(vars.exp_if_list[0])

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
    for dut, if_name, fec in zip(vars.b2b_dut, vars.b2b_link, fec_t):
        brkout_cmd = 'config interface breakout {} "{}" {}'.format(
                        if_name, mode, flags)
        if mode in lane_speed_25g:
            brkout_cmd += '\nconfig interface fec {} {}'.format(if_name, fec)
        result = st.config(dut, brkout_cmd, skip_tmpl=True)
        if 'ERROR' in result:
            brkout_result[mode] = result.splitlines()[0]
            return -1

    # Now get actual interface list after breakout and verify count
    vars.actual_if_list = []
    for dut, org_if_name in zip(vars.b2b_dut, vars.b2b_link):
        port_list = collect_if_list(dut, org_if_name)
        if len(port_list) != intf_cnt:
            brkout_result[mode] = 'Mismatch in breakout count after cli'
            return -1
        # Perform qos reload on the new interfaces
        perform_qos_cli(dut, port_list, 'reload')
        vars.actual_if_list.append(port_list)

    # Startup all the newly created interfaces
    for dut, if_list in zip(vars.b2b_dut, vars.exp_if_list):
        for if_name in if_list:
            st.config(dut,
                    'config interface startup {}\n'.format(if_name) +
                    'sleep 1\n', skip_tmpl=True)

    # Give some time for new interfaces to come up
    # We can simply check this on one DUT because if they are up/up on one side
    # they should be in same state on the other DUT
    wait_time = 0
    grep_pattern = '|'.join(vars.actual_if_list[0])
    while wait_time < vars.wait_time:
        st.wait(10)
        wait_time += 10
        result1 = st.show(vars.b2b_dut[0],
                          f"show int status | egrep '{grep_pattern}'",
                          skip_tmpl=True)
        lines = result1.splitlines()
        down_ctr = 0
        for line in lines:
            if 'Ethernet' not in line:
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
        return -1

    brkout_result[mode] = collect_lldp_neighor_info(intf_cnt)
    if brkout_result[mode] != 'OK':
        return -1

    # Run show config on both DUTs before running ping and traffic tests
    # for dut in vars.dut_list:
        # st.show(dut, 'show runningconfiguration all', skip_tmpl=True)
    brkout_result[mode] = perform_ping_test()
    if brkout_result[mode] != 'OK':
        vars.fail_ctr += 1
        return -1

    vars.pass_ctr += 1
    if vars.test_info['Traffic_test'] == 'True':
        # traffic test is only possible with leaf to leaf connection
        # otherwise it becomes more complicated
        if 'frame_sizes' not in vars.test_info:
            vars.test_info['frame_sizes'] = ['1350', '8192']
        for n in vars.test_info['frame_sizes']:
            brkout_result[mode] = perform_traffic_test(int(n))
            if brkout_result[mode] != 'OK':
                vars.fail_ctr += 1
            else:
                vars.pass_ctr += 1
    return intf_cnt

def process_brkout_result():
    for key, value in brkout_result.items():
        print('{:^10} : {}'.format(key, value))

def test_all_breakout():
    st.banner('Test STARTED')
    vars.pass_ctr = 0
    vars.fail_ctr = 0

    # Do breakout 3 times in random sequence
    for ctr in range(3):
        # Randomize the order of operations
        random.shuffle(vars.supported_modes)
        brkout_result.clear()
        # Now run all breakouts on both sides of a b2b link
        for mode in vars.supported_modes:
            cnt = perform_one_breakout(mode)
            # Cleanup IP interfaces and routes after each breakout cycle
            for dut in vars.b2b_dut:
                qos_test_utils.cleanup_config(dut)
        process_brkout_result()

    # Restore to original breakout mode
    perform_one_breakout(vars.org_mode)
    result = 'Test Cases: Passed={} Failed={}'.format(vars.pass_ctr,
                vars.fail_ctr)
    if vars.fail_ctr > 0:
        st.report_fail('msg', result)
    else:
        st.report_pass('msg', result)
