import os
import sys
import pytest
import pprint
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils

from spytest import st, tgapi, SpyTestDict

min_keys = ["tc_pair", "dwrr_wt", "frame_sizes", "stream_rates"]

def calc_gbps(gbps_percnt):
    return int(gbps_percnt) * test_info['if_speed'] / 100.0

def init_test_info(dut, dut_if):
    key_str = 'T1' + test_info['leaf']
    test_info['dut'] = dut
    test_info['src'] = [key_str + 'P1', key_str + 'P2']
    test_info['dst'] = key_str + 'P3'
    test_info['dut_if'] = dut_if

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict
    global vars
    global test_info

    st.log("setup topology Started")
    module_dir = os.path.dirname(__file__)
    test_info = common_util.get_qos_test_dict('../scheduler/dwrr_input.json2',
                                              'DWRR_TEST')
    if test_info == None:
        st.report_fail('msg', 'Failed to read test input file dwrr_input.json2')
        sys.exit(-1)

    for k in min_keys:
        if k not in test_info:
            st.report_fail('msg', f'Input dictionary is missing {k}')
            sys.exit(-1)

    tb_dict = st.ensure_min_topology('T1' + test_info['leaf'] + ":3")

    vars = st.get_testbed_vars()

    test_info['tgen_port_cnt'] = 4
    if test_info['leaf'] == 'D1':
        init_test_info(vars.D1, vars.D1T1P3)
        vars.if1 = vars.D1T1P1
        vars.if2 = vars.D1T1P2
    elif test_info['leaf'] == 'D2':
        init_test_info(vars.D2, vars.D2T1P3)
        vars.if1 = vars.D2T1P1
        vars.if2 = vars.D2T1P2
    elif test_info['leaf'] == 'D3':
        init_test_info(vars.D3, vars.D3T1P3)
        vars.if1 = vars.D3T1P1
        vars.if2 = vars.D3T1P2
    elif test_info['leaf'] == 'D4':
        init_test_info(vars.D4, vars.D4T1P3)
        vars.if1 = vars.D4T1P1
        vars.if2 = vars.D4T1P2
    temp = st.show(test_info['dut'],
                "show int status {} | tail -1 | awk '{{print $3}}'".format(\
                test_info['dut_if']), skip_tmpl=True)
    temp = temp.splitlines()[0]
    if temp[-1].upper() == 'G':
        temp = temp[:-1]
    test_info['if_speed'] = int(temp) if temp.isdigit() else 10
    test_info['gbps_table'] = []
    for r in test_info['stream_rates']:
        test_info['gbps_table'].append((calc_gbps(r[0]), calc_gbps(r[1])))

    stream_api.init_qos_on_dut(test_info['dut'])
    qos_test_utils.cleanup_config(test_info['dut'])
    stream_api.config_one_leaf(tb_dict, test_info)
    st.log("setup topology Done")
    yield

lossy = [0, 1, 2, 5, 6]
lossless = [3, 4]
BOTH_LOSSY = 0
BOTH_LOSSLESS = 1
MIXED = 2

def pair_to_int(pair):
    return [int(pair[0]), int(pair[1])]

def run_traffic_test(gbps_pair, tc_pair, wt_pair):
    tc_pair = pair_to_int(tc_pair)
    wt_pair = pair_to_int(wt_pair)
    str1 = str2 = None
    for i in range(2):
        s = stream_api.create_traffic_stream(tb_dict, test_info['src'][i],
                  test_info['dst'], test_info['frame_size'],
                  stream_api.gbps_to_pps(gbps_pair[i], test_info['frame_size']),
                  tc_pair[i])
        if s == None:
            if str1 != None:
                stream_api.delete_traffic_stream(str1)
            return
        s['tc'] = tc_pair[i]
        s['gbps'] = gbps_pair[i]
        if str1 == None:
            str1 = s
        else:
            str2 = s

    pre_test_cnt1 = common_util.get_pfc_tx_count(test_info['dut'], vars.if1,
                                                 tc_pair[0])
    pre_test_cnt2 = common_util.get_pfc_tx_count(test_info['dut'], vars.if2,
                                                 tc_pair[1])
    # Take a snapshot of queue counters before and after test
    # this is a debugging aid
    result = st.show(test_info['dut'],
                     f"show queue counters {test_info['dut_if']}",
                     skip_tmpl=True)

    # 2 streams have been created. Now execute them
    stream_api.start_traffic_stream()
    st.wait(60)
    stats = stream_api.collect_traffic_stream_stats()
    if 'traffic_item' not in stats:
        st.report_fail('msg', 'Failed to find traffic_item in stats')
        sys.exit(-1)

    stream_api.stop_traffic_stream()
    st.wait(5)
    result = st.show(test_info['dut'],
                     f"show queue counters {test_info['dut_if']}",
                     skip_tmpl=True)

    # Post-traffic interface counters for diagnostics
    for iface in [vars.if1, vars.if2, test_info['dut_if']]:
        st.show(test_info['dut'],
                f"show int count -i {iface}", skip_tmpl=True)

    # Each stream handle will have an entry in the stats dictionary
    item_stats = stats['traffic_item']
    stats1 = item_stats[str1['stream_id']]
    stats2 = item_stats[str2['stream_id']]
    loss1 = float(stats1['rx']['loss_percent'])
    loss2 = float(stats2['rx']['loss_percent'])
    rx_bits1 = float(stats1['rx'].get('total_pkt_bit_rate'))
    rx_bits2 = float(stats2['rx'].get('total_pkt_bit_rate'))
    rx_gbps1 = rx_bits1 / 1000000000.0
    rx_gbps2 = rx_bits2 / 1000000000.0
    pfc_cnt1 = common_util.get_pfc_tx_count(test_info['dut'], vars.if1,
                                            tc_pair[0]) - pre_test_cnt1
    pfc_cnt2 = common_util.get_pfc_tx_count(test_info['dut'], vars.if2,
                                            tc_pair[1]) - pre_test_cnt2
    s_info = (f'TC Pair {tc_pair} Weight Pair {wt_pair} Loss {loss1:.2f} {loss2:.2f} Rx Gbps {rx_gbps1:.2f} {rx_gbps2:.2f}'
              f'\n{vars.if1}: TC{tc_pair[0]} PFC Tx Cnt={pfc_cnt1} '
              f'{vars.if2}: TC{tc_pair[1]} PFC Tx Cnt={pfc_cnt2}')

    # First validate the traffic rate with the weight ratio
    rx_bits_ratio = (rx_bits1 / rx_bits2) if (rx_bits1 and rx_bits2) else 0
    wt_ratio = wt_pair[0] / wt_pair[1]
    passed = qos_test_utils.validate_value(rx_bits_ratio, wt_ratio, 1)

    # Now check if other traffic requirements like lossless nature are satisfied
    if tc_pair[0] in lossless and tc_pair[1] in lossless:
        passed = (passed and loss1 <= 0.5 and loss2 <= 0.5)
    elif tc_pair[0] in lossless and tc_pair[1] in lossy:
        passed = (passed and loss1 <= 0.5)
    elif tc_pair[0] in lossy and tc_pair[1] in lossless:
        passed = (passed and loss2 <= 0.5)

    if passed:
        st.log(f'PASS: {s_info}')
        test_info['pass_ctr'] += 1
    else:
        st.log(f'FAIL: {s_info}')
        test_info['fail_ctr'] += 1

    stream_api.delete_traffic_stream(str1)
    stream_api.delete_traffic_stream(str2)

def get_scheduler_cfg(tc, wt):
    new_name = f"{test_info['dst']}_dwrr{tc}"
    orig_name = f'scheduler.{tc}'
    dut_if = test_info['dut_if']
    test_info['cfg'] += f'''config scheduler add --type DWRR --weight {wt} {new_name}\n
        config queue queue-list update --scheduler {new_name} {dut_if} {tc}\n'''
    test_info['undo_cfg'] += f'''config queue queue-list update --scheduler {orig_name} {dut_if} {tc}\n
        config scheduler del {new_name}\n'''

def apply_dwrr(tc_pair, wt_pair):
    test_info['cfg'] = ''
    test_info['undo_cfg'] = ''
    get_scheduler_cfg(tc_pair[0], wt_pair[0])
    get_scheduler_cfg(tc_pair[1], wt_pair[1])
    st.config(test_info['dut'], test_info['cfg'], skip_tmpl=True)

def clear_dwrr():
    st.config(test_info['dut'], test_info['undo_cfg'], skip_tmpl=True)

def test_deficit_weighted_round_robin():
    # Test assumes a single device with 3 or more tgen ports connected to it
    st.banner('Test STARTED')

    test_info['pass_ctr'] = test_info['fail_ctr'] = 0
    for tc_pair in test_info['tc_pair']:
        for wt_pair in test_info['dwrr_wt']:
            apply_dwrr(tc_pair, wt_pair)
            for gbps_pair in test_info['gbps_table']:
                for frame_size in test_info['frame_sizes']:
                    test_info['frame_size'] = int(frame_size)
                    run_traffic_test(gbps_pair, tc_pair, wt_pair)
            clear_dwrr()

    # Print the final disposition of the test execution
    final_msg = f"Test Cases: Passed={test_info['pass_ctr']} Failed={test_info['fail_ctr']}"
    if test_info['fail_ctr'] > 0:
        st.report_fail('msg', final_msg)
    else:
        st.report_pass('msg', final_msg)
