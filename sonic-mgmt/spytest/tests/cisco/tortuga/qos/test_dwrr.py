import os
import sys
import pytest
import pprint
import tortuga_common_utils as common_util
import traffic_stream_ixia_api as stream_api

from spytest import st, tgapi, SpyTestDict
module_dir = os.path.join(os.path.dirname(__file__), '../../', 'common')
sys.path.insert(0, os.path.abspath(module_dir))

min_keys = ["tc_pair", "dwrr_wt", "frame_sizes", "stream_rates"]

def calc_gbps(gbps_percnt):
    return int(gbps_percnt) * test_info['if_speed'] / 100.0

def init_test_info(dut, dut_if):
    key_str = 'T1' + test_info['leaf']
    test_info['dut'] = dut
    test_info['src'] = [key_str + 'P1', key_str + 'P2']
    test_info['dst'] = key_str + 'P3'
    test_info['dut_if'] = dut_if
    stream_api.traffic_api_init(key_str,
                                ['0', '0', '1', '2', '3', '0', '0', '0'])

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict
    global vars
    global test_info

    st.log("setup topology Started")
    module_dir = os.path.dirname(__file__)
    test_info = common_util.get_qos_test_dict('../qos/dwrr_input.json2',
                                              'DWRR_TEST')
    if test_info == None:
        st.report_fail('msg', 'Failed to read test input file dwrr_input.json2')
        sys.exit(-1)

    for k in min_keys:
        if k not in test_info:
            st.report_fail('msg', 'Input dictionary is missing {}'.format(k))
            sys.exit(-1)

    tb_dict = st.ensure_min_topology('T1' + test_info['leaf'] + ":4")

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

    common_util.cleanup_ip_interfaces(test_info['dut'])
    stream_api.config_one_leaf(tb_dict, test_info)
    st.log("setup topology Done")
    yield

lossy = [0, 1, 2, 5, 6]
lossless = [3, 4]
BOTH_LOSSY = 0
BOTH_LOSSLESS = 1
MIXED = 2
def check_tc_pair(tc_pair):
    if tc_pair[0] in lossy and tc_pair[1] in lossy:
        return BOTH_LOSSY
    if tc_pair[0] in lossless and tc_pair[1] in lossless:
        return BOTH_LOSSLESS
    return MIXED

def run_traffic_test(gbps_pair, tc_pair):
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
    s_info = (f'TC Pair {tc_pair} Loss {loss1} {loss2} Rx Gbps {rx_gbps1} {rx_gbps2}'
              f'\n{vars.if1}: TC{tc_pair[0]} PFC Tx Cnt={pfc_cnt1} '
              f'{vars.if2}: TC{tc_pair[1]} PFC Tx Cnt={pfc_cnt2}')

    rv = check_tc_pair(tc_pair)
    if rv == BOTH_LOSSY:
        # Assuming weights are equal, it should be 1:1 roughly
        ratio = (rx_bits1 / rx_bits2)
        passed = (ratio >= 0.75 and ratio <= 1.25)
    elif rv == BOTH_LOSSLESS:
        # Allow upto 1% loss in both
        passed = (loss1 <= 1 and loss2 <= 1)
    elif tc_pair[0] in lossy:
        passed = (loss2 <= 1)
    else:
        passed = (loss1 <= 1)
    if passed:
        st.log(f'PASS: {s_info}')
        test_info['pass_ctr'] += 1
    else:
        st.log(f'FAIL: {s_info}')
        test_info['fail_ctr'] += 1

    stream_api.delete_traffic_stream(str1)
    stream_api.delete_traffic_stream(str2)

def get_scheduler_cfg(tc):
    new_name = test_info['dst'] + '_' + 'dwrr' + str(tc)
    test_info['cfg'] += '''config scheduler add --type DWRR --weight {} {}\n
        config queue queue-list update --scheduler {} {} {}\n'''.format(\
        test_info['dwrr_wt'], new_name, new_name, test_info['dut_if'], tc)

def apply_dwrr(tc_pair):
    test_info['cfg'] = 'config qos reload\n'
    get_scheduler_cfg(tc_pair[0])
    if tc_pair[0] != tc_pair[1]:
        get_scheduler_cfg(tc_pair[1])
    test_info['cfg'] += ('config tc-to-priority-group-map update --maps ' +
              '0:0,1:0,2:1,3:2,4:3,5:0,6:0,7:0 AZURE\n')
    st.config(test_info['dut'], test_info['cfg'], skip_tmpl=True)

def test_deficit_weighted_round_robin():
    # Test assumes a single device with 3 or more tgen ports connected to it
    st.banner('Test STARTED')

    test_info['pass_ctr'] = test_info['fail_ctr'] = 0
    for tc_pair in test_info['tc_pair']:
        tc_pair[0] = int(tc_pair[0])
        tc_pair[1] = int(tc_pair[1])
        apply_dwrr(tc_pair)
        for gbps_pair in test_info['gbps_table']:
            for frame_size in test_info['frame_sizes']:
                test_info['frame_size'] = int(frame_size)
                run_traffic_test(gbps_pair, tc_pair)

    st.config(test_info['dut'], 'config qos reload', skip_tmpl=True)

    # Print the final disposition of the test execution
    final_msg = 'Test Cases: Passed={} Failed={}'.format(
                    test_info['pass_ctr'], test_info['fail_ctr'])
    if test_info['fail_ctr'] > 0:
        st.report_fail('msg', final_msg)
    else:
        st.report_pass('msg', final_msg)
