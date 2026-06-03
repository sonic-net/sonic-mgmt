import time
import json
import os
import sys
import pytest
import pprint
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils

from spytest import st, tgapi, SpyTestDict

min_keys = ["leaf", "tc", "frame_sizes", "pirs", "stream_rates"]


def calc_gbps(gbps_percnt):
    return int(gbps_percnt) * test_info['if_speed'] / 100.0

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict
    global vars
    global test_info

    st.log("setup topology Started")
    test_info = common_util.get_qos_test_dict('../scheduler/sp_input_short.json2',
                                              'STRICT_PRIORITY_TEST')
    if test_info == None:
        st.report_fail('msg', 'Failed to read test input file or missing key')
        return

    for k in min_keys:
        if k not in test_info:
            st.report_fail('msg', f'Input dictionary is missing {k}')
            sys.exit(-1)

    test_info['tgen_port_cnt'] = 4
    # the leaf to leaf link D3D4 is non-standard for a 2 spine 2 leaf topology
    # the non-standard link is useful for breakout testing with data streams
    tb_dict = st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:1", "D2D4:1",
                                     "D3T1:3", "D4T1:1")
    vars = st.get_testbed_vars()

    test_info['dut'] = tb_dict[test_info['leaf']]
    test_info['src'] = ['T1' + test_info['leaf'] + 'P1',
                        'T1' + test_info['leaf'] + 'P2']
    test_info['dst'] = 'T1' + test_info['leaf'] + 'P3'
    test_info['dut_if'] = tb_dict[test_info['leaf'] + 'T1' + 'P3']
    test_info['if_speed'] = common_util.get_if_speed(test_info['dut'],
                                                     test_info['dut_if'])
    test_info['gbps_table'] = []
    for r in test_info['stream_rates']:
        test_info['gbps_table'].append((calc_gbps(r[0]), calc_gbps(r[1])))

    stream_api.init_qos_on_dut(test_info['dut'])
    qos_test_utils.cleanup_config(test_info['dut'])
    stream_api.config_one_leaf(tb_dict, test_info)
    st.log("setup topology Done")
            
    yield

'''
gbps is the total stream rate in gigabits /sec
If 2 streams are of the same TC, then its the sum of both streams

avail is how much bandwidth is theoretically available for the stream(s)

loss is the percent of loss returned in statistics

s_info is the formatted string containing key info about the stream(s)
'''
def report_pass_or_fail(gbps, avail, loss, s_info):
    diff = gbps - avail
    if diff <= 0:
        # If available is more than input traffic rate, we should be good
        expected_loss_percnt = 0
    else:
        expected_loss_percnt = diff * 100.0 / gbps
    delta = loss - expected_loss_percnt
    if expected_loss_percnt == 0:
        # No loss expected — any loss is the deviation
        delta_percnt = abs(loss)
    else:
        delta_percnt = abs(delta) * 100.0 / expected_loss_percnt
    info1 = f"PIR(gbps) {test_info['pir']} Frame Len {test_info['frame_size']} "
    if delta_percnt <= 10:
        # If deviation from expected loss is within 10%, we call it a PASS
        st.log(f'PASS: {info1}{s_info} Exp Loss% {expected_loss_percnt:.2f}')
        test_info['pass_ctr'] += 1
    else:
        st.log(f'FAIL: {info1}{s_info} Exp Loss% {expected_loss_percnt:.2f}')
        test_info['fail_ctr'] += 1

def run_traffic_test(gbps_pair, tc_pair):
    str1 = str2 = None
    if tc_pair[0] < tc_pair[1]:
        high = 1
        low = 0
    else:
        high = 0
        low = 1
    # str1 is the higher priority stream. If both streams belong to same tc,
    # they they are created in order of occurrence in the tc_pair
    str1 = stream_api.create_traffic_stream(tb_dict, test_info['src'][high],
              test_info['dst'], test_info['frame_size'],
              stream_api.gbps_to_pps(gbps_pair[high], test_info['frame_size']),
              tc_pair[high])
    if str1 == None:
        st.error('Stream creation failed str1')
        return
    str1['tc'] = tc_pair[high]
    str1['gbps'] = gbps_pair[high]

    str2 = stream_api.create_traffic_stream(tb_dict, test_info['src'][low],
              test_info['dst'], test_info['frame_size'],
              stream_api.gbps_to_pps(gbps_pair[low], test_info['frame_size']),
              tc_pair[low])
    if str2 == None:
        st.error('Stream creation failed str2')
        return
    str2['tc'] = tc_pair[low]
    str2['gbps'] = gbps_pair[low]
    
    st.log('Test info before stream execution')
    st.log(test_info)

    # 2 streams have been created. Now execute them
    stream_api.start_traffic_stream()
    st.wait(45)
    stream_api.stop_traffic_stream()
    st.wait(5)

    stats = stream_api.collect_traffic_stream_stats()
    if 'traffic_item' not in stats:
        st.report_fail('msg', 'Failed to find traffic_item in stats')
        sys.exit(-1)

    # Each stream handle will have an entry in the stats dictionary
    item_stats = stats['traffic_item']
    str1['loss'] = float(item_stats[str1['stream_id']]['rx']['loss_percent'])
    str2['loss'] = float(item_stats[str2['stream_id']]['rx']['loss_percent'])

    if str1['tc'] == str2['tc']:
        # Both streams belong to the same traffic class
        loss_percent = (str1['loss'] + str2['loss']) / 2.0
        total_gbps = (gbps_pair[0] + gbps_pair[1])
        s_info = f"TC {str1['tc']} Streams(gbps) {gbps_pair} Avg Loss% {loss_percent:.2f}"
        report_pass_or_fail(total_gbps, test_info['pir'], loss_percent, s_info)
    else:
        # str1 corresponds to the higher priority stream
        # Theoretically the higher priority stream should take upto the PIR
        # and the rest of the bandwidht should go to lower priority stream
        s_info = f"TC {str1['tc']} Stream(gbps) {str1['gbps']:.2f} Loss% {str1['loss']:.2f}"
        report_pass_or_fail(str1['gbps'], test_info['pir'], str1['loss'],
                            s_info)
        s_info = f"TC {str2['tc']} Stream(gbps) {str2['gbps']:.2f} Loss% {str2['loss']:.2f}"
        # Theoretically, whatever bandwidth remains after passing higher 
        # priority stream, should go to lower priority stream. So we used upto
        # PIR of the bandwidth for str1 (the higher priority stream). Now we 
        # calculate how much remains
        remaining_gbps = test_info['if_speed'] - min(str1['gbps'], test_info['pir'])
        if remaining_gbps > test_info['pir']:
            remaining_gbps = test_info['pir']
        report_pass_or_fail(str2['gbps'], remaining_gbps, str2['loss'], s_info)

    stream_api.delete_traffic_stream(str1)
    stream_api.delete_traffic_stream(str2)

def get_scheduler_cfg(tc):
    new_name = f"{test_info['dst']}_{tc}{test_info['pir_bytes']}"
    orig_name = f'scheduler.{tc}'
    pir_bytes = test_info['pir_bytes']
    dut_if = test_info['dut_if']
    test_info['cfg'] += f'''config scheduler add --type STRICT --cir {pir_bytes} --pir {pir_bytes} {new_name}\n
        config queue queue-list update --scheduler {new_name} {dut_if} {tc}\n'''
    test_info['undo_cfg'] += f'''config queue queue-list update --scheduler {orig_name} {dut_if} {tc}\n
        config scheduler del {new_name}\n'''

def apply_pir(pir):
    test_info['pir'] = (int(pir) * test_info['if_speed']) / 100.0
    test_info['pir_bytes'] = stream_api.gbps_to_bytes(test_info['pir'])
    test_info['cfg'] = ''
    test_info['undo_cfg'] = ''
    get_scheduler_cfg(test_info['tc'][0])
    get_scheduler_cfg(test_info['tc'][1])
    st.config(test_info['dut'], test_info['cfg'], skip_tmpl=True)

def clear_pir():
    st.config(test_info['dut'], test_info['undo_cfg'], skip_tmpl=True)

def test_one_dev_strict_priority():
    # Test assumes a single device with 3 or more tgen ports connected to it
    st.banner('Test STARTED')

    test_info['tc'][0] = int(test_info['tc'][0])
    test_info['tc'][1] = int(test_info['tc'][1])
    test_info['pass_ctr'] = test_info['fail_ctr'] = 0
    for tc_pair in [(test_info['tc'][0], test_info['tc'][0]),
                    (test_info['tc'][0], test_info['tc'][1]),
                    (test_info['tc'][1], test_info['tc'][1])]:
        for pir in test_info['pirs']:
            apply_pir(pir)
            for gbps_pair in test_info['gbps_table']:
                for frame_size in test_info['frame_sizes']:
                        test_info['frame_size'] = int(frame_size)
                        run_traffic_test(gbps_pair, tc_pair)
            clear_pir()

    # Print the final disposition of the test execution
    final_msg = f"Test Cases: Passed={test_info['pass_ctr']} Failed={test_info['fail_ctr']}"
    if test_info['fail_ctr'] > 0:
        st.report_fail('msg', final_msg)
    else:
        st.report_pass('msg', final_msg)
