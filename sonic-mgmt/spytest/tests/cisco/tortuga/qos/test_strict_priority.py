import time
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

min_keys = ["tgen", "tgen_port_cnt", "leaf", "tc", "frame_sizes", "pirs",
            "stream_rates"]

def calc_gbps(gbps_percnt):
    return int(gbps_percnt) * test_info['if_speed'] / 100.0

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict
    global test_info

    st.log("setup topology Started")
    module_dir = os.path.dirname(__file__)
    input_file = os.path.join(module_dir, 'sp_input.json2')
    test_info = common_util.json2_file_to_dict(input_file)
    if test_info == None:
        st.report_fail('msg', 'Failed to read test input file sp_input.json2')
        sys.exit(-1)

    test_info = test_info['STRICT_PRIORITY_TEST']
    for k in min_keys:
        if k not in test_info:
            st.report_fail('msg', 'Input dictionary is missing {}'.format(k))
            sys.exit(-1)

    if not test_info['tgen_port_cnt'].isdigit():
        n = -1
    else:
        n = int(test_info['tgen_port_cnt'])
    if n < 0 or n > 4:
        st.report_fail('msg', 'Bad port count {} in input dictionary'\
            .format(test_info['tgen_port_cnt']))
        sys.exit(-1)

    min_topo = test_info['tgen'] + test_info['leaf'] + ':' + test_info['tgen_port_cnt']
    test_info['tgen_port_cnt'] = n
    tb_dict = st.ensure_min_topology(min_topo)
    print('testbed dictionary : ')
    pprint.pprint(tb_dict)

    test_info['dut'] = tb_dict[test_info['leaf']]
    test_info['src'] = [test_info['tgen'] + test_info['leaf'] + 'P1',
                        test_info['tgen'] + test_info['leaf'] + 'P2']
    test_info['dst'] = test_info['tgen'] + test_info['leaf'] + 'P3'
    test_info['dut_if'] = tb_dict[test_info['leaf'] + test_info['tgen'] + 'P3']
    stream_api.tgen_handle, _ = tgapi.get_handle_byname(test_info['dst'])
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

    common_op = '''sonic-clear counters\nsonic-clear dropcounters\n
        sonic-clear queuecounters\n'''
    result = st.show(test_info['dut'], "show int count | awk '{print $1}' | grep Eth",
                     skip_tmpl=True)
    lines = result.splitlines()
    for i in lines:
        if 'Eth' not in i:
            continue
        common_op +=\
            'ip addr flush dev {}\nip route flush dev {}\n'.format(i, i)
    st.config(test_info['dut'], common_op, skip_tmpl=True)
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
    if delta <= 0:
        # we suffered less loss than expected
        delta_percnt = 0
    elif expected_loss_percnt == 0:
        # When no loss is expected, any loss is a delta
        delta_percnt = delta
    else:
        # Calculate the percent of deviation from theoretical loss%
        delta_percnt = delta * 100.0 / expected_loss_percnt
    info1 = 'PIR(gbps) {} Frame Len {} '.format(test_info['pir'],
                test_info['frame_size'])
    if delta_percnt <= 5:
        # If deviation from expected loss is withint 5%, we call it a PASS
        print('PASS: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
              expected_loss_percnt))
        test_info['pass_ctr'] += 1
    else:
        print('FAIL: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
              expected_loss_percnt))
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
        return
    str1['tc'] = tc_pair[high]
    str1['gbps'] = gbps_pair[high]

    str2 = stream_api.create_traffic_stream(tb_dict, test_info['src'][low],
              test_info['dst'], test_info['frame_size'],
              stream_api.gbps_to_pps(gbps_pair[low], test_info['frame_size']),
              tc_pair[low])
    if str2 == None:
        return
    str2['tc'] = tc_pair[low]
    str2['gbps'] = gbps_pair[low]
    
    st.banner('Test info before stream execution')
    pprint.pprint(test_info)

    # 2 streams have been created. Now execute them
    stream_api.tgen_handle.tg_traffic_control(action='run')
    st.wait(45)
    stream_api.tgen_handle.tg_traffic_control(action='stop', max_wait_timer=0)
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
        s_info = 'TC {} Streams(gbps) {} Avg Loss% {}'.format(str1['tc'],
                    gbps_pair, loss_percent)
        report_pass_or_fail(total_gbps, test_info['pir'], loss_percent, s_info)
    else:
        # str1 corresponds to the higher priority stream
        # Theoretically the higher priority stream should take upto the PIR
        # and the rest of the bandwidht should go to lower priority stream
        s_info = 'TC {} Stream(gbps) {} Loss% {}'.format(str1['tc'],
                    str1['gbps'], str1['loss'])
        report_pass_or_fail(str1['gbps'], test_info['pir'], str1['loss'],
                            s_info)
        s_info = 'TC {} Stream(gbps) {} Loss% {}'.format(str2['tc'],
                    str2['gbps'], str2['loss'])
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
    new_name = test_info['dst'] + '_' + str(tc) + str(test_info['pir_bytes'])
    test_info['cfg'] += '''config scheduler add --type STRICT --cir {} --pir {} {}\n
        config queue queue-list update --scheduler {} {} {}\n'''.format(\
        test_info['pir_bytes'], test_info['pir_bytes'], new_name, new_name, 
        test_info['dut_if'], tc)

def apply_pir(pir):
    test_info['pir'] = (int(pir) * test_info['if_speed']) / 100.0
    test_info['pir_bytes'] = stream_api.gbps_to_bytes(test_info['pir'])
    test_info['cfg'] = 'config qos reload\n'
    get_scheduler_cfg(test_info['tc'][0])
    get_scheduler_cfg(test_info['tc'][1])
    st.config(test_info['dut'], test_info['cfg'], skip_tmpl=True)

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

    # Clear any qos config
    st.config(test_info['dut'], 'config qos clear', skip_tmpl=True)

    # Print the final disposition of the test execution
    final_msg = 'Tests Passed={}  Tests Failed={}'.format(
                    test_info['pass_ctr'], test_info['fail_ctr'])
    if test_info['fail_ctr'] > 0:
        st.report_fail('msg', final_msg)
    else:
        st.report_pass('msg', final_msg)
